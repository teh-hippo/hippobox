use anyhow::{Context, Result, bail};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::fs::{self, File};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

const DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

pub(super) fn setup_container_mounts(rootless: bool) -> Result<()> {
    let noexec = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    if !rootless {
        mount_fs(
            "/proc",
            "proc",
            "proc",
            noexec,
            None::<&str>,
            "failed to mount /proc",
        )?;
    }
    // mount /dev
    mount_fs(
        "/dev",
        "tmpfs",
        "tmpfs",
        MsFlags::MS_NOSUID,
        Some("mode=755"),
        "failed to mount tmpfs on /dev",
    )?;
    for &name in DEVICES {
        let (src, tgt) = (format!("/.hippobox-dev/{name}"), format!("/dev/{name}"));
        File::create(&tgt).with_context(|| format!("failed to create device node at {tgt}"))?;
        mount(
            Some(src.as_str()),
            tgt.as_str(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| format!("failed to bind-mount {src} onto {tgt}"))?;
    }
    for (target, link) in [
        ("/proc/self/fd/0", "/dev/stdin"),
        ("/proc/self/fd/1", "/dev/stdout"),
        ("/proc/self/fd/2", "/dev/stderr"),
        ("/proc/self/fd", "/dev/fd"),
    ] {
        let _ = fs::remove_file(link);
        symlink(target, link)
            .with_context(|| format!("failed to create symlink {link} -> {target}"))?;
    }
    mount_fs(
        "/dev/shm",
        "shm",
        "tmpfs",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=1777,size=65536k"),
        "failed to mount /dev/shm",
    )?;
    mount_fs(
        "/dev/pts",
        "devpts",
        "devpts",
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666"),
        "failed to mount /dev/pts",
    )?;
    if !rootless {
        let _ = mount_fs(
            "/sys",
            "sysfs",
            "sysfs",
            noexec | MsFlags::MS_RDONLY,
            None::<&str>,
            "failed to mount /sys",
        );
    }
    if Path::new("/tmp").is_dir() {
        let _ = mount(
            Some("tmpfs"),
            "/tmp",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("mode=1777"),
        );
    }
    Ok(())
}

pub(super) fn prepare_host_device_sources(rootfs: &Path) -> Result<()> {
    let dir = rootfs.join(".hippobox-dev");
    fs::create_dir_all(&dir)?;
    for &name in DEVICES {
        let src = dir.join(name);
        File::create(&src)
            .with_context(|| format!("failed to create device placeholder at {}", src.display()))?;
        let host = format!("/dev/{name}");
        mount(
            Some(host.as_str()),
            src.as_path(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| format!("failed to bind-mount {host} onto {}", src.display()))?;
    }
    Ok(())
}

pub(super) fn cleanup_host_device_sources(rootfs: &Path) -> Result<()> {
    let dir = rootfs.join(".hippobox-dev");
    for &name in DEVICES {
        let _ = umount2(&dir.join(name), MntFlags::MNT_DETACH);
    }
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

pub(super) fn mask_proc_paths() -> Result<()> {
    let ro = MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY;
    for path in [
        "/proc/acpi",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/proc/timer_list",
    ] {
        let p = Path::new(path);
        if !p.exists() {
            continue;
        }
        let result = if p.is_dir() {
            mount(
                Some("tmpfs"),
                path,
                Some("tmpfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some("size=0"),
            )
        } else {
            mount(
                Some("/dev/null"),
                path,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
        };
        if let Err(e) = result {
            eprintln!("warning: failed to mask {path}: {e}");
            continue;
        }
        if p.is_file() {
            let _ = mount(None::<&str>, path, None::<&str>, ro, None::<&str>);
        }
    }
    for path in [
        "/proc/asound",
        "/proc/bus",
        "/proc/fs",
        "/proc/irq",
        "/proc/sys",
        "/proc/sysrq-trigger",
    ] {
        if !Path::new(path).exists() {
            continue;
        }
        if let Err(e) = mount(
            Some(path),
            path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        ) {
            eprintln!("warning: failed to bind {path}: {e}");
            continue;
        }
        let _ = mount(None::<&str>, path, None::<&str>, ro, None::<&str>);
    }
    Ok(())
}

pub(super) fn mount_fs(
    target: &str,
    source: &str,
    fstype: &str,
    flags: MsFlags,
    options: Option<&str>,
    context: &'static str,
) -> Result<()> {
    fs::create_dir_all(target)?;
    mount(Some(source), target, Some(fstype), flags, options).context(context)
}

pub(super) fn copy_host_files_to_rootfs(merged: &Path) -> Result<()> {
    for src in ["/etc/resolv.conf", "/etc/hostname"] {
        let dest = merged.join(src.trim_start_matches('/'));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        match fs::copy(src, &dest) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("failed to copy {src} into rootfs")),
        }
    }
    Ok(())
}

pub(super) fn mount_overlay(
    lower_dirs: &[PathBuf],
    upper: &Path,
    work: &Path,
    merged: &Path,
    rootless: bool,
) -> Result<()> {
    use std::fmt::Write;
    let mut opts = String::with_capacity(256);
    opts.push_str("lowerdir=");
    for (i, p) in lower_dirs.iter().enumerate() {
        if i > 0 {
            opts.push(':');
        }
        let _ = write!(opts, "{}", p.display());
    }
    let _ = write!(
        opts,
        ",upperdir={},workdir={},volatile",
        upper.display(),
        work.display()
    );
    if rootless
        && mount(
            Some("overlay"),
            merged,
            Some("overlay"),
            MsFlags::empty(),
            Some(format!("{opts},redirect_dir=on").as_str()),
        )
        .is_ok()
    {
        return Ok(());
    }
    mount(
        Some("overlay"),
        merged,
        Some("overlay"),
        MsFlags::empty(),
        Some(opts.as_str()),
    )
    .context("failed to mount overlayfs")
}

pub(super) fn unmount_overlay(merged: &Path) -> Result<()> {
    umount2(merged, MntFlags::MNT_DETACH).context("failed to unmount overlayfs")
}

pub fn parse_volume(spec: &str) -> Result<super::VolumeMount> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (source, target, read_only) = match parts.len() {
        2 => (parts[0], parts[1], false),
        3 => match parts[2] {
            "ro" => (parts[0], parts[1], true),
            "rw" => (parts[0], parts[1], false),
            opt => bail!("invalid volume option {opt:?}, expected 'ro' or 'rw'"),
        },
        _ => bail!("invalid volume spec {spec:?}, expected SRC:DST[:ro|rw]"),
    };
    if source.is_empty() || target.is_empty() {
        bail!("invalid volume spec {spec:?}, empty source or target");
    }
    if !source.starts_with('/') {
        bail!("volume source must be absolute: {source:?}");
    }
    if !target.starts_with('/') {
        bail!("volume target must be absolute: {target:?}");
    }
    if Path::new(target)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        bail!("volume target must not contain '..': {target:?}");
    }
    if !Path::new(source).exists() {
        bail!("volume source does not exist: {source:?}");
    }
    Ok(super::VolumeMount {
        source: Path::new(source)
            .canonicalize()
            .with_context(|| format!("failed to resolve volume source {source:?}"))?
            .to_string_lossy()
            .to_string(),
        target: target.to_string(),
        read_only,
    })
}

pub(super) fn mount_volumes(merged: &Path, volumes: &[super::VolumeMount]) -> Result<()> {
    for vol in volumes {
        let target = merged.join(vol.target.trim_start_matches('/'));
        if !target.starts_with(merged) {
            bail!("volume target escapes container rootfs: {}", vol.target);
        }
        if vol.source == "tmpfs" {
            fs::create_dir_all(&target)?;
            mount(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                Some("size=67108864"),
            )
            .with_context(|| format!("failed to mount tmpfs volume at {}", target.display()))?;
            continue;
        }
        let meta = fs::metadata(&vol.source)
            .with_context(|| format!("volume source inaccessible: {}", vol.source))?;
        if meta.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            if !target.exists() {
                File::create(&target)?;
            }
        } else {
            fs::create_dir_all(&target)?;
        }
        mount(
            Some(vol.source.as_str()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .with_context(|| {
            format!(
                "failed to bind-mount {} at {}",
                vol.source,
                target.display()
            )
        })?;
        let mut flags = MsFlags::MS_BIND
            | MsFlags::MS_REC
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV;
        if vol.read_only {
            flags |= MsFlags::MS_RDONLY;
        }
        match mount(None::<&str>, &target, None::<&str>, flags, None::<&str>) {
            Ok(()) => {}
            Err(nix::errno::Errno::EPERM) if vol.read_only => eprintln!(
                "warning: read-only remount not supported for {} (rootless limitation)",
                vol.target
            ),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to remount {} with security flags", target.display())
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_volume_valid() {
        let v = parse_volume("/tmp:/data").unwrap();
        assert_eq!(v.target, "/data");
        assert!(!v.read_only && v.source.starts_with('/'));
        assert!(parse_volume("/tmp:/data:ro").unwrap().read_only);
        assert!(!parse_volume("/tmp:/data:rw").unwrap().read_only);
        assert_eq!(parse_volume("/tmp/../tmp:/data").unwrap().source, "/tmp");
    }
    #[test]
    fn parse_volume_rejects_invalid() {
        for bad in [
            "",
            ":/data",
            "/tmp:",
            "relative:/data",
            "/tmp:relative",
            "/a:/b:ro:extra",
            "/tmp:/data:xx",
            "/nonexistent/path:/data",
            "/tmp:/../escape",
            "/tmp:/data/../../../etc",
        ] {
            assert!(parse_volume(bad).is_err(), "should reject {bad:?}");
        }
    }
}
