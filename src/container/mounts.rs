use anyhow::{Context, Result, bail};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::VolumeMount;

const REQUIRED_DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

pub fn setup_container_mounts(rootless: bool) -> Result<()> {
    if !rootless {
        mount_fs(
            "/proc",
            "proc",
            "proc",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None::<&str>,
            "failed to mount /proc",
        )?;
    }
    mount_dev()?;
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
    // sysfs may fail in some user namespace configurations — non-fatal.
    // For rootless, /sys is already bind-mounted from host before pivot_root.
    if !rootless {
        let _ = mount_fs(
            "/sys",
            "sysfs",
            "sysfs",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RDONLY,
            None::<&str>,
            "failed to mount /sys",
        );
    }

    Ok(())
}

pub fn prepare_host_device_sources(rootfs: &Path) -> Result<()> {
    let source_dir = rootfs.join(".hippobox-dev");
    fs::create_dir_all(&source_dir)?;

    for &name in REQUIRED_DEVICES {
        let source = source_dir.join(name);
        File::create(&source).with_context(|| {
            format!(
                "failed to create host device placeholder at {}",
                source.display()
            )
        })?;

        let host_device = format!("/dev/{name}");
        mount(
            Some(host_device.as_str()),
            source.as_path(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| {
            format!(
                "failed to bind-mount {host_device} onto {}",
                source.display()
            )
        })?;
    }

    Ok(())
}

pub fn cleanup_host_device_sources(rootfs: &Path) -> Result<()> {
    let source_dir = rootfs.join(".hippobox-dev");
    for &name in REQUIRED_DEVICES {
        let source = source_dir.join(name);
        let _ = umount2(&source, MntFlags::MNT_DETACH);
    }

    let _ = fs::remove_dir_all(&source_dir);

    Ok(())
}

/// Paths in /proc to mask completely (files get /dev/null, dirs get empty tmpfs).
const MASKED_PROC_PATHS: &[&str] = &[
    "/proc/acpi",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/proc/timer_list",
];

/// Paths in /proc that should be read-only (bind-mount + remount ro).
const READONLY_PROC_PATHS: &[&str] = &[
    "/proc/asound",
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];

/// Mask sensitive /proc paths by bind-mounting /dev/null or tmpfs over them.
/// Docker and Podman do the same to prevent information leaks and kernel exposure.
pub fn mask_proc_paths() -> Result<()> {
    for path in MASKED_PROC_PATHS {
        let p = Path::new(path);
        if !p.exists() {
            continue;
        }
        let result = if p.is_dir() {
            mount(
                Some("tmpfs"),
                *path,
                Some("tmpfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some("size=0"),
            )
        } else {
            mount(
                Some("/dev/null"),
                *path,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
        };
        if let Err(e) = result {
            eprintln!("warning: failed to mask {path}: {e}");
            continue;
        }
        // Remount read-only so the masked path can't be written to.
        if p.is_file() {
            let _ = mount(
                None::<&str>,
                *path,
                None::<&str>,
                MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                None::<&str>,
            );
        }
    }

    for path in READONLY_PROC_PATHS {
        let p = Path::new(path);
        if !p.exists() {
            continue;
        }
        // Bind-mount in place, then remount read-only.
        if let Err(e) = mount(
            Some(*path),
            *path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        ) {
            eprintln!("warning: failed to bind {path}: {e}");
            continue;
        }
        let _ = mount(
            None::<&str>,
            *path,
            None::<&str>,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
            None::<&str>,
        );
    }

    Ok(())
}

fn mount_dev() -> Result<()> {
    mount_fs(
        "/dev",
        "tmpfs",
        "tmpfs",
        MsFlags::MS_NOSUID,
        Some("mode=755"),
        "failed to mount tmpfs on /dev",
    )?;

    for &name in REQUIRED_DEVICES {
        bind_host_device(name)?;
    }

    for &(target, link_path) in &[
        ("/proc/self/fd/0", "/dev/stdin"),
        ("/proc/self/fd/1", "/dev/stdout"),
        ("/proc/self/fd/2", "/dev/stderr"),
        ("/proc/self/fd", "/dev/fd"),
    ] {
        let _ = fs::remove_file(link_path);
        symlink(target, link_path)
            .with_context(|| format!("failed to create symlink {link_path} -> {target}"))?;
    }

    Ok(())
}

fn mount_fs(
    target: &str,
    source: &str,
    fstype: &str,
    flags: MsFlags,
    options: Option<&str>,
    context: &'static str,
) -> Result<()> {
    fs::create_dir_all(target)?;
    mount(Some(source), target, Some(fstype), flags, options).context(context)?;
    Ok(())
}

fn bind_host_device(name: &str) -> Result<()> {
    let source = format!("/.hippobox-dev/{name}");
    let target = format!("/dev/{name}");
    File::create(&target)
        .with_context(|| format!("failed to create device placeholder at {target}"))?;

    mount(
        Some(source.as_str()),
        target.as_str(),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| format!("failed to bind-mount {source} onto {target}"))?;
    Ok(())
}

pub fn copy_host_files_to_rootfs(merged: &Path) -> Result<()> {
    for src in ["/etc/resolv.conf", "/etc/hostname"] {
        let dest = merged.join(src.trim_start_matches('/'));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        match fs::copy(src, &dest) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to copy {src} into rootfs"));
            }
        }
    }
    Ok(())
}

pub fn parse_volume(spec: &str) -> Result<VolumeMount> {
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
        bail!("invalid volume spec {spec:?}, source and target must not be empty");
    }
    if !source.starts_with('/') {
        bail!("volume source must be an absolute path: {source:?}");
    }
    if !target.starts_with('/') {
        bail!("volume target must be an absolute path: {target:?}");
    }
    if Path::new(target).components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        bail!("volume target must not contain '..': {target:?}");
    }
    let source_path = Path::new(source);
    if !source_path.exists() {
        bail!("volume source does not exist: {source:?}");
    }
    Ok(VolumeMount {
        source: source_path
            .canonicalize()
            .with_context(|| format!("failed to resolve volume source {source:?}"))?
            .to_string_lossy()
            .to_string(),
        target: target.to_string(),
        read_only,
    })
}

pub fn mount_volumes(merged: &Path, volumes: &[VolumeMount]) -> Result<()> {
    for vol in volumes {
        let target = merged.join(vol.target.trim_start_matches('/'));
        // Defence-in-depth: ensure the resolved target stays inside the rootfs.
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
            .with_context(|| {
                format!("failed to mount tmpfs volume at {}", target.display())
            })?;
            continue;
        }

        // Check source type to create the right placeholder at the target.
        let source_meta = fs::metadata(&vol.source)
            .with_context(|| format!("volume source inaccessible: {}", vol.source))?;
        if source_meta.is_file() {
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

        // Harden bind mount: apply MS_NOSUID | MS_NODEV and optionally MS_RDONLY.
        let mut remount_flags =
            MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_REMOUNT
            | MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
        if vol.read_only {
            remount_flags |= MsFlags::MS_RDONLY;
        }
        match mount(None::<&str>, &target, None::<&str>, remount_flags, None::<&str>) {
            Ok(()) => {}
            Err(nix::errno::Errno::EPERM) if vol.read_only => {
                eprintln!(
                    "warning: read-only remount not supported for {} (rootless limitation)",
                    vol.target
                );
            }
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
    fn parse_volume_basic() {
        let v = parse_volume("/tmp:/data").unwrap();
        assert_eq!(v.target, "/data");
        assert!(!v.read_only);
        assert!(v.source.starts_with('/'));
    }

    #[test]
    fn parse_volume_read_only() {
        let v = parse_volume("/tmp:/data:ro").unwrap();
        assert!(v.read_only);
    }

    #[test]
    fn parse_volume_explicit_rw() {
        let v = parse_volume("/tmp:/data:rw").unwrap();
        assert!(!v.read_only);
    }

    #[test]
    fn parse_volume_rejects_relative_source() {
        assert!(parse_volume("relative:/data").is_err());
    }

    #[test]
    fn parse_volume_rejects_relative_target() {
        assert!(parse_volume("/tmp:relative").is_err());
    }

    #[test]
    fn parse_volume_rejects_empty() {
        assert!(parse_volume("").is_err());
        assert!(parse_volume(":/data").is_err());
        assert!(parse_volume("/tmp:").is_err());
    }

    #[test]
    fn parse_volume_rejects_bad_option() {
        assert!(parse_volume("/tmp:/data:xx").is_err());
    }

    #[test]
    fn parse_volume_rejects_missing_source() {
        assert!(parse_volume("/nonexistent/path:/data").is_err());
    }

    #[test]
    fn parse_volume_canonicalises_source() {
        let v = parse_volume("/tmp/../tmp:/data").unwrap();
        assert_eq!(v.source, "/tmp");
    }

    #[test]
    fn parse_volume_rejects_path_traversal() {
        assert!(parse_volume("/tmp:/../escape").is_err());
        assert!(parse_volume("/tmp:/data/../../../etc").is_err());
    }
}
