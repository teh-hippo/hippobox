use anyhow::{Context, Result};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

const REQUIRED_DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

pub(super) fn setup_container_mounts(rootless: bool) -> Result<()> {
    let noexec = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    if !rootless {
        mount_fs("/proc", "proc", "proc", noexec, None::<&str>, "failed to mount /proc")?;
    }
    mount_dev()?;
    mount_fs("/dev/shm", "shm", "tmpfs", MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=1777,size=65536k"), "failed to mount /dev/shm")?;
    mount_fs("/dev/pts", "devpts", "devpts", MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666"), "failed to mount /dev/pts")?;
    if !rootless {
        let _ = mount_fs("/sys", "sysfs", "sysfs",
            noexec | MsFlags::MS_RDONLY, None::<&str>, "failed to mount /sys");
    }
    if Path::new("/tmp").is_dir() {
        let _ = mount(Some("tmpfs"), "/tmp", Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV, Some("mode=1777"));
    }
    Ok(())
}

pub(super) fn prepare_host_device_sources(rootfs: &Path) -> Result<()> {
    let source_dir = rootfs.join(".hippobox-dev");
    fs::create_dir_all(&source_dir)?;

    for &name in REQUIRED_DEVICES {
        let source = source_dir.join(name);
        File::create(&source)
            .with_context(|| format!("failed to create device placeholder at {}", source.display()))?;
        let host_device = format!("/dev/{name}");
        mount(Some(host_device.as_str()), source.as_path(), None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .with_context(|| format!("failed to bind-mount {host_device} onto {}", source.display()))?;
    }
    Ok(())
}

pub(super) fn cleanup_host_device_sources(rootfs: &Path) -> Result<()> {
    let source_dir = rootfs.join(".hippobox-dev");
    for &name in REQUIRED_DEVICES {
        let _ = umount2(&source_dir.join(name), MntFlags::MNT_DETACH);
    }
    let _ = fs::remove_dir_all(&source_dir);
    Ok(())
}

const MASKED_PROC_PATHS: &[&str] = &[
    "/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
    "/proc/sched_debug", "/proc/scsi", "/proc/timer_list",
];

const READONLY_PROC_PATHS: &[&str] = &[
    "/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
];

/// Mask sensitive /proc paths by bind-mounting /dev/null or tmpfs over them.
pub(super) fn mask_proc_paths() -> Result<()> {
    let ro_remount = MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY;
    for path in MASKED_PROC_PATHS {
        let p = Path::new(path);
        if !p.exists() { continue; }
        let result = if p.is_dir() {
            mount(Some("tmpfs"), *path, Some("tmpfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, Some("size=0"))
        } else {
            mount(Some("/dev/null"), *path, None::<&str>, MsFlags::MS_BIND, None::<&str>)
        };
        if let Err(e) = result { eprintln!("warning: failed to mask {path}: {e}"); continue; }
        if p.is_file() { let _ = mount(None::<&str>, *path, None::<&str>, ro_remount, None::<&str>); }
    }
    for path in READONLY_PROC_PATHS {
        if !Path::new(path).exists() { continue; }
        if let Err(e) = mount(Some(*path), *path, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>) {
            eprintln!("warning: failed to bind {path}: {e}"); continue;
        }
        let _ = mount(None::<&str>, *path, None::<&str>, ro_remount, None::<&str>);
    }
    Ok(())
}

fn mount_dev() -> Result<()> {
    mount_fs("/dev", "tmpfs", "tmpfs", MsFlags::MS_NOSUID, Some("mode=755"), "failed to mount tmpfs on /dev")?;

    for &name in REQUIRED_DEVICES {
        let source = format!("/.hippobox-dev/{name}");
        let target = format!("/dev/{name}");
        File::create(&target)
            .with_context(|| format!("failed to create device placeholder at {target}"))?;
        mount(Some(source.as_str()), target.as_str(), None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .with_context(|| format!("failed to bind-mount {source} onto {target}"))?;
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

pub(super) fn mount_fs(
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

pub(super) fn copy_host_files_to_rootfs(merged: &Path) -> Result<()> {
    for src in ["/etc/resolv.conf", "/etc/hostname"] {
        let dest = merged.join(src.trim_start_matches('/'));
        if let Some(parent) = dest.parent() { fs::create_dir_all(parent)?; }
        match fs::copy(src, &dest) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err).with_context(|| format!("failed to copy {src} into rootfs")),
        }
    }
    Ok(())
}

pub(super) fn mount_overlay(
    lower_dirs: &[PathBuf], upper: &Path, work: &Path, merged: &Path, rootless: bool,
) -> Result<()> {
    use std::fmt::Write;
    let mut opts = String::with_capacity(256);
    opts.push_str("lowerdir=");
    for (i, p) in lower_dirs.iter().enumerate() {
        if i > 0 { opts.push(':'); }
        let _ = write!(opts, "{}", p.display());
    }
    let _ = write!(opts, ",upperdir={},workdir={},volatile", upper.display(), work.display());

    if rootless {
        let with_redirect = format!("{opts},redirect_dir=on");
        if mount(Some("overlay"), merged, Some("overlay"), MsFlags::empty(), Some(with_redirect.as_str())).is_ok() {
            return Ok(());
        }
    }
    mount(Some("overlay"), merged, Some("overlay"), MsFlags::empty(), Some(opts.as_str()))
        .context("failed to mount overlayfs")
}

pub(super) fn unmount_overlay(merged: &Path) -> Result<()> {
    umount2(merged, MntFlags::MNT_DETACH).context("failed to unmount overlayfs")
}
