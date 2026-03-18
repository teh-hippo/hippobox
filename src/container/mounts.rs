use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sys::stat;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

pub fn setup_container_mounts() -> Result<()> {
    mount_proc()?;
    mount_sys()?;
    mount_dev()?;
    mount_dev_shm()?;
    mount_dev_pts()?;
    mask_sensitive_paths()?;
    Ok(())
}

fn mount_proc() -> Result<()> {
    fs::create_dir_all("/proc")?;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("failed to mount /proc")?;
    Ok(())
}

fn mount_sys() -> Result<()> {
    fs::create_dir_all("/sys")?;
    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .context("failed to mount /sys")?;
    Ok(())
}

fn mount_dev() -> Result<()> {
    fs::create_dir_all("/dev")?;
    mount(
        Some("tmpfs"),
        "/dev",
        Some("tmpfs"),
        MsFlags::MS_NOSUID,
        Some("mode=755"),
    )
    .context("failed to mount tmpfs on /dev")?;

    for (name, major, minor) in [
        ("null", 1, 3),
        ("zero", 1, 5),
        ("full", 1, 7),
        ("random", 1, 8),
        ("urandom", 1, 9),
        ("tty", 5, 0),
    ] {
        let path = format!("/dev/{name}");
        let dev = stat::makedev(major, minor);
        stat::mknod(
            path.as_str(),
            stat::SFlag::S_IFCHR,
            stat::Mode::S_IRUSR
                | stat::Mode::S_IWUSR
                | stat::Mode::S_IRGRP
                | stat::Mode::S_IWGRP
                | stat::Mode::S_IROTH
                | stat::Mode::S_IWOTH,
            dev,
        )
        .with_context(|| format!("failed to create /dev/{name}"))?;
    }

    ensure_symlink("/proc/self/fd/0", "/dev/stdin")?;
    ensure_symlink("/proc/self/fd/1", "/dev/stdout")?;
    ensure_symlink("/proc/self/fd/2", "/dev/stderr")?;
    ensure_symlink("/proc/self/fd", "/dev/fd")?;

    Ok(())
}

fn mount_dev_shm() -> Result<()> {
    fs::create_dir_all("/dev/shm")?;
    mount(
        Some("shm"),
        "/dev/shm",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=1777,size=65536k"),
    )
    .context("failed to mount /dev/shm")?;
    Ok(())
}

fn mount_dev_pts() -> Result<()> {
    fs::create_dir_all("/dev/pts")?;
    mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666"),
    )
    .context("failed to mount /dev/pts")?;
    ensure_symlink("/dev/pts/ptmx", "/dev/ptmx")?;
    Ok(())
}

fn mask_sensitive_paths() -> Result<()> {
    for path in [
        "/proc/kcore",
        "/proc/keys",
        "/proc/timer_list",
        "/proc/sched_debug",
    ] {
        if Path::new(path).exists() {
            mount(
                Some("/dev/null"),
                path,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .with_context(|| format!("failed to mask {path}"))?;
        }
    }

    for path in ["/proc/sys", "/proc/bus"] {
        if Path::new(path).exists() {
            mount(
                Some(path),
                path,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )
            .with_context(|| format!("failed to bind remount {path}"))?;
            mount(
                Some(path),
                path,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT,
                None::<&str>,
            )
            .with_context(|| format!("failed to remount {path} read-only"))?;
        }
    }

    Ok(())
}

pub fn copy_host_files_to_rootfs(merged: &Path) -> Result<()> {
    for src in ["/etc/resolv.conf", "/etc/hostname"] {
        let src_path = Path::new(src);
        if !src_path.exists() {
            continue;
        }

        let dest = merged.join(src.trim_start_matches('/'));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src_path, &dest)
            .with_context(|| format!("failed to copy {} into rootfs", src_path.display()))?;
    }
    Ok(())
}

fn ensure_symlink(target: &str, link_path: &str) -> Result<()> {
    let link = Path::new(link_path);
    if link.exists() || fs::symlink_metadata(link).is_ok() {
        let _ = fs::remove_file(link);
    }
    symlink(target, link).with_context(|| format!("failed to create symlink {link_path} -> {target}"))?;
    Ok(())
}
