use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sys::stat;
use std::os::unix::fs::symlink;
use std::path::Path;

/// Set up all mounts inside the container after pivot_root.
pub fn setup_container_mounts() -> Result<()> {
    mount_proc()?;
    mount_sys()?;
    mount_dev()?;
    mount_dev_shm()?;
    mount_dev_pts()?;
    bind_mount_etc()?;
    mask_sensitive_paths()?;
    Ok(())
}

fn mount_proc() -> Result<()> {
    std::fs::create_dir_all("/proc")?;
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
    std::fs::create_dir_all("/sys")?;
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
    std::fs::create_dir_all("/dev")?;
    mount(
        Some("tmpfs"),
        "/dev",
        Some("tmpfs"),
        MsFlags::MS_NOSUID,
        Some("mode=755"),
    )
    .context("failed to mount tmpfs on /dev")?;

    // Create device nodes
    let devices: &[(&str, u64, u64)] = &[
        ("null", 1, 3),
        ("zero", 1, 5),
        ("full", 1, 7),
        ("random", 1, 8),
        ("urandom", 1, 9),
        ("tty", 5, 0),
    ];

    for (name, major, minor) in devices {
        let path = format!("/dev/{name}");
        let dev = stat::makedev(*major, *minor);
        stat::mknod(
            path.as_str(),
            stat::SFlag::S_IFCHR,
            stat::Mode::S_IRUSR | stat::Mode::S_IWUSR | stat::Mode::S_IRGRP | stat::Mode::S_IWGRP | stat::Mode::S_IROTH | stat::Mode::S_IWOTH,
            dev,
        )
        .with_context(|| format!("failed to create /dev/{name}"))?;
    }

    // Create symlinks
    symlink("/proc/self/fd/0", "/dev/stdin").ok();
    symlink("/proc/self/fd/1", "/dev/stdout").ok();
    symlink("/proc/self/fd/2", "/dev/stderr").ok();
    symlink("/proc/self/fd", "/dev/fd").ok();

    Ok(())
}

fn mount_dev_shm() -> Result<()> {
    std::fs::create_dir_all("/dev/shm")?;
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
    std::fs::create_dir_all("/dev/pts")?;
    mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666"),
    )
    .context("failed to mount /dev/pts")?;

    // Symlink /dev/ptmx → /dev/pts/ptmx
    symlink("/dev/pts/ptmx", "/dev/ptmx").ok();

    Ok(())
}

fn bind_mount_etc() -> Result<()> {
    let files = [
        ("/etc/resolv.conf", "/etc/resolv.conf"),
        ("/etc/hostname", "/etc/hostname"),
    ];

    for (_, target) in &files {
        // The target file may not exist in the rootfs — touch it
        if let Some(parent) = Path::new(target).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        // Create the file if it doesn't exist
        if !Path::new(target).exists() {
            std::fs::write(target, "").ok();
        }
    }

    // We can't bind-mount from host after pivot_root because the host paths are gone.
    // The bind mounts need to happen BEFORE pivot_root, from the merged rootfs perspective.
    // Instead, we copy the host files into the rootfs before pivot_root.
    // This function is called after pivot_root, so the host files are already accessible
    // only if they were copied. We handle this in the pre-pivot setup.

    Ok(())
}

fn mask_sensitive_paths() -> Result<()> {
    let mask_paths = [
        "/proc/kcore",
        "/proc/keys",
        "/proc/timer_list",
        "/proc/sched_debug",
    ];

    for path in &mask_paths {
        if Path::new(path).exists() {
            mount(
                Some("/dev/null"),
                *path,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .ok(); // Non-fatal
        }
    }

    // Read-only mounts
    let readonly_paths = ["/proc/sys", "/proc/bus"];
    for path in &readonly_paths {
        if Path::new(path).exists() {
            mount(
                Some(*path),
                *path,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )
            .ok();
            mount(
                Some(*path),
                *path,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT,
                None::<&str>,
            )
            .ok();
        }
    }

    Ok(())
}

/// Copy host files into the merged rootfs BEFORE pivot_root.
pub fn copy_host_files_to_rootfs(merged: &Path) -> Result<()> {
    let files = ["/etc/resolv.conf", "/etc/hostname"];
    for src in &files {
        let src_path = Path::new(src);
        if src_path.exists() {
            let dest = merged.join(src.trim_start_matches('/'));
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(src_path, &dest).ok();
        }
    }
    Ok(())
}
