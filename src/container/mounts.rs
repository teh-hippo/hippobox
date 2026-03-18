use anyhow::{Context, Result};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

const REQUIRED_DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

pub fn setup_container_mounts(rootless: bool) -> Result<()> {
    if rootless {
        fs::create_dir_all("/proc")?;
    } else {
        mount_proc()?;
    }
    mount_dev()?;
    mount_dev_shm()?;
    mount_dev_pts()?;

    if rootless {
        fs::create_dir_all("/sys")?;
    } else {
        mount_sys()?;
        mask_sensitive_paths()?;
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

    for &name in REQUIRED_DEVICES {
        bind_host_device(name)?;
    }

    ensure_symlink("/proc/self/fd/0", "/dev/stdin")?;
    ensure_symlink("/proc/self/fd/1", "/dev/stdout")?;
    ensure_symlink("/proc/self/fd/2", "/dev/stderr")?;
    ensure_symlink("/proc/self/fd", "/dev/fd")?;

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
        match mount(
            Some("/dev/null"),
            path,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        ) {
            Ok(()) => {}
            Err(nix::errno::Errno::ENOENT) => {}
            Err(err) => return Err(err).with_context(|| format!("failed to mask {path}")),
        }
    }

    for path in ["/proc/sys", "/proc/bus"] {
        match mount(
            Some(path),
            path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        ) {
            Ok(()) => {}
            Err(nix::errno::Errno::ENOENT) => continue,
            Err(err) => return Err(err).with_context(|| format!("failed to bind remount {path}")),
        }
        mount(
            Some(path),
            path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT,
            None::<&str>,
        )
        .with_context(|| format!("failed to remount {path} read-only"))?;
    }

    Ok(())
}

pub fn copy_host_files_to_rootfs(merged: &Path) -> Result<()> {
    for src in ["/etc/resolv.conf", "/etc/hostname"] {
        let src_path = Path::new(src);
        let dest = merged.join(src.trim_start_matches('/'));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        match fs::copy(src_path, &dest) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to copy {} into rootfs", src_path.display()));
            }
        }
    }
    Ok(())
}

fn ensure_symlink(target: &str, link_path: &str) -> Result<()> {
    let link = Path::new(link_path);
    let _ = fs::remove_file(link);
    symlink(target, link)
        .with_context(|| format!("failed to create symlink {link_path} -> {target}"))?;
    Ok(())
}
