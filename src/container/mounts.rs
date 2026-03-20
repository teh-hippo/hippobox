use anyhow::{Context, Result};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

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
    let _ = mount_fs(
        "/sys",
        "sysfs",
        "sysfs",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RDONLY,
        None::<&str>,
        "failed to mount /sys",
    );

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
