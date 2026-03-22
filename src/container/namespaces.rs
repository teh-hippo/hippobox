use anyhow::{Context, Result};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{chdir, pivot_root};
use std::fs;
use std::path::Path;

use super::VolumeMount;

pub(super) fn setup_namespaces_and_pivot(
    new_root: &Path, rootless: bool, volumes: &[VolumeMount], isolate_network: bool,
) -> Result<()> {
    let mut flags = CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWIPC;
    if isolate_network { flags |= CloneFlags::CLONE_NEWNET; }
    unshare(flags).context("failed to unshare namespaces")?;

    let bind_rec = MsFlags::MS_BIND | MsFlags::MS_REC;
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)
        .context("failed to set mount propagation to private")?;
    mount(Some(new_root), new_root, None::<&str>, bind_rec, None::<&str>)
        .context("failed to bind-mount new root")?;

    if rootless {
        let root_proc = new_root.join("proc");
        fs::create_dir_all(&root_proc)?;
        mount(Some("/proc"), &root_proc, None::<&str>, bind_rec, None::<&str>)
            .context("failed to stage proc for rootless rootfs")?;
        let root_sys = new_root.join("sys");
        fs::create_dir_all(&root_sys)?;
        let _ = mount(Some("/sys"), &root_sys, None::<&str>, bind_rec, None::<&str>);
    }

    super::volumes::mount_volumes(new_root, volumes)?;

    let old_root = new_root.join("old_root");
    fs::create_dir_all(&old_root)?;
    pivot_root(new_root, &old_root).context("pivot_root failed")?;
    chdir("/").context("chdir to / failed")?;
    nix::mount::umount2("/old_root", nix::mount::MntFlags::MNT_DETACH)
        .context("failed to unmount old root")?;
    let _ = fs::remove_dir("/old_root");
    Ok(())
}
