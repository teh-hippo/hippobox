use anyhow::{Context, Result};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{chdir, pivot_root};
use std::fs;
use std::path::Path;

use super::VolumeMount;

/// Set up mount/UTS/IPC isolation and pivot into the container root.
/// Volume mounts happen after unshare (inside the new mount namespace)
/// but before pivot_root (so host paths are still accessible).
pub fn setup_namespaces_and_pivot(
    new_root: &Path,
    rootless: bool,
    volumes: &[VolumeMount],
    isolate_network: bool,
) -> Result<()> {
    let mut clone_flags =
        CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWIPC;
    if isolate_network {
        clone_flags |= CloneFlags::CLONE_NEWNET;
    }
    unshare(clone_flags).context("failed to unshare namespaces")?;

    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("failed to set mount propagation to private")?;

    mount(
        Some(new_root),
        new_root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("failed to bind-mount new root")?;

    if rootless {
        let root_proc = new_root.join("proc");
        fs::create_dir_all(&root_proc)?;
        mount(
            Some("/proc"),
            &root_proc,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .context("failed to stage proc for rootless rootfs")?;
    }

    // Mount volumes inside the new mount namespace, before pivot_root.
    // Host paths are still accessible; read-only remount works here.
    super::mounts::mount_volumes(new_root, volumes)?;

    let old_root = new_root.join("old_root");
    fs::create_dir_all(&old_root)?;

    pivot_root(new_root, &old_root).context("pivot_root failed")?;
    chdir("/").context("chdir to / failed")?;

    nix::mount::umount2("/old_root", nix::mount::MntFlags::MNT_DETACH)
        .context("failed to unmount old root")?;

    let _ = fs::remove_dir("/old_root");
    Ok(())
}
