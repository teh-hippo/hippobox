use anyhow::{Context, Result};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{chdir, pivot_root};
use std::fs;
use std::path::Path;

/// Set up mount/UTS/IPC isolation and pivot into the container root.
/// PID isolation is not enabled yet; the runtime keeps the host PID namespace for now.
pub fn setup_namespaces_and_pivot(new_root: &Path, rootless: bool) -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWIPC)
        .context("failed to unshare namespaces")?;

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

    let old_root = new_root.join("old_root");
    fs::create_dir_all(&old_root)?;

    pivot_root(new_root, &old_root).context("pivot_root failed")?;
    chdir("/").context("chdir to / failed")?;

    nix::mount::umount2("/old_root", nix::mount::MntFlags::MNT_DETACH)
        .context("failed to unmount old root")?;

    let _ = fs::remove_dir("/old_root");
    Ok(())
}
