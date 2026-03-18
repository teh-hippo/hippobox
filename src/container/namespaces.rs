use anyhow::{Context, Result};
use nix::sched::{unshare, CloneFlags};
use nix::mount::{mount, MsFlags};
use nix::unistd::{pivot_root, chdir};
use std::path::Path;

/// Set up namespaces and pivot_root into the new root.
/// This must be called from the child process (after re-exec).
pub fn setup_namespaces_and_pivot(new_root: &Path) -> Result<()> {
    // Unshare PID, mount, UTS, IPC namespaces (network is shared — host networking)
    unshare(
        CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC,
    )
    .context("failed to unshare namespaces")?;

    // CRITICAL: Set mount propagation to private before any other mounts
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("failed to set mount propagation to private")?;

    // Bind-mount new_root onto itself (pivot_root requires a mount point)
    mount(
        Some(new_root),
        new_root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("failed to bind-mount new root")?;

    // Create put_old directory inside new_root
    let old_root = new_root.join("old_root");
    std::fs::create_dir_all(&old_root)?;

    // pivot_root
    pivot_root(new_root, &old_root).context("pivot_root failed")?;

    // chdir to new root
    chdir("/").context("chdir to / failed")?;

    // Unmount old root (lazy unmount handles busy mounts)
    nix::mount::umount2("/old_root", nix::mount::MntFlags::MNT_DETACH)
        .context("failed to unmount old root")?;

    // Remove old_root directory
    std::fs::remove_dir("/old_root").ok(); // Best effort

    Ok(())
}
