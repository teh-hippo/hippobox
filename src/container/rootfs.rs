use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use std::path::{Path, PathBuf};

/// Mount overlayfs with the given lower layers, upper dir, work dir, and merge point.
pub fn mount_overlay(
    lower_dirs: &[PathBuf],
    upper: &Path,
    work: &Path,
    merged: &Path,
) -> Result<()> {
    let lowerdir = lower_dirs
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(":");

    let options = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowerdir,
        upper.display(),
        work.display()
    );

    mount(
        Some("overlay"),
        merged,
        Some("overlay"),
        MsFlags::empty(),
        Some(options.as_str()),
    )
    .context("failed to mount overlayfs")?;

    Ok(())
}

/// Unmount overlayfs.
pub fn unmount_overlay(merged: &Path) -> Result<()> {
    umount2(merged, MntFlags::MNT_DETACH).context("failed to unmount overlayfs")?;
    Ok(())
}
