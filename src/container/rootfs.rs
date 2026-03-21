use anyhow::{Context, Result};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::path::{Path, PathBuf};

/// Mount overlayfs with the given lower layers, upper dir, work dir, and merge point.
/// When `rootless` is true, attempts `redirect_dir=on` first (needed for directory
/// renames in unprivileged overlayfs), falling back without it if the kernel rejects it.
pub(super) fn mount_overlay(
    lower_dirs: &[PathBuf],
    upper: &Path,
    work: &Path,
    merged: &Path,
    rootless: bool,
) -> Result<()> {
    use std::fmt::Write;
    let mut base_options = String::with_capacity(256);
    base_options.push_str("lowerdir=");
    for (i, p) in lower_dirs.iter().enumerate() {
        if i > 0 {
            base_options.push(':');
        }
        let _ = write!(base_options, "{}", p.display());
    }
    let _ = write!(
        base_options,
        ",upperdir={},workdir={},volatile",
        upper.display(),
        work.display()
    );

    if rootless {
        let with_redirect = format!("{base_options},redirect_dir=on");
        if mount(
            Some("overlay"),
            merged,
            Some("overlay"),
            MsFlags::empty(),
            Some(with_redirect.as_str()),
        )
        .is_ok()
        {
            return Ok(());
        }
    }

    mount(
        Some("overlay"),
        merged,
        Some("overlay"),
        MsFlags::empty(),
        Some(base_options.as_str()),
    )
    .context("failed to mount overlayfs")
}

/// Unmount overlayfs.
pub(super) fn unmount_overlay(merged: &Path) -> Result<()> {
    umount2(merged, MntFlags::MNT_DETACH).context("failed to unmount overlayfs")
}
