use anyhow::{Context, Result};
use nix::fcntl::{Flock, FlockArg};
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(super) fn acquire_container_lock(container_dir: &Path) -> Result<Flock<File>> {
    let lock_path = container_dir.join("hippobox.lock");
    let lock_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("failed to open lock at {}", lock_path.display()))?;
    Flock::lock(lock_file, FlockArg::LockExclusive)
        .map_err(|(_, e)| e)
        .with_context(|| format!("failed to flock {}", lock_path.display()))
}

/// Clean up stale containers from previous runs that didn't get a chance to clean
/// up (e.g. the hippobox process was killed). Best-effort: logs warnings and
/// continues on individual failures.
pub fn gc_stale_containers(base_dir: &Path) {
    let containers_dir = base_dir.join("containers");
    let entries = match std::fs::read_dir(&containers_dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !entry.file_type().is_ok_and(|ft| ft.is_dir()) {
            continue;
        }

        // Skip containers we don't own (e.g. rootful containers when running rootless).
        // Avoids wasting time on umount/remove_dir_all that will always EPERM.
        if let Ok(meta) = std::fs::metadata(&path) {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != nix::unistd::getuid().as_raw() {
                continue;
            }
        }

        if let Err(e) = gc_try_clean_container(&path) {
            eprintln!(
                "warning: gc failed for {}: {e}",
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
        }
    }
}

fn gc_try_clean_container(container_dir: &Path) -> Result<()> {
    let lock_path = container_dir.join("hippobox.lock");

    // No lock file means a legacy or partially-created container. Try to clean it.
    if lock_path.exists() {
        let lock_file = File::open(&lock_path)?;
        match Flock::lock(lock_file, FlockArg::LockExclusiveNonblock) {
            Ok(_flock) => {
                // Lock acquired — the owner process is dead. Proceed with cleanup.
            }
            Err((_, nix::errno::Errno::EAGAIN)) => {
                // Lock held by another process — container is active.
                return Ok(());
            }
            Err((_, e)) => return Err(e).context("failed to probe container lock"),
        }
    }

    let merged = container_dir.join("merged");
    if merged.exists() {
        // Unmount device bind mounts first (children before parent).
        let _ = super::mounts::cleanup_host_device_sources(&merged);

        // Try non-detach overlay unmount.
        // EINVAL: not mounted. ENOENT: path gone. EPERM: rootless user namespace mount.
        match nix::mount::umount2(&merged, nix::mount::MntFlags::empty()) {
            Ok(_)
            | Err(
                nix::errno::Errno::EINVAL
                | nix::errno::Errno::ENOENT
                | nix::errno::Errno::EPERM,
            ) => {}
            Err(nix::errno::Errno::EBUSY) => {
                eprintln!(
                    "warning: overlay still busy for {}, skipping",
                    container_dir
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                );
                return Ok(());
            }
            Err(e) => return Err(e).context("failed to unmount stale overlay"),
        }
    }

    fix_overlay_workdir(container_dir);
    let _ = std::fs::remove_dir_all(container_dir);
    Ok(())
}

/// Overlayfs work dirs have restrictive permissions (mode 000) that prevent
/// removal. Recursively fix permissions before cleanup.
fn fix_overlay_workdir(container_dir: &Path) {
    fn fix_recursive(dir: &Path) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
                    fix_recursive(&path);
                }
            }
        }
    }
    let work_dir = container_dir.join("work");
    if work_dir.exists() {
        let _ = std::fs::set_permissions(&work_dir, std::fs::Permissions::from_mode(0o700));
        fix_recursive(&work_dir);
    }
}

pub(super) struct CleanupGuard {
    pub id: String,
    pub container_dir: PathBuf,
    pub merged: PathBuf,
    pub layer_dirs: Vec<PathBuf>,
    pub overlay_mounted: bool,
    pub rootless: bool,
    pub _lock: Flock<File>,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if !self.rootless {
            let _ = super::cgroups::cleanup(&self.id);
        }
        let can_remove = if self.overlay_mounted {
            let _ = super::mounts::cleanup_host_device_sources(&self.merged);
            super::rootfs::unmount_overlay(&self.merged).is_ok()
        } else {
            true
        };
        for dir in &self.layer_dirs {
            let _ = std::fs::remove_file(dir.join(".in-use"));
        }
        if can_remove {
            fix_overlay_workdir(&self.container_dir);
            let _ = std::fs::remove_dir_all(&self.container_dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_container_dir(base: &Path, name: &str) -> PathBuf {
        let dir = base.join("containers").join(name);
        std::fs::create_dir_all(dir.join("merged")).unwrap();
        std::fs::create_dir_all(dir.join("upper")).unwrap();
        std::fs::create_dir_all(dir.join("work")).unwrap();
        dir
    }

    #[test]
    fn gc_removes_dir_with_no_lock_file() {
        let tmp = TempDir::new().unwrap();
        let container = make_container_dir(tmp.path(), "stale-no-lock");

        gc_stale_containers(tmp.path());
        assert!(!container.exists(), "stale container without lock should be removed");
    }

    #[test]
    fn gc_skips_container_with_held_lock() {
        let tmp = TempDir::new().unwrap();
        let container = make_container_dir(tmp.path(), "active");
        let _lock = acquire_container_lock(&container).unwrap();

        gc_stale_containers(tmp.path());
        assert!(container.exists(), "active container should be kept");
    }

    #[test]
    fn gc_removes_container_with_released_lock() {
        let tmp = TempDir::new().unwrap();
        let container = make_container_dir(tmp.path(), "dead-owner");

        // Acquire and immediately release the lock.
        {
            let _lock = acquire_container_lock(&container).unwrap();
        }

        gc_stale_containers(tmp.path());
        assert!(!container.exists(), "container with released lock should be removed");
    }

    #[test]
    fn gc_handles_empty_containers_dir() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("containers")).unwrap();

        gc_stale_containers(tmp.path());
        // Should not panic or error.
    }

    #[test]
    fn gc_handles_missing_containers_dir() {
        let tmp = TempDir::new().unwrap();
        // No containers/ dir at all.

        gc_stale_containers(tmp.path());
        // Should not panic or error.
    }

    #[test]
    fn gc_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let container = make_container_dir(tmp.path(), "once-stale");

        gc_stale_containers(tmp.path());
        assert!(!container.exists());

        // Second run should be a no-op.
        gc_stale_containers(tmp.path());
    }
}
