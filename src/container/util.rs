//! Cross-platform helpers used by the non-Linux runtimes (Windows today,
//! macOS in future) and a couple of test-only utilities. Linux uses richer
//! variants in `container/linux/`.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Recursively copy a directory tree from `src` to `dst`.
///
/// When `try_hardlink` is `true`, files are hard-linked when possible (same
/// filesystem) and fall back to a full copy.  Use `true` for user-owned data
/// such as volume mounts.  Use `false` when copying shared layer caches into a
/// container's merged rootfs — hard-linking would let the container corrupt the
/// layer cache.
#[allow(dead_code)] // used by #[cfg(not(unix))] Windows module + tests
pub(crate) fn copy_dir_recursive(src: &Path, dst: &Path, try_hardlink: bool) -> Result<()> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((s, d)) = stack.pop() {
        for entry in std::fs::read_dir(&s).with_context(|| format!("read {}", s.display()))? {
            let entry = entry?;
            let (sp, dp) = (entry.path(), d.join(entry.file_name()));
            let ft = entry.file_type()?;
            if ft.is_dir() {
                let _ = std::fs::create_dir(&dp);
                stack.push((sp, dp));
            } else if ft.is_symlink() {
                let tgt = std::fs::read_link(&sp)?;
                let _ = std::fs::remove_file(&dp);
                crate::registry::create_symlink(&tgt, &dp)?;
            } else {
                let _ = std::fs::remove_file(&dp);
                if !try_hardlink || std::fs::hard_link(&sp, &dp).is_err() {
                    std::fs::copy(&sp, &dp).with_context(|| format!("copy {}", sp.display()))?;
                }
            }
        }
    }
    Ok(())
}

/// Simple cleanup guard for non-Linux runtimes (Windows, future macOS).
/// Removes the container directory on drop. The Linux runtime has its own
/// CleanupGuard with overlay unmount and cgroup cleanup.
#[allow(dead_code)] // used by #[cfg(not(unix))] Windows module + tests
pub(crate) struct SimpleCleanupGuard(pub PathBuf);
impl Drop for SimpleCleanupGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[allow(dead_code)]
pub(crate) fn which(name: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    let separator = ';';
    #[cfg(not(windows))]
    let separator = ':';
    std::env::var_os("PATH")?
        .to_str()?
        .split(separator)
        .map(|dir| PathBuf::from(dir).join(name))
        .find(|p| p.is_file())
}

/// Simple GC for non-Linux hosts: walk containers/, remove_dir_all each subdir.
/// On Windows, checks for an exclusive lock file before deleting (skips active containers).
/// Used by Windows (and future macOS) where there are no overlayfs mounts or flocks.
#[allow(dead_code)] // called from #[cfg(not(target_os = "linux"))] branch + tests
pub(crate) fn gc_simple(base_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(base_dir.join("containers")) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
            #[cfg(windows)]
            if super::windows::is_container_locked(&entry.path()) {
                continue;
            }
            if std::fs::remove_dir_all(entry.path()).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_dir_recursive_basic() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (src, dst) = (tmp.path().join("src"), tmp.path().join("dst"));
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "hello").unwrap();
        std::fs::write(src.join("sub/b.txt"), "world").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a.txt", src.join("link.txt")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        copy_dir_recursive(&src, &dst, true).unwrap();
        assert_eq!(std::fs::read_to_string(dst.join("a.txt")).unwrap(), "hello");
        assert_eq!(
            std::fs::read_to_string(dst.join("sub/b.txt")).unwrap(),
            "world"
        );
        #[cfg(unix)]
        {
            assert!(dst.join("link.txt").is_symlink());
            assert_eq!(
                std::fs::read_link(dst.join("link.txt"))
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "a.txt"
            );
        }
        #[cfg(windows)]
        {
            // On Windows, symlink creation requires Developer Mode or admin.
            // If the symlink was created successfully in src, verify the copy.
            if std::os::windows::fs::symlink_file("a.txt", src.join("link.txt")).is_ok() {
                let dst2 = tmp.path().join("dst2");
                std::fs::create_dir_all(&dst2).unwrap();
                copy_dir_recursive(&src, &dst2, true).unwrap();
                assert!(dst2.join("link.txt").is_symlink());
                assert_eq!(
                    std::fs::read_link(dst2.join("link.txt"))
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    "a.txt"
                );
            }
            // If symlink creation fails (no Developer Mode), that's OK — the
            // Windows extract path already handles this gracefully.
        }
        // Overwrite: second copy replaces shared file
        std::fs::write(src.join("a.txt"), "new").unwrap();
        copy_dir_recursive(&src, &dst, true).unwrap();
        assert_eq!(std::fs::read_to_string(dst.join("a.txt")).unwrap(), "new");
    }

    #[test]
    fn copy_dir_no_hardlink_isolates_source() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (src, dst) = (tmp.path().join("src"), tmp.path().join("dst"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("data.txt"), "original").unwrap();

        // Copy without hard links — modifying dst must not affect src
        copy_dir_recursive(&src, &dst, false).unwrap();
        std::fs::write(dst.join("data.txt"), "modified").unwrap();
        assert_eq!(
            std::fs::read_to_string(src.join("data.txt")).unwrap(),
            "original",
            "source file was modified — copy_dir_recursive leaked a hard link"
        );
    }

    #[test]
    fn gc_simple_all_cases() {
        // Missing containers dir — should not panic
        let tmp = tempfile::TempDir::new().unwrap();
        assert_eq!(gc_simple(tmp.path()), 0);

        // Removes directories, leaves files
        let containers = tmp.path().join("containers");
        std::fs::create_dir_all(containers.join("stale1")).unwrap();
        std::fs::create_dir_all(containers.join("stale2/sub")).unwrap();
        std::fs::write(containers.join("not_a_dir"), "x").unwrap();
        gc_simple(tmp.path());
        assert!(!containers.join("stale1").exists());
        assert!(!containers.join("stale2").exists());
        assert!(containers.join("not_a_dir").exists());
    }

    #[test]
    fn simple_cleanup_guard_removes_on_drop() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("ctest");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        {
            let _guard = SimpleCleanupGuard(dir.clone());
            assert!(dir.exists());
        }
        assert!(!dir.exists());
    }

    #[test]
    #[cfg(unix)]
    fn which_lookup() {
        assert!(which("env").unwrap().is_file());
        assert!(which("hippobox_nonexistent_binary_xyz").is_none());
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("mytool"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            tmp.path().join("mytool"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let original = std::env::var_os("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", tmp.path().display(), original.to_string_lossy());
        unsafe {
            std::env::set_var("PATH", &new_path);
        }
        let result = which("mytool");
        unsafe {
            std::env::set_var("PATH", &original);
        }
        assert_eq!(result.unwrap().file_name().unwrap(), "mytool");
    }

    #[test]
    #[cfg(windows)]
    fn which_lookup_windows() {
        // cmd.exe is always present on Windows
        assert!(which("cmd.exe").unwrap().is_file());
        assert!(which("hippobox_nonexistent_binary_xyz").is_none());
    }
}
