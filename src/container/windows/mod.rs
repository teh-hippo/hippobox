use anyhow::{Context, Result};
use std::path::PathBuf;

pub(crate) fn run(spec: super::ContainerSpec) -> Result<i32> {
    let super::ContainerSpec {
        id,
        image_ref,
        manifest,
        config,
        base_dir,
        user_cmd,
        user_env,
        ..
    } = spec;

    let cc = config.config.as_ref();
    let argv = super::build_argv(cc, user_cmd)?;
    let env_vars = super::build_env_vars(cc, &user_env)?;

    let container_dir = base_dir.join("containers").join(&id);
    let merged = container_dir.join("merged");
    std::fs::create_dir_all(&merged)?;

    let _guard = CleanupGuard {
        container_dir: container_dir.clone(),
    };

    // Merge layers bottom-up (manifest order is top-to-bottom)
    for layer in manifest.layers.iter().rev() {
        let layer_dir = layer.layer_dir(&base_dir);
        if !layer_dir.exists() {
            anyhow::bail!(
                "layer directory missing: {} — image may need re-pulling",
                layer_dir.display()
            );
        }
        copy_dir_recursive(&layer_dir, &merged)?;
    }

    eprintln!(
        "starting windows container {} ({}/{}/{})",
        &id[..12.min(id.len())],
        image_ref.registry,
        image_ref.repository,
        image_ref.tag
    );

    // Resolve the entrypoint within the merged rootfs.
    // Windows container images store filesystem content under a `Files\` subtree.
    // Absolute image paths like `c:\windows\system32\cmd.exe` map to
    // `<merged>\Files\windows\system32\cmd.exe`.
    let merged_str = merged.to_string_lossy();
    let entrypoint = &argv[0];
    let resolved = resolve_win_path(entrypoint, &merged_str);

    eprintln!("  cmd: {:?}", argv);

    let mut cmd = std::process::Command::new(&resolved);
    for arg in &argv[1..] {
        cmd.arg(arg);
    }

    // Inject environment variables from the image config
    for kv in &env_vars {
        if let Some((k, v)) = kv.split_once('=') {
            cmd.env(k, v);
        }
    }

    // Build PATH: resolve each image PATH entry within the merged rootfs,
    // then append the host PATH so Windows system tools remain available.
    let separator = if cfg!(windows) { ';' } else { ':' };
    let img_path_entries: Vec<&str> = env_vars
        .iter()
        .find_map(|v| v.strip_prefix("PATH=").or_else(|| v.strip_prefix("Path=")))
        .map(|p| p.split(separator).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    let mut path_parts: Vec<String> = img_path_entries
        .iter()
        .map(|p| resolve_win_path(p, &merged_str))
        .collect();
    let existing_path = std::env::var("PATH").unwrap_or_default();
    if !existing_path.is_empty() {
        path_parts.push(existing_path);
    }
    if !path_parts.is_empty() {
        cmd.env("PATH", path_parts.join(&separator.to_string()));
    }

    let status = cmd.status().context("failed to launch Windows process")?;
    Ok(status.code().unwrap_or(1))
}

/// Resolve a Windows path from an image config into the merged rootfs.
///
/// Windows container images use absolute paths like `c:\windows\system32\cmd.exe`.
/// The container rootfs uses a `Files\` prefix for the filesystem root, so
/// `c:\windows\...` maps to `<merged>\Files\windows\...`.
///
/// - Absolute Windows path (`c:\...`): strip drive prefix, prepend `<merged>\Files\`
/// - Relative path with separators: prepend `<merged>\Files\`
/// - Bare command name: return as-is for PATH lookup
/// - Unix-style flags (`/c`, `/help`): return as-is (not paths)
fn resolve_win_path(path: &str, merged: &str) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    // Normalise all path separators to the platform separator
    let normalised = path.replace('/', &sep.to_string()).replace('\\', &sep.to_string());

    // Absolute Windows path with drive letter: c:\windows\... → <merged>\Files\windows\...
    if normalised.len() >= 2
        && normalised.as_bytes()[0].is_ascii_alphabetic()
        && normalised.as_bytes()[1] == b':'
    {
        let after_drive = &normalised[2..];
        let relative = after_drive
            .strip_prefix(sep)
            .unwrap_or(after_drive);
        return format!("{merged}{sep}Files{sep}{relative}");
    }

    // Paths starting with separator and containing at least one more segment
    // (e.g. \Windows\System32\cmd.exe) — not bare \c or \help style flags
    if normalised.starts_with(sep) && normalised[1..].contains(sep) {
        let relative = &normalised[1..];
        return format!("{merged}{sep}Files{sep}{relative}");
    }

    // Relative path with separators (e.g. Windows\System32\cmd.exe)
    // Exclude single-segment paths like \c or \help (command flags)
    if normalised.contains(sep) && !normalised.starts_with(sep) {
        return format!("{merged}{sep}Files{sep}{normalised}");
    }

    // Bare command name or flag — return as-is for PATH lookup
    normalised
}

/// Recursively copy `src` into `dst`, preferring hardlinks for regular files.
///
/// Layer directories are read-only, so hardlinking is safe and avoids copying
/// file contents entirely. Falls back to a full copy when the source and dest
/// are on different filesystems (EXDEV / OS error 17).
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((s, d)) = stack.pop() {
        let entries = std::fs::read_dir(&s)
            .with_context(|| format!("failed to read layer directory: {}", s.display()))?;
        for entry in entries {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = d.join(entry.file_name());
            let ft = entry.file_type()?;
            if ft.is_dir() {
                let _ = std::fs::create_dir(&dst_path);
                stack.push((src_path, dst_path));
            } else if ft.is_symlink() {
                let target = std::fs::read_link(&src_path)?;
                let _ = std::fs::remove_file(&dst_path);
                create_symlink(&target, &dst_path).with_context(|| {
                    format!(
                        "failed to create symlink {} -> {}",
                        dst_path.display(),
                        target.display()
                    )
                })?;
            } else {
                // Remove existing file first (may be a hardlink from a lower layer)
                let _ = std::fs::remove_file(&dst_path);
                // Try hardlink first — zero-copy for same-filesystem layer dirs
                if std::fs::hard_link(&src_path, &dst_path).is_err() {
                    std::fs::copy(&src_path, &dst_path).with_context(|| {
                        format!(
                            "failed to copy {} to {}",
                            src_path.display(),
                            dst_path.display()
                        )
                    })?;
                }
            }
        }
    }
    Ok(())
}

/// Create a symlink — platform-specific.
fn create_symlink(target: &std::path::Path, link: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)?;
    }
    #[cfg(windows)]
    {
        // On Windows, we need to distinguish between file and directory symlinks.
        // In OCI layers the target may not exist yet, so default to file symlink.
        if target.is_dir() {
            std::os::windows::fs::symlink_dir(target, link)?;
        } else {
            std::os::windows::fs::symlink_file(target, link)?;
        }
    }
    Ok(())
}

/// RAII cleanup for container directories.
struct CleanupGuard {
    container_dir: PathBuf,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.container_dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_dir_recursive_basic() {
        let tmp = tempfile::TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "hello").unwrap();
        std::fs::write(src.join("sub/b.txt"), "world").unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        copy_dir_recursive(&src, &dst).unwrap();
        assert_eq!(std::fs::read_to_string(dst.join("a.txt")).unwrap(), "hello");
        assert_eq!(
            std::fs::read_to_string(dst.join("sub/b.txt")).unwrap(),
            "world"
        );
    }

    #[test]
    fn copy_dir_recursive_overwrite() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lower = tmp.path().join("lower");
        let upper = tmp.path().join("upper");
        let merged = tmp.path().join("merged");
        std::fs::create_dir_all(&lower).unwrap();
        std::fs::create_dir_all(&upper).unwrap();
        std::fs::create_dir_all(&merged).unwrap();
        std::fs::write(lower.join("f.txt"), "from-lower").unwrap();
        std::fs::write(upper.join("f.txt"), "from-upper").unwrap();
        copy_dir_recursive(&lower, &merged).unwrap();
        copy_dir_recursive(&upper, &merged).unwrap();
        assert_eq!(
            std::fs::read_to_string(merged.join("f.txt")).unwrap(),
            "from-upper"
        );
    }

    #[test]
    fn copy_dir_recursive_uses_hardlinks() {
        let tmp = tempfile::TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "data").unwrap();
        copy_dir_recursive(&src, &dst).unwrap();
        // Hardlinks produce the same file size and content at minimum
        assert_eq!(
            std::fs::read_to_string(dst.join("file.txt")).unwrap(),
            "data"
        );
        // On the same filesystem, the hardlink should succeed.
        // We can't portably check inode numbers, so just verify content.
    }

    #[cfg(unix)]
    #[test]
    fn copy_dir_recursive_uses_hardlinks_inode() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("file.txt"), "data").unwrap();
        copy_dir_recursive(&src, &dst).unwrap();
        let src_ino = std::fs::metadata(src.join("file.txt")).unwrap().ino();
        let dst_ino = std::fs::metadata(dst.join("file.txt")).unwrap().ino();
        assert_eq!(src_ino, dst_ino, "should use hardlink (same inode)");
    }

    #[test]
    fn copy_dir_recursive_handles_symlinks() {
        let tmp = tempfile::TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("real.txt"), "content").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("real.txt", src.join("link.txt")).unwrap();
        #[cfg(windows)]
        {
            // On Windows, symlink creation may require elevated privileges.
            if std::os::windows::fs::symlink_file("real.txt", src.join("link.txt")).is_err() {
                eprintln!("skipping symlink test: insufficient privileges");
                return;
            }
        }
        copy_dir_recursive(&src, &dst).unwrap();
        assert!(dst.join("link.txt").is_symlink());
        assert_eq!(
            std::fs::read_link(dst.join("link.txt"))
                .unwrap()
                .to_str()
                .unwrap(),
            "real.txt"
        );
    }

    #[test]
    fn cleanup_guard_removes_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("container-test");
        std::fs::create_dir_all(dir.join("merged")).unwrap();
        std::fs::write(dir.join("merged/file.txt"), "data").unwrap();
        {
            let _guard = CleanupGuard {
                container_dir: dir.clone(),
            };
            assert!(dir.exists());
        }
        assert!(
            !dir.exists(),
            "CleanupGuard should remove the directory on drop"
        );
    }

    #[test]
    fn layer_merge_ordering() {
        let tmp = tempfile::TempDir::new().unwrap();
        let layer1 = tmp.path().join("layer1");
        let layer2 = tmp.path().join("layer2");
        let merged = tmp.path().join("merged");
        std::fs::create_dir_all(&layer1).unwrap();
        std::fs::create_dir_all(&layer2).unwrap();
        std::fs::create_dir_all(&merged).unwrap();
        std::fs::write(layer1.join("shared.txt"), "from-layer1").unwrap();
        std::fs::write(layer1.join("only-in-1.txt"), "layer1-only").unwrap();
        std::fs::write(layer2.join("shared.txt"), "from-layer2").unwrap();
        std::fs::write(layer2.join("only-in-2.txt"), "layer2-only").unwrap();
        copy_dir_recursive(&layer1, &merged).unwrap();
        copy_dir_recursive(&layer2, &merged).unwrap();
        assert_eq!(
            std::fs::read_to_string(merged.join("shared.txt")).unwrap(),
            "from-layer2"
        );
        assert_eq!(
            std::fs::read_to_string(merged.join("only-in-1.txt")).unwrap(),
            "layer1-only"
        );
        assert_eq!(
            std::fs::read_to_string(merged.join("only-in-2.txt")).unwrap(),
            "layer2-only"
        );
    }

    #[test]
    fn resolve_win_path_cases() {
        let sep = std::path::MAIN_SEPARATOR;
        let merged = format!("C:{sep}Users{sep}test{sep}hippobox{sep}containers{sep}abc{sep}merged");
        // Absolute Windows path: strip drive, add Files
        assert_eq!(
            resolve_win_path(r"c:\windows\system32\cmd.exe", &merged),
            format!("{merged}{sep}Files{sep}windows{sep}system32{sep}cmd.exe")
        );
        assert_eq!(
            resolve_win_path(r"C:\Program Files\PowerShell\7\pwsh.exe", &merged),
            format!("{merged}{sep}Files{sep}Program Files{sep}PowerShell{sep}7{sep}pwsh.exe")
        );
        // Forward slashes normalised
        assert_eq!(
            resolve_win_path("c:/windows/system32/cmd.exe", &merged),
            format!("{merged}{sep}Files{sep}windows{sep}system32{sep}cmd.exe")
        );
        // Absolute path without drive letter
        assert_eq!(
            resolve_win_path(r"\Windows\System32\cmd.exe", &merged),
            format!("{merged}{sep}Files{sep}Windows{sep}System32{sep}cmd.exe")
        );
        // Relative path with separators
        assert_eq!(
            resolve_win_path(r"Windows\System32\cmd.exe", &merged),
            format!("{merged}{sep}Files{sep}Windows{sep}System32{sep}cmd.exe")
        );
        // Bare command — returned as-is
        assert_eq!(resolve_win_path("pwsh.exe", &merged), "pwsh.exe");
        assert_eq!(resolve_win_path("cmd.exe", &merged), "cmd.exe");
    }
}
