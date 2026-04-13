use anyhow::{Context, Result, bail};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

pub(super) fn has_unsafe_components(path: &Path) -> bool {
    path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

/// Extract a Linux OCI layer, handling `.wh.` whiteout files and opaque dirs.
#[cfg(unix)]
pub fn extract_linux_layer(archive: &mut tar::Archive<impl Read>, target: &Path) -> Result<()> {
    use std::ffi::CString;

    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(false);

    let safe_dir = |relative: &Path| -> Result<PathBuf> {
        if has_unsafe_components(relative) {
            bail!("unsafe archive path component in {}", relative.display());
        }
        let mut out = target.to_path_buf();
        for component in relative.components() {
            if let Component::Normal(part) = component {
                out.push(part);
                match fs::symlink_metadata(&out) {
                    Ok(m) if m.file_type().is_symlink() => bail!(
                        "refusing to traverse symlink while extracting: {}",
                        out.display()
                    ),
                    Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
                    _ => {}
                }
            }
        }
        fs::create_dir_all(&out)?;
        Ok(out)
    };

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if has_unsafe_components(&path) {
            bail!("unsafe archive path component in {}", path.display());
        }
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if file_name == ".wh..wh..opq" {
            let parent = safe_dir(path.parent().unwrap_or(Path::new("")))?;
            let c_path = CString::new(parent.to_string_lossy().as_bytes())?;
            let ret = unsafe {
                nix::libc::setxattr(
                    c_path.as_ptr(),
                    c"trusted.overlay.opaque".as_ptr(),
                    b"y".as_ptr().cast(),
                    1,
                    0,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error()).with_context(|| {
                    format!("failed to set opaque xattr on {}", parent.display())
                });
            }
            continue;
        }

        if let Some(deleted_name) = file_name.strip_prefix(".wh.") {
            if deleted_name.is_empty()
                || deleted_name == "."
                || deleted_name == ".."
                || deleted_name.contains('/')
                || deleted_name.contains('\\')
                || Path::new(deleted_name).components().count() != 1
            {
                bail!("unsafe whiteout name: {deleted_name}");
            }
            let parent = safe_dir(path.parent().unwrap_or(Path::new("")))?;
            let wp = parent.join(deleted_name);
            if let Ok(m) = fs::symlink_metadata(&wp) {
                if m.file_type().is_dir() && !m.file_type().is_symlink() {
                    fs::remove_dir_all(&wp)?;
                } else {
                    fs::remove_file(&wp)?;
                }
            }
            nix::sys::stat::mknod(
                &wp,
                nix::sys::stat::SFlag::S_IFCHR,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                nix::sys::stat::makedev(0, 0),
            )
            .with_context(|| format!("failed to create whiteout at {}", wp.display()))?;
            continue;
        }

        if !entry.unpack_in(target)? {
            bail!("archive entry escapes target directory: {}", path.display());
        }
    }
    Ok(())
}

/// Extract a Windows OCI layer — manual extraction with Windows-specific filtering.
///
/// Windows layers differ from Linux in several ways:
/// - No `.wh.` whiteout files or xattr-based opaque directories
/// - Paths may use backslashes internally
/// - May contain `UtilityVM/` subtrees (Hyper-V isolation artefacts) — skipped
/// - May contain NTFS alternate data stream entries (`:` in filename) — skipped
///
/// We cannot use the tar crate's `unpack_in` for Windows layers because Windows
/// tar archives often carry NTFS ACL-derived directory modes (e.g. 000). The
/// `unpack_in` method calls `fs::canonicalize` which traverses parent directories;
/// if a parent was extracted with mode 000, the traversal fails with EACCES.
/// Instead, we manually create directories and write files ourselves.
pub fn extract_windows_layer(archive: &mut tar::Archive<impl Read>, target: &Path) -> Result<()> {
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.into_owned();

        // Normalise backslashes to forward slashes
        let normalised = if raw_path.to_string_lossy().contains('\\') {
            PathBuf::from(raw_path.to_string_lossy().replace('\\', "/"))
        } else {
            raw_path
        };

        if has_unsafe_components(&normalised) {
            bail!("unsafe archive path component in {}", normalised.display());
        }

        // Skip UtilityVM subtrees (Hyper-V isolation artefacts)
        if normalised
            .components()
            .next()
            .and_then(|c| {
                if let Component::Normal(s) = c {
                    Some(s)
                } else {
                    None
                }
            })
            .is_some_and(|s| s.eq_ignore_ascii_case("UtilityVM"))
        {
            continue;
        }

        // Skip NTFS alternate data stream entries (contain ':' in filename)
        let path_str = normalised.to_string_lossy();
        if path_str.contains(':') {
            continue;
        }

        let dest = target.join(&normalised);

        // Safety: validate that the resolved path stays within `target`.
        // Build the path component-by-component, refusing symlink traversal.
        {
            let mut check = target.to_path_buf();
            for component in normalised.components() {
                if let Component::Normal(part) = component {
                    check.push(part);
                    match fs::symlink_metadata(&check) {
                        Ok(m) if m.file_type().is_symlink() => bail!(
                            "refusing to traverse symlink while extracting: {}",
                            check.display()
                        ),
                        Err(e) if e.kind() != io::ErrorKind::NotFound => {}
                        _ => {}
                    }
                }
            }
        }

        let etype = entry.header().entry_type();
        if etype.is_dir() {
            fs::create_dir_all(&dest)?;
            set_dir_permissions(&dest)?;
        } else if etype.is_symlink() {
            if let Some(link_target) = entry.link_name()? {
                let link_path = PathBuf::from(link_target.to_string_lossy().replace('\\', "/"));
                let _ = fs::remove_file(&dest);
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                    set_dir_permissions(parent)?;
                }
                create_symlink(&link_path, &dest)?;
            }
        } else if etype.is_file() || etype == tar::EntryType::Continuous {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
                set_dir_permissions(parent)?;
            }
            let _ = fs::remove_file(&dest);
            let mut out = fs::File::create(&dest)
                .with_context(|| format!("failed to create {}", dest.display()))?;
            io::copy(&mut entry, &mut out)
                .with_context(|| format!("failed to write {}", dest.display()))?;
            set_file_permissions(&dest, &normalised)?;
        }
        // Skip hardlinks and other entry types — uncommon in Windows layers
    }
    Ok(())
}

/// Set directory permissions — platform-specific.
fn set_dir_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    // On Windows, NTFS handles directory permissions via ACLs — no action needed.
    let _ = path;
    Ok(())
}

/// Set file permissions — platform-specific.
fn set_file_permissions(path: &Path, normalised: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let ext = normalised
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let mode = if matches!(ext.as_str(), "exe" | "dll" | "cmd" | "bat" | "ps1" | "com") {
            0o755
        } else {
            0o644
        };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    // On Windows, NTFS handles file permissions via ACLs — no action needed.
    let _ = (path, normalised);
    Ok(())
}

/// Create a symlink — platform-specific.
fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).with_context(|| {
            format!(
                "failed to create symlink {} -> {}",
                link.display(),
                target.display()
            )
        })?;
    }
    #[cfg(windows)]
    {
        // On Windows, we need to know if the target is a directory or file.
        // In OCI layers the target may not exist yet, so default to file symlink.
        if target.is_dir() {
            std::os::windows::fs::symlink_dir(target, link).with_context(|| {
                format!(
                    "failed to create dir symlink {} -> {}",
                    link.display(),
                    target.display()
                )
            })?;
        } else {
            std::os::windows::fs::symlink_file(target, link).with_context(|| {
                format!(
                    "failed to create file symlink {} -> {}",
                    link.display(),
                    target.display()
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tar_entry(path: &str, content: &[u8], mode: u32, etype: tar::EntryType) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_path(path).unwrap();
        h.set_size(content.len() as u64);
        h.set_mode(mode);
        h.set_entry_type(etype);
        h.set_cksum();
        b.append(&h, content).unwrap();
        b.into_inner().unwrap()
    }
    fn tar_raw_path(path_bytes: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.as_gnu_mut().unwrap().name[..path_bytes.len()].copy_from_slice(path_bytes);
        h.as_gnu_mut().unwrap().name[path_bytes.len()] = 0;
        h.set_size(4);
        h.set_mode(0o644);
        h.set_cksum();
        b.append(&h, b"evil" as &[u8]).unwrap();
        b.into_inner().unwrap()
    }

    #[cfg(unix)]
    fn untar_linux(data: &[u8], dir: &Path) -> Result<()> {
        extract_linux_layer(&mut tar::Archive::new(std::io::Cursor::new(data)), dir)
    }

    fn untar_windows(data: &[u8], dir: &Path) -> Result<()> {
        extract_windows_layer(&mut tar::Archive::new(std::io::Cursor::new(data)), dir)
    }

    // ── Path safety tests ──

    #[test]
    fn path_safety() {
        for (p, expect) in [
            ("usr/bin/bash", false),
            ("./foo/bar", false),
            ("", false),
            ("/etc/passwd", true),
            ("foo/../etc", true),
            ("..", true),
        ] {
            assert_eq!(has_unsafe_components(Path::new(p)), expect, "path={p:?}");
        }
    }

    // ── Linux extraction tests ──

    #[cfg(unix)]
    #[test]
    fn extract_valid_and_nested() {
        let t = TempDir::new().unwrap();
        untar_linux(
            &tar_entry("hello.txt", b"hello", 0o644, tar::EntryType::Regular),
            t.path(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(t.path().join("hello.txt")).unwrap(),
            "hello"
        );
        let t2 = TempDir::new().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut dh = tar::Header::new_gnu();
        dh.set_path("usr/local/bin/").unwrap();
        dh.set_size(0);
        dh.set_mode(0o755);
        dh.set_entry_type(tar::EntryType::Directory);
        dh.set_cksum();
        b.append(&dh, &[][..]).unwrap();
        let mut fh = tar::Header::new_gnu();
        fh.set_path("usr/local/bin/tool").unwrap();
        fh.set_size(4);
        fh.set_mode(0o755);
        fh.set_cksum();
        b.append(&fh, b"test" as &[u8]).unwrap();
        untar_linux(&b.into_inner().unwrap(), t2.path()).unwrap();
        assert_eq!(
            fs::read_to_string(t2.path().join("usr/local/bin/tool")).unwrap(),
            "test"
        );
    }

    #[cfg(unix)]
    #[test]
    fn extract_security() {
        for p in [b"/etc/shadow" as &[u8], b"../../etc/passwd"] {
            assert!(untar_linux(&tar_raw_path(p), &TempDir::new().unwrap().path()).is_err());
        }
        let t = TempDir::new().unwrap();
        std::os::unix::fs::symlink("/tmp", t.path().join("evil")).unwrap();
        assert!(
            untar_linux(
                &tar_entry(
                    "evil/payload.txt",
                    b"attack",
                    0o644,
                    tar::EntryType::Regular
                ),
                t.path()
            )
            .is_err()
        );
        let t2 = TempDir::new().unwrap();
        fs::write(t2.path().join("existing.txt"), "data").unwrap();
        let _ = untar_linux(
            &tar_entry(".wh.existing.txt", b"", 0o644, tar::EntryType::Regular),
            t2.path(),
        );
        for name in [".wh.", ".wh..", ".wh...", r".wh.foo\bar"] {
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            if h.set_path(name).is_err() {
                continue;
            }
            h.set_size(0);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append(&h, &[][..]).unwrap();
            assert!(
                untar_linux(&b.into_inner().unwrap(), &TempDir::new().unwrap().path()).is_err(),
                "should reject {name:?}"
            );
        }
    }

    // ── Windows extraction tests ──

    #[test]
    fn windows_extract_basic() {
        let t = TempDir::new().unwrap();
        untar_windows(
            &tar_entry("Files/hello.txt", b"hi", 0o644, tar::EntryType::Regular),
            t.path(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(t.path().join("Files/hello.txt")).unwrap(),
            "hi"
        );
    }

    #[test]
    fn windows_extract_skips_utility_vm() {
        let t = TempDir::new().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        // Normal file
        let mut h = tar::Header::new_gnu();
        h.set_path("Files/app.exe").unwrap();
        h.set_size(3);
        h.set_mode(0o755);
        h.set_cksum();
        b.append(&h, b"MZ\0" as &[u8]).unwrap();
        // UtilityVM entry — should be skipped
        let mut h = tar::Header::new_gnu();
        h.set_path("UtilityVM/Files/kernel").unwrap();
        h.set_size(4);
        h.set_mode(0o644);
        h.set_cksum();
        b.append(&h, b"kern" as &[u8]).unwrap();
        untar_windows(&b.into_inner().unwrap(), t.path()).unwrap();
        assert!(t.path().join("Files/app.exe").exists());
        assert!(!t.path().join("UtilityVM").exists());
    }

    #[test]
    fn windows_extract_skips_ntfs_streams() {
        let t = TempDir::new().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_path("Files/normal.txt").unwrap();
        h.set_size(5);
        h.set_mode(0o644);
        h.set_cksum();
        b.append(&h, b"hello" as &[u8]).unwrap();
        // This has a : in the path — should be skipped (NTFS ADS)
        let raw_name = b"Files/data.txt:Zone.Identifier\0";
        let mut h2 = tar::Header::new_gnu();
        h2.as_gnu_mut().unwrap().name[..raw_name.len() - 1]
            .copy_from_slice(&raw_name[..raw_name.len() - 1]);
        h2.as_gnu_mut().unwrap().name[raw_name.len() - 1] = 0;
        h2.set_size(2);
        h2.set_mode(0o644);
        h2.set_cksum();
        b.append(&h2, b"ZI" as &[u8]).unwrap();
        untar_windows(&b.into_inner().unwrap(), t.path()).unwrap();
        assert!(t.path().join("Files/normal.txt").exists());
        assert!(!t.path().join("Files/data.txt:Zone.Identifier").exists());
    }

    #[test]
    fn windows_extract_rejects_unsafe_paths() {
        for p in [b"/etc/shadow" as &[u8], b"../../etc/passwd"] {
            assert!(untar_windows(&tar_raw_path(p), &TempDir::new().unwrap().path()).is_err());
        }
    }

    #[test]
    fn windows_extract_creates_directories() {
        let t = TempDir::new().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        // Directory entry
        let mut dh = tar::Header::new_gnu();
        dh.set_path("Files/").unwrap();
        dh.set_size(0);
        dh.set_mode(0o000); // NTFS ACL-derived mode
        dh.set_entry_type(tar::EntryType::Directory);
        dh.set_cksum();
        b.append(&dh, &[][..]).unwrap();
        // File inside the directory
        let mut fh = tar::Header::new_gnu();
        fh.set_path("Files/License.txt").unwrap();
        fh.set_size(7);
        fh.set_mode(0o644);
        fh.set_cksum();
        b.append(&fh, b"license" as &[u8]).unwrap();
        untar_windows(&b.into_inner().unwrap(), t.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(t.path().join("Files/License.txt")).unwrap(),
            "license"
        );
    }

    #[cfg(unix)]
    #[test]
    fn windows_extract_fixes_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempDir::new().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut dh = tar::Header::new_gnu();
        dh.set_path("Files/").unwrap();
        dh.set_size(0);
        dh.set_mode(0o000);
        dh.set_entry_type(tar::EntryType::Directory);
        dh.set_cksum();
        b.append(&dh, &[][..]).unwrap();
        let mut fh = tar::Header::new_gnu();
        fh.set_path("Files/License.txt").unwrap();
        fh.set_size(7);
        fh.set_mode(0o644);
        fh.set_cksum();
        b.append(&fh, b"license" as &[u8]).unwrap();
        untar_windows(&b.into_inner().unwrap(), t.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(t.path().join("Files/License.txt")).unwrap(),
            "license"
        );
        let mode = fs::metadata(t.path().join("Files"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "directory should be fixed to 755");
    }
}
