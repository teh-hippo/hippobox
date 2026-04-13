#[cfg(unix)]
mod linux;
#[cfg(unix)]
pub use linux::extract_linux_layer;

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

/// Extract a Windows OCI layer, skipping UtilityVM subtrees and NTFS ADS entries.
/// Manually creates dirs/files because `unpack_in` fails on NTFS ACL-derived 000 modes.
pub fn extract_windows_layer(archive: &mut tar::Archive<impl Read>, target: &Path) -> Result<()> {
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.into_owned();

        let normalised = if raw_path.to_string_lossy().contains('\\') {
            PathBuf::from(raw_path.to_string_lossy().replace('\\', "/"))
        } else {
            raw_path
        };

        if has_unsafe_components(&normalised) {
            bail!("unsafe archive path component in {}", normalised.display());
        }

        if normalised.to_string_lossy().contains(':')
            || normalised.components().next().is_some_and(
                |c| matches!(c, Component::Normal(s) if s.eq_ignore_ascii_case("UtilityVM")),
            )
        {
            continue;
        }

        let dest = target.join(&normalised);
        {
            let mut check = target.to_path_buf();
            for component in normalised.components() {
                if let Component::Normal(part) = component {
                    check.push(part);
                    if fs::symlink_metadata(&check).is_ok_and(|m| m.file_type().is_symlink()) {
                        bail!(
                            "refusing to traverse symlink while extracting: {}",
                            check.display()
                        );
                    }
                }
            }
        }

        let etype = entry.header().entry_type();
        if etype.is_dir() {
            fs::create_dir_all(&dest)?;
            fix_permissions(&dest, None)?;
        } else if etype.is_symlink() {
            if let Some(link_target) = entry.link_name()? {
                let link_path = PathBuf::from(link_target.to_string_lossy().replace('\\', "/"));
                let _ = fs::remove_file(&dest);
                ensure_parent(&dest)?;
                if let Err(e) = create_symlink(&link_path, &dest) {
                    if cfg!(windows) {
                        eprintln!(
                            "  warning: skipping symlink {} -> {} (insufficient privileges)",
                            dest.display(),
                            link_path.display()
                        );
                    } else {
                        return Err(e);
                    }
                }
            }
        } else if etype.is_file() || etype == tar::EntryType::Continuous {
            ensure_parent(&dest)?;
            let _ = fs::remove_file(&dest);
            let mut out = fs::File::create(&dest)
                .with_context(|| format!("failed to create {}", dest.display()))?;
            io::copy(&mut entry, &mut out)
                .with_context(|| format!("failed to write {}", dest.display()))?;
            fix_permissions(&dest, Some(&normalised))?;
        }
    }
    Ok(())
}

fn ensure_parent(dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
        fix_permissions(parent, None)?;
    }
    Ok(())
}

#[cfg(unix)]
fn fix_permissions(path: &Path, normalised: Option<&Path>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = match normalised {
        None => 0o755,
        Some(p) => {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(
                ext.to_ascii_lowercase().as_str(),
                "exe" | "dll" | "cmd" | "bat" | "ps1" | "com"
            ) {
                0o755
            } else {
                0o644
            }
        }
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn fix_permissions(_path: &Path, _normalised: Option<&Path>) -> Result<()> {
    Ok(())
}

pub(crate) fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link)?;
    #[cfg(windows)]
    if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, link)?;
    } else {
        std::os::windows::fs::symlink_file(target, link)?;
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

    fn untar_windows(data: &[u8], dir: &Path) -> Result<()> {
        extract_windows_layer(&mut tar::Archive::new(std::io::Cursor::new(data)), dir)
    }

    fn tar_dir_and_file(dir_path: &str, file_path: &str, content: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut dh = tar::Header::new_gnu();
        dh.set_path(dir_path).unwrap();
        dh.set_size(0);
        dh.set_mode(0o000);
        dh.set_entry_type(tar::EntryType::Directory);
        dh.set_cksum();
        b.append(&dh, &[][..]).unwrap();
        let mut fh = tar::Header::new_gnu();
        fh.set_path(file_path).unwrap();
        fh.set_size(content.len() as u64);
        fh.set_mode(0o644);
        fh.set_cksum();
        b.append(&fh, content).unwrap();
        b.into_inner().unwrap()
    }

    #[test]
    fn windows_extract_files_and_safety() {
        // Basic file extraction
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

        // Directory creation with permission fix
        let t2 = TempDir::new().unwrap();
        untar_windows(
            &tar_dir_and_file("Files/", "Files/License.txt", b"license"),
            t2.path(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(t2.path().join("Files/License.txt")).unwrap(),
            "license"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(t2.path().join("Files"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o755, "directory should be fixed to 755");
        }

        // Unsafe paths are rejected
        for p in [b"/etc/shadow" as &[u8], b"../../etc/passwd"] {
            assert!(untar_windows(&tar_raw_path(p), &TempDir::new().unwrap().path()).is_err());
        }
    }

    #[test]
    fn windows_extract_skips_filtered_entries() {
        let t = TempDir::new().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        for (path, content) in [
            ("Files/app.exe", b"MZ\0" as &[u8]),
            ("UtilityVM/Files/kernel", b"kern"),
            ("Files/normal.txt", b"hello"),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_path(path).unwrap();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append(&h, content).unwrap();
        }
        let raw = b"Files/data.txt:Zone.Identifier";
        let mut h2 = tar::Header::new_gnu();
        h2.as_gnu_mut().unwrap().name[..raw.len()].copy_from_slice(raw);
        h2.as_gnu_mut().unwrap().name[raw.len()] = 0;
        h2.set_size(2);
        h2.set_mode(0o644);
        h2.set_cksum();
        b.append(&h2, b"ZI" as &[u8]).unwrap();
        untar_windows(&b.into_inner().unwrap(), t.path()).unwrap();
        assert!(t.path().join("Files/app.exe").exists());
        assert!(t.path().join("Files/normal.txt").exists());
        assert!(!t.path().join("UtilityVM").exists());
    }
}
