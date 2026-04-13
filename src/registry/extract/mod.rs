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

pub(super) fn check_no_symlink_traversal(target: &Path, relative: &Path) -> Result<()> {
    let mut check = target.to_path_buf();
    for component in relative.components() {
        if let Component::Normal(part) = component {
            check.push(part);
            if fs::symlink_metadata(&check).is_ok_and(|m| m.file_type().is_symlink()) {
                bail!("symlink traversal in extraction: {}", check.display());
            }
        }
    }
    Ok(())
}

fn should_skip_windows_entry(path: &str) -> bool {
    path.contains(':')
        || path
            .split('/')
            .next()
            .is_some_and(|s| s.eq_ignore_ascii_case("UtilityVM"))
}

/// Extract a Windows OCI layer, skipping UtilityVM and ADS entries.
pub fn extract_windows_layer(archive: &mut tar::Archive<impl Read>, target: &Path) -> Result<()> {
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.into_owned();
        let normalised = PathBuf::from(raw_path.to_string_lossy().replace('\\', "/"));

        if has_unsafe_components(&normalised) {
            bail!("unsafe archive path component in {}", normalised.display());
        }
        if should_skip_windows_entry(&normalised.to_string_lossy()) {
            continue;
        }

        let dest = target.join(&normalised);
        check_no_symlink_traversal(target, &normalised)?;

        // Ensure parent directory exists with correct permissions for all entry types
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p)?;
            fix_permissions(p, None)?;
        }

        let etype = entry.header().entry_type();
        if etype.is_dir() {
            fs::create_dir_all(&dest)?;
            fix_permissions(&dest, None)?;
        } else if etype.is_symlink() {
            if let Some(link_target) = entry.link_name()? {
                let link_path = PathBuf::from(link_target.to_string_lossy().replace('\\', "/"));
                let _ = fs::remove_file(&dest);
                create_symlink(&link_path, &dest)?;
            }
        } else if etype.is_file() || etype == tar::EntryType::Continuous {
            let _ = fs::remove_file(&dest);
            let mut out =
                fs::File::create(&dest).with_context(|| format!("create {}", dest.display()))?;
            io::copy(&mut entry, &mut out).with_context(|| format!("write {}", dest.display()))?;
            fix_permissions(&dest, Some(&normalised))?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn fix_permissions(path: &Path, normalised: Option<&Path>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let executable = ["exe", "dll", "cmd", "bat", "ps1", "com"];
    let is_exec = normalised.is_some_and(|p| {
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        executable.iter().any(|e| ext.eq_ignore_ascii_case(e))
    });
    let mode = if normalised.is_none() || is_exec {
        0o755
    } else {
        0o644
    };
    Ok(fs::set_permissions(path, fs::Permissions::from_mode(mode))?)
}

#[cfg(not(unix))]
fn fix_permissions(_path: &Path, _normalised: Option<&Path>) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) use std::os::unix::fs::symlink as create_symlink;

#[cfg(windows)]
pub(crate) fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, link)?;
    } else {
        std::os::windows::fs::symlink_file(target, link)?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use tempfile::TempDir;

    pub(super) fn tar_archive(entries: &[(&str, &[u8], u32, tar::EntryType)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for &(path, content, mode, etype) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_path(path).unwrap();
            h.set_size(content.len() as u64);
            h.set_mode(mode);
            h.set_entry_type(etype);
            h.set_cksum();
            b.append(&h, content).unwrap();
        }
        b.into_inner().unwrap()
    }

    pub(super) fn tar_raw(path_bytes: &[u8], content: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.as_gnu_mut().unwrap().name[..path_bytes.len()].copy_from_slice(path_bytes);
        h.as_gnu_mut().unwrap().name[path_bytes.len()] = 0;
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append(&h, content).unwrap();
        b.into_inner().unwrap()
    }

    fn untar(data: &[u8], dir: &Path) -> Result<()> {
        extract_windows_layer(&mut tar::Archive::new(std::io::Cursor::new(data)), dir)
    }

    #[test]
    fn extract_windows_layer_test() {
        use tar::EntryType::*;
        let t = TempDir::new().unwrap();
        let d = t.path();

        let mut data = tar_archive(&[
            ("Files/", &[], 0o000, Directory),
            ("Files/a.txt", b"hello", 0o644, Regular),
            ("Files/b.exe", b"MZ", 0o644, Regular),
            ("UtilityVM/Files/k", b"kern", 0o644, Regular),
        ]);
        data.extend_from_slice(&tar_raw(b"Files/x.txt:Zone.Id", b"ZI"));
        untar(&data, d).unwrap();

        assert_eq!(fs::read_to_string(d.join("Files/a.txt")).unwrap(), "hello");
        assert!(d.join("Files/b.exe").exists());
        assert!(!d.join("UtilityVM").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(d.join("Files")).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755);
        }

        for p in [b"/etc/shadow" as &[u8], b"../../etc/passwd"] {
            assert!(untar(&tar_raw(p, b"x"), &TempDir::new().unwrap().path()).is_err());
        }
    }
}
