use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
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

pub(super) fn extract_with_whiteouts(archive: &mut tar::Archive<impl Read>, target: &Path) -> Result<()> {
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(false);

    // Resolve a relative path under target, ensuring no symlink traversal.
    let safe_dir = |relative: &Path| -> Result<PathBuf> {
        if has_unsafe_components(relative) {
            bail!("unsafe archive path component in {}", relative.display());
        }
        let mut out = target.to_path_buf();
        for component in relative.components() {
            if let Component::Normal(part) = component {
                out.push(part);
                match fs::symlink_metadata(&out) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        bail!(
                            "refusing to traverse symlink while extracting: {}",
                            out.display()
                        );
                    }
                    Err(err) if err.kind() != io::ErrorKind::NotFound => {
                        return Err(err.into());
                    }
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

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if file_name == ".wh..wh..opq" {
            let parent = safe_dir(path.parent().unwrap_or(Path::new("")))?;
            let c_path = CString::new(parent.to_string_lossy().as_bytes())?;
            let c_name = CString::new("trusted.overlay.opaque")?;
            let ret = unsafe {
                nix::libc::setxattr(
                    c_path.as_ptr(),
                    c_name.as_ptr(),
                    b"y".as_ptr() as *const nix::libc::c_void,
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
                || Path::new(deleted_name).components().count() != 1
                || deleted_name == "."
                || deleted_name == ".."
                || deleted_name.contains('/')
                || deleted_name.contains('\\')
            {
                bail!("unsafe whiteout name: {deleted_name}");
            }
            let parent = safe_dir(path.parent().unwrap_or(Path::new("")))?;
            let whiteout_path = parent.join(deleted_name);
            if let Ok(metadata) = fs::symlink_metadata(&whiteout_path) {
                if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
                    fs::remove_dir_all(&whiteout_path)?;
                } else {
                    fs::remove_file(&whiteout_path)?;
                }
            }

            nix::sys::stat::mknod(
                &whiteout_path,
                nix::sys::stat::SFlag::S_IFCHR,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                nix::sys::stat::makedev(0, 0),
            )
            .with_context(|| format!("failed to create whiteout at {}", whiteout_path.display()))?;
            continue;
        }

        if !entry.unpack_in(target)? {
            bail!("archive entry escapes target directory: {}", path.display());
        }
    }
    Ok(())
}

pub(super) fn create_extract_temp_dir(target_dir: &Path) -> Result<PathBuf> {
    let pid = std::process::id();

    for nonce in 0..64 {
        let tmp_dir = target_dir.with_extension(format!("tmp-{pid}-{nonce}"));
        match fs::create_dir(&tmp_dir) {
            Ok(()) => {
                fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o700))?;
                return Ok(tmp_dir);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }

    bail!(
        "failed to create a unique extraction temp dir for {}",
        target_dir.display()
    );
}

pub(super) struct HashingReader<R: Read> {
    pub inner: R,
    pub hasher: Sha256,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_relative_path() {
        assert!(!has_unsafe_components(Path::new("usr/bin/bash")));
        assert!(!has_unsafe_components(Path::new("a/b/c")));
    }

    #[test]
    fn absolute_path_is_unsafe() {
        assert!(has_unsafe_components(Path::new("/etc/passwd")));
        assert!(has_unsafe_components(Path::new("/usr/bin")));
    }

    #[test]
    fn parent_dir_is_unsafe() {
        assert!(has_unsafe_components(Path::new("foo/../etc")));
        assert!(has_unsafe_components(Path::new("../escape")));
        assert!(has_unsafe_components(Path::new("..")));
    }

    #[test]
    fn current_dir_is_safe() {
        assert!(!has_unsafe_components(Path::new("./foo/bar")));
    }

    #[test]
    fn empty_path_is_safe() {
        assert!(!has_unsafe_components(Path::new("")));
    }

    #[test]
    fn hashing_reader_correct_sha256() {
        use sha2::{Digest, Sha256};
        use std::io::{Cursor, Read};

        let data = b"hello world";
        let expected = format!("{:x}", Sha256::digest(data));

        let mut reader = HashingReader {
            inner: Cursor::new(data),
            hasher: Sha256::new(),
        };
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();

        let computed = format!("{:x}", reader.hasher.finalize());
        assert_eq!(computed, expected);
        assert_eq!(buf, data);
    }

    #[test]
    fn hashing_reader_empty() {
        use sha2::{Digest, Sha256};
        use std::io::{Cursor, Read};

        let expected = format!("{:x}", Sha256::digest(b""));

        let mut reader = HashingReader {
            inner: Cursor::new(b""),
            hasher: Sha256::new(),
        };
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();

        let computed = format!("{:x}", reader.hasher.finalize());
        assert_eq!(computed, expected);
        assert_eq!(buf.len(), 0);
    }
}
