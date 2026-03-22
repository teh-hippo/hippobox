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

    let safe_dir = |relative: &Path| -> Result<PathBuf> {
        if has_unsafe_components(relative) { bail!("unsafe archive path component in {}", relative.display()); }
        let mut out = target.to_path_buf();
        for component in relative.components() {
            if let Component::Normal(part) = component {
                out.push(part);
                match fs::symlink_metadata(&out) {
                    Ok(m) if m.file_type().is_symlink() =>
                        bail!("refusing to traverse symlink while extracting: {}", out.display()),
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
        if has_unsafe_components(&path) { bail!("unsafe archive path component in {}", path.display()); }
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if file_name == ".wh..wh..opq" {
            let parent = safe_dir(path.parent().unwrap_or(Path::new("")))?;
            let c_path = CString::new(parent.to_string_lossy().as_bytes())?;
            let ret = unsafe { nix::libc::setxattr(
                c_path.as_ptr(), c"trusted.overlay.opaque".as_ptr(), b"y".as_ptr().cast(), 1, 0,
            )};
            if ret != 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("failed to set opaque xattr on {}", parent.display()));
            }
            continue;
        }

        if let Some(deleted_name) = file_name.strip_prefix(".wh.") {
            if deleted_name.is_empty() || deleted_name == "." || deleted_name == ".."
                || deleted_name.contains('/') || deleted_name.contains('\\')
                || Path::new(deleted_name).components().count() != 1
            { bail!("unsafe whiteout name: {deleted_name}"); }
            let parent = safe_dir(path.parent().unwrap_or(Path::new("")))?;
            let wp = parent.join(deleted_name);
            if let Ok(m) = fs::symlink_metadata(&wp) {
                if m.file_type().is_dir() && !m.file_type().is_symlink() { fs::remove_dir_all(&wp)?; }
                else { fs::remove_file(&wp)?; }
            }
            nix::sys::stat::mknod(&wp, nix::sys::stat::SFlag::S_IFCHR,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                nix::sys::stat::makedev(0, 0))
                .with_context(|| format!("failed to create whiteout at {}", wp.display()))?;
            continue;
        }

        if !entry.unpack_in(target)? { bail!("archive entry escapes target directory: {}", path.display()); }
    }
    Ok(())
}

pub(super) fn create_extract_temp_dir(target_dir: &Path) -> Result<PathBuf> {
    let pid = std::process::id();
    for nonce in 0..64 {
        let tmp = target_dir.with_extension(format!("tmp-{pid}-{nonce}"));
        match fs::create_dir(&tmp) {
            Ok(()) => { fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700))?; return Ok(tmp); }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("failed to create a unique extraction temp dir for {}", target_dir.display())
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
    fn has_unsafe_components_checks() {
        assert!(!has_unsafe_components(Path::new("usr/bin/bash")));
        assert!(!has_unsafe_components(Path::new("./foo/bar")));
        assert!(!has_unsafe_components(Path::new("")));
        assert!(has_unsafe_components(Path::new("/etc/passwd")));
        assert!(has_unsafe_components(Path::new("foo/../etc")));
        assert!(has_unsafe_components(Path::new("..")));
    }

    #[test]
    fn hashing_reader_computes_sha256() {
        use sha2::{Digest, Sha256};
        use std::io::{Cursor, Read};

        for data in [b"hello world" as &[u8], b""] {
            let expected = format!("{:x}", Sha256::digest(data));
            let mut reader = HashingReader { inner: Cursor::new(data), hasher: Sha256::new() };
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).unwrap();
            assert_eq!(format!("{:x}", reader.hasher.finalize()), expected);
        }
    }

    #[test]
    fn extract_basic_tar() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("hello.txt").unwrap();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, b"hello" as &[u8]).unwrap();
        let data = builder.into_inner().unwrap();
        let mut archive = tar::Archive::new(std::io::Cursor::new(data));
        extract_with_whiteouts(&mut archive, tmp.path()).unwrap();
        assert_eq!(std::fs::read_to_string(tmp.path().join("hello.txt")).unwrap(), "hello");
    }

    fn make_tar_with_path(path_bytes: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.as_gnu_mut().unwrap().name[..path_bytes.len()].copy_from_slice(path_bytes);
        header.as_gnu_mut().unwrap().name[path_bytes.len()] = 0;
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, b"evil" as &[u8]).unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn extract_rejects_unsafe_paths() {
        for path in [b"/etc/shadow" as &[u8], b"../../etc/passwd"] {
            let tmp = tempfile::TempDir::new().unwrap();
            let data = make_tar_with_path(path);
            let mut archive = tar::Archive::new(std::io::Cursor::new(data));
            assert!(extract_with_whiteouts(&mut archive, tmp.path()).is_err());
        }
    }
}
