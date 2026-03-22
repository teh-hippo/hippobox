use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

pub(super) fn has_unsafe_components(path: &Path) -> bool {
    path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
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
        if n > 0 { self.hasher.update(&buf[..n]); }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tar_entry(path: &str, content: &[u8], mode: u32, etype: tar::EntryType) -> Vec<u8> {
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

    fn make_tar_with_path(path_bytes: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.as_gnu_mut().unwrap().name[..path_bytes.len()].copy_from_slice(path_bytes);
        h.as_gnu_mut().unwrap().name[path_bytes.len()] = 0;
        h.set_size(4); h.set_mode(0o644); h.set_cksum();
        b.append(&h, b"evil" as &[u8]).unwrap();
        b.into_inner().unwrap()
    }

    fn extract_tar(data: &[u8], dir: &Path) -> Result<()> {
        extract_with_whiteouts(&mut tar::Archive::new(std::io::Cursor::new(data)), dir)
    }

    #[test]
    fn has_unsafe_components_checks() {
        for (path, expect) in [("usr/bin/bash", false), ("./foo/bar", false), ("", false),
            ("/etc/passwd", true), ("foo/../etc", true), ("..", true)] {
            assert_eq!(has_unsafe_components(Path::new(path)), expect, "path={path:?}");
        }
    }

    #[test]
    fn hashing_reader_correctness() {
        use sha2::{Digest, Sha256};
        // Full read and chunked read both produce correct hash
        for data in [b"hello world" as &[u8], b"", b"The quick brown fox jumps over the lazy dog"] {
            let expected = format!("{:x}", Sha256::digest(data));
            let mut r = HashingReader { inner: std::io::Cursor::new(data), hasher: Sha256::new() };
            let mut buf = [0u8; 5];
            let mut total = Vec::new();
            loop { let n = r.read(&mut buf).unwrap(); if n == 0 { break; } total.extend_from_slice(&buf[..n]); }
            assert_eq!(total, data);
            assert_eq!(format!("{:x}", r.hasher.finalize()), expected);
        }
    }

    #[test]
    fn extract_basic_tar_and_directory_structure() {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = make_tar_entry("hello.txt", b"hello", 0o644, tar::EntryType::Regular);
        extract_tar(&data, tmp.path()).unwrap();
        assert_eq!(std::fs::read_to_string(tmp.path().join("hello.txt")).unwrap(), "hello");

        let tmp2 = tempfile::TempDir::new().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut dh = tar::Header::new_gnu();
        dh.set_path("usr/local/bin/").unwrap(); dh.set_size(0); dh.set_mode(0o755);
        dh.set_entry_type(tar::EntryType::Directory); dh.set_cksum();
        b.append(&dh, &[][..]).unwrap();
        let mut fh = tar::Header::new_gnu();
        fh.set_path("usr/local/bin/tool").unwrap(); fh.set_size(4); fh.set_mode(0o755); fh.set_cksum();
        b.append(&fh, b"test" as &[u8]).unwrap();
        extract_tar(&b.into_inner().unwrap(), tmp2.path()).unwrap();
        assert_eq!(fs::read_to_string(tmp2.path().join("usr/local/bin/tool")).unwrap(), "test");
    }

    #[test]
    fn extract_rejects_unsafe_paths() {
        for path in [b"/etc/shadow" as &[u8], b"../../etc/passwd"] {
            let tmp = tempfile::TempDir::new().unwrap();
            assert!(extract_tar(&make_tar_with_path(path), tmp.path()).is_err());
        }
    }

    #[test]
    fn extract_rejects_symlink_traversal() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::os::unix::fs::symlink("/tmp", tmp.path().join("evil")).unwrap();
        let data = make_tar_entry("evil/payload.txt", b"attack", 0o644, tar::EntryType::Regular);
        assert!(extract_tar(&data, tmp.path()).is_err());
    }

    #[test]
    fn extract_whiteout_handling() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("existing.txt"), "data").unwrap();
        let data = make_tar_entry(".wh.existing.txt", b"", 0o644, tar::EntryType::Regular);
        let _ = extract_tar(&data, tmp.path()); // may need CAP_MKNOD
    }

    #[test]
    fn extract_rejects_unsafe_whiteout_names() {
        for name in [".wh.", ".wh..", ".wh...", r".wh.foo\bar"] {
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            if h.set_path(name).is_err() { continue; }
            h.set_size(0); h.set_mode(0o644); h.set_entry_type(tar::EntryType::Regular); h.set_cksum();
            b.append(&h, &[][..]).unwrap();
            let tmp = tempfile::TempDir::new().unwrap();
            assert!(extract_tar(&b.into_inner().unwrap(), tmp.path()).is_err(), "should reject {name:?}");
        }
    }

    #[test]
    fn create_extract_temp_dir_unique_and_restricted() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("layers/sha256/abc123");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let d1 = create_extract_temp_dir(&target).unwrap();
        let d2 = create_extract_temp_dir(&target).unwrap();
        assert_ne!(d1, d2);
        for d in [&d1, &d2] {
            assert_eq!(fs::metadata(d).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }
}
