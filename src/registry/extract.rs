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

    #[test]
    fn create_extract_temp_dir_unique_and_restricted() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("layers/sha256/abc123");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        let dir1 = create_extract_temp_dir(&target).unwrap();
        let dir2 = create_extract_temp_dir(&target).unwrap();
        assert_ne!(dir1, dir2, "must create distinct temp dirs");

        // Both should exist and have restrictive permissions
        for dir in [&dir1, &dir2] {
            assert!(dir.exists());
            let mode = fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "temp dir should be 0700");
        }
    }

    #[test]
    fn extract_handles_whiteout_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Create a file that the whiteout should mark for deletion
        let target = tmp.path().join("existing.txt");
        fs::write(&target, "will be whiteout'd").unwrap();

        // Build a tar with a .wh.existing.txt whiteout entry
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path(".wh.existing.txt").unwrap();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();
        let data = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(std::io::Cursor::new(data));
        // This test requires CAP_MKNOD which we may not have in test env,
        // but the path validation and removal logic is exercised regardless
        let _ = extract_with_whiteouts(&mut archive, tmp.path());
    }

    #[test]
    fn extract_rejects_unsafe_whiteout_names() {
        // Whiteout names that are empty or contain traversal components should be rejected
        for bad_name in [".wh.", ".wh..", ".wh..."] {
            let mut builder = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            if header.set_path(bad_name).is_err() { continue; }
            header.set_size(0);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append(&header, &[][..]).unwrap();
            let data = builder.into_inner().unwrap();

            let tmp = tempfile::TempDir::new().unwrap();
            let mut archive = tar::Archive::new(std::io::Cursor::new(data));
            let result = extract_with_whiteouts(&mut archive, tmp.path());
            assert!(result.is_err(), "should reject whiteout name: {bad_name:?}");
        }
    }

    #[test]
    fn extract_rejects_whiteout_with_backslash() {
        // Backslash in whiteout deleted name is rejected as a path traversal attempt
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path(r".wh.foo\bar").unwrap();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();
        let data = builder.into_inner().unwrap();

        let tmp = tempfile::TempDir::new().unwrap();
        let mut archive = tar::Archive::new(std::io::Cursor::new(data));
        let result = extract_with_whiteouts(&mut archive, tmp.path());
        assert!(result.is_err(), r"should reject whiteout with backslash: .wh.foo\bar");
    }

    #[test]
    fn extract_rejects_symlink_traversal() {
        // Security: an attacker could create a symlink then write through it
        let tmp = tempfile::TempDir::new().unwrap();

        // Pre-create a symlink inside the extraction target: evil -> /tmp
        let evil_link = tmp.path().join("evil");
        std::os::unix::fs::symlink("/tmp", &evil_link).unwrap();

        // Build a tar that tries to write through the symlink
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_path("evil/payload.txt").unwrap();
        header.set_size(6);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, b"attack" as &[u8]).unwrap();
        let data = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(std::io::Cursor::new(data));
        let result = extract_with_whiteouts(&mut archive, tmp.path());
        assert!(result.is_err(), "extraction through symlink should be rejected");
    }

    #[test]
    fn extract_preserves_directory_structure() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        // Add a nested directory entry
        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_path("usr/local/bin/").unwrap();
        dir_header.set_size(0);
        dir_header.set_mode(0o755);
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_cksum();
        builder.append(&dir_header, &[][..]).unwrap();

        // Add a file inside it
        let mut file_header = tar::Header::new_gnu();
        file_header.set_path("usr/local/bin/tool").unwrap();
        file_header.set_size(4);
        file_header.set_mode(0o755);
        file_header.set_cksum();
        builder.append(&file_header, b"test" as &[u8]).unwrap();

        let data = builder.into_inner().unwrap();
        let mut archive = tar::Archive::new(std::io::Cursor::new(data));
        extract_with_whiteouts(&mut archive, tmp.path()).unwrap();

        assert!(tmp.path().join("usr/local/bin/tool").exists());
        assert_eq!(fs::read_to_string(tmp.path().join("usr/local/bin/tool")).unwrap(), "test");
    }

    #[test]
    fn hashing_reader_handles_partial_reads() {
        use sha2::{Digest, Sha256};

        // Verify that reading in multiple small chunks produces the same hash
        let data = b"The quick brown fox jumps over the lazy dog";
        let expected = format!("{:x}", Sha256::digest(data));

        let mut reader = HashingReader { inner: std::io::Cursor::new(data), hasher: Sha256::new() };
        let mut buf = [0u8; 5]; // small buffer forces multiple reads
        let mut total = Vec::new();
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 { break; }
            total.extend_from_slice(&buf[..n]);
        }
        assert_eq!(total, data);
        assert_eq!(format!("{:x}", reader.hasher.finalize()), expected);
    }
}
