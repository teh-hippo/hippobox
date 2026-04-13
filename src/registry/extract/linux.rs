use anyhow::{Result, bail};
use std::ffi::CString;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

/// Extract a Linux OCI layer, handling `.wh.` whiteout files and opaque dirs.
pub fn extract_linux_layer(archive: &mut tar::Archive<impl Read>, target: &Path) -> Result<()> {
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(false);

    let safe_dir = |relative: &Path| -> Result<PathBuf> {
        if super::has_unsafe_components(relative) {
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
        if super::has_unsafe_components(&path) {
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
            if ["", ".", ".."].contains(&deleted_name)
                || deleted_name.contains(['/', '\\'])
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

use anyhow::Context;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn untar_linux(data: &[u8], dir: &Path) -> Result<()> {
        extract_linux_layer(&mut tar::Archive::new(std::io::Cursor::new(data)), dir)
    }

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
            assert_eq!(
                super::super::has_unsafe_components(Path::new(p)),
                expect,
                "path={p:?}"
            );
        }
    }

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
        let data = {
            let mut b = tar::Builder::new(Vec::new());
            for (path, mode, etype, content) in [
                (
                    "usr/local/bin/",
                    0o755u32,
                    tar::EntryType::Directory,
                    &[][..],
                ),
                (
                    "usr/local/bin/tool",
                    0o755,
                    tar::EntryType::Regular,
                    b"test" as &[u8],
                ),
            ] {
                let mut h = tar::Header::new_gnu();
                h.set_path(path).unwrap();
                h.set_size(content.len() as u64);
                h.set_mode(mode);
                h.set_entry_type(etype);
                h.set_cksum();
                b.append(&h, content).unwrap();
            }
            b.into_inner().unwrap()
        };
        untar_linux(&data, t2.path()).unwrap();
        assert_eq!(
            fs::read_to_string(t2.path().join("usr/local/bin/tool")).unwrap(),
            "test"
        );
    }

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
}
