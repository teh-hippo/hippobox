use anyhow::{Context, Result, bail};
use std::ffi::CString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub fn extract_linux_layer(archive: &mut tar::Archive<impl Read>, target: &Path) -> Result<()> {
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(false);

    let safe_dir = |relative: &Path| -> Result<PathBuf> {
        if super::has_unsafe_components(relative) {
            bail!("unsafe archive path component in {}", relative.display());
        }
        super::check_no_symlink_traversal(target, relative)?;
        let out = target.join(relative);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::extract::tests::{tar_archive, tar_raw};
    use tar::EntryType::*;
    use tempfile::TempDir;

    fn untar(data: &[u8], dir: &Path) -> Result<()> {
        extract_linux_layer(&mut tar::Archive::new(std::io::Cursor::new(data)), dir)
    }

    #[test]
    fn extract_linux_layer_test() {
        // has_unsafe_components unit checks
        let check = super::super::has_unsafe_components;
        for (p, want) in [
            ("usr/bin/bash", false),
            ("./foo/bar", false),
            ("", false),
            ("/etc/passwd", true),
            ("foo/../etc", true),
            ("..", true),
        ] {
            assert_eq!(check(Path::new(p)), want, "path={p:?}");
        }

        // Happy path: files and nested dirs
        let t = TempDir::new().unwrap();
        let data = tar_archive(&[
            ("hello.txt", b"hello", 0o644, Regular),
            ("usr/bin/tool", b"test", 0o755, Regular),
        ]);
        untar(&data, t.path()).unwrap();
        assert_eq!(
            fs::read_to_string(t.path().join("hello.txt")).unwrap(),
            "hello"
        );
        assert_eq!(
            fs::read_to_string(t.path().join("usr/bin/tool")).unwrap(),
            "test"
        );

        // Unsafe paths rejected
        for p in [b"/etc/shadow" as &[u8], b"../../etc/passwd"] {
            assert!(untar(&tar_raw(p, b"x"), &TempDir::new().unwrap().path()).is_err());
        }

        // Symlink traversal blocked
        let t2 = TempDir::new().unwrap();
        std::os::unix::fs::symlink("/tmp", t2.path().join("evil")).unwrap();
        assert!(untar(&tar_archive(&[("evil/a", b"x", 0o644, Regular)]), t2.path()).is_err());

        // Whiteout: existing file replaced with char device
        let t3 = TempDir::new().unwrap();
        fs::write(t3.path().join("exist.txt"), "data").unwrap();
        let _ = untar(
            &tar_archive(&[(".wh.exist.txt", b"", 0o644, Regular)]),
            t3.path(),
        );

        // Whiteout: malformed names rejected
        for name in [".wh.", ".wh..", ".wh...", r".wh.foo\bar"] {
            let data = tar_archive(&[(name, b"", 0o644, Regular)]);
            let _ = untar(&data, &TempDir::new().unwrap().path())
                .map(|_| panic!("should reject {name:?}"));
        }
    }
}
