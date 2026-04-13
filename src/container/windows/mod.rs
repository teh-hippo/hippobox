use crate::registry::create_symlink;
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

    let _guard = CleanupGuard(container_dir.clone());

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

    let merged_str = merged.to_string_lossy();
    let resolved = resolve_win_path(&argv[0], &merged_str);
    eprintln!("  cmd: {:?}", argv);

    let mut cmd = std::process::Command::new(&resolved);
    cmd.args(&argv[1..]);

    for kv in &env_vars {
        if let Some((k, v)) = kv.split_once('=') {
            cmd.env(k, v);
        }
    }

    let sep = if cfg!(windows) { ';' } else { ':' };
    let mut path_parts: Vec<String> = env_vars
        .iter()
        .find_map(|v| v.strip_prefix("PATH=").or_else(|| v.strip_prefix("Path=")))
        .into_iter()
        .flat_map(|p| p.split(sep).filter(|s| !s.is_empty()))
        .map(|p| resolve_win_path(p, &merged_str))
        .collect();
    if let Ok(existing) = std::env::var("PATH") {
        if !existing.is_empty() {
            path_parts.push(existing);
        }
    }
    if !path_parts.is_empty() {
        cmd.env("PATH", path_parts.join(&sep.to_string()));
    }

    let status = cmd.status().context("failed to launch Windows process")?;
    Ok(status.code().unwrap_or(1))
}

/// Resolve a Windows path from an image config into the merged rootfs.
///
/// Strips drive letters (`C:\`) and leading separators, then maps multi-segment
/// paths into `<merged>/Files/…`. Bare command names are returned as-is.
fn resolve_win_path(path: &str, merged: &str) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    let n = path
        .replace('/', &sep.to_string())
        .replace('\\', &sep.to_string());

    // Strip drive letter prefix (e.g. "C:" or "c:")
    let stripped =
        if n.len() >= 2 && n.as_bytes()[0].is_ascii_alphabetic() && n.as_bytes()[1] == b':' {
            &n[2..]
        } else {
            &n
        };
    let stripped = stripped.strip_prefix(sep).unwrap_or(stripped);

    if stripped.contains(sep) {
        format!("{merged}{sep}Files{sep}{stripped}")
    } else {
        n
    }
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((s, d)) = stack.pop() {
        for entry in std::fs::read_dir(&s).with_context(|| format!("read dir: {}", s.display()))? {
            let entry = entry?;
            let (sp, dp) = (entry.path(), d.join(entry.file_name()));
            let ft = entry.file_type()?;
            if ft.is_dir() {
                let _ = std::fs::create_dir(&dp);
                stack.push((sp, dp));
            } else if ft.is_symlink() {
                let tgt = std::fs::read_link(&sp)?;
                let _ = std::fs::remove_file(&dp);
                create_symlink(&tgt, &dp)?;
            } else {
                let _ = std::fs::remove_file(&dp);
                if std::fs::hard_link(&sp, &dp).is_err() {
                    std::fs::copy(&sp, &dp).with_context(|| format!("copy {}", sp.display()))?;
                }
            }
        }
    }
    Ok(())
}

struct CleanupGuard(PathBuf);

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_dir_recursive_basic_and_links() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (src, dst) = (tmp.path().join("src"), tmp.path().join("dst"));
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "hello").unwrap();
        std::fs::write(src.join("sub/b.txt"), "world").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a.txt", src.join("link.txt")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        copy_dir_recursive(&src, &dst).unwrap();
        assert_eq!(std::fs::read_to_string(dst.join("a.txt")).unwrap(), "hello");
        assert_eq!(
            std::fs::read_to_string(dst.join("sub/b.txt")).unwrap(),
            "world"
        );
        #[cfg(unix)]
        {
            assert!(dst.join("link.txt").is_symlink());
            assert_eq!(
                std::fs::read_link(dst.join("link.txt"))
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "a.txt"
            );
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                std::fs::metadata(src.join("a.txt")).unwrap().ino(),
                std::fs::metadata(dst.join("a.txt")).unwrap().ino(),
            );
        }
    }

    #[test]
    fn layer_merge_ordering_and_overwrite() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (l1, l2, m) = (
            tmp.path().join("layer1"),
            tmp.path().join("layer2"),
            tmp.path().join("merged"),
        );
        for d in [&l1, &l2, &m] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(l1.join("shared.txt"), "from-layer1").unwrap();
        std::fs::write(l1.join("only-in-1.txt"), "layer1-only").unwrap();
        std::fs::write(l2.join("shared.txt"), "from-layer2").unwrap();
        std::fs::write(l2.join("only-in-2.txt"), "layer2-only").unwrap();
        copy_dir_recursive(&l1, &m).unwrap();
        copy_dir_recursive(&l2, &m).unwrap();
        assert_eq!(
            std::fs::read_to_string(m.join("shared.txt")).unwrap(),
            "from-layer2"
        );
        assert_eq!(
            std::fs::read_to_string(m.join("only-in-1.txt")).unwrap(),
            "layer1-only"
        );
        assert_eq!(
            std::fs::read_to_string(m.join("only-in-2.txt")).unwrap(),
            "layer2-only"
        );
    }

    #[test]
    fn cleanup_guard_removes_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("container-test");
        std::fs::create_dir_all(dir.join("merged")).unwrap();
        {
            let _guard = CleanupGuard(dir.clone());
            assert!(dir.exists());
        }
        assert!(!dir.exists());
    }

    #[test]
    fn resolve_win_path_cases() {
        let sep = std::path::MAIN_SEPARATOR;
        let m = format!("C:{sep}Users{sep}test{sep}hippobox{sep}containers{sep}abc{sep}merged");
        let files = |rest: &str| format!("{m}{sep}Files{sep}{rest}");
        let ws = format!("windows{sep}system32{sep}cmd.exe");
        let ws2 = format!("Windows{sep}System32{sep}cmd.exe");
        let pf = format!("Program Files{sep}PowerShell{sep}7{sep}pwsh.exe");
        assert_eq!(
            resolve_win_path(r"c:\windows\system32\cmd.exe", &m),
            files(&ws)
        );
        assert_eq!(
            resolve_win_path("c:/windows/system32/cmd.exe", &m),
            files(&ws)
        );
        assert_eq!(
            resolve_win_path(r"C:\Program Files\PowerShell\7\pwsh.exe", &m),
            files(&pf)
        );
        assert_eq!(
            resolve_win_path(r"\Windows\System32\cmd.exe", &m),
            files(&ws2)
        );
        assert_eq!(
            resolve_win_path(r"Windows\System32\cmd.exe", &m),
            files(&ws2)
        );
        assert_eq!(resolve_win_path("pwsh.exe", &m), "pwsh.exe");
        assert_eq!(resolve_win_path("cmd.exe", &m), "cmd.exe");
    }
}
