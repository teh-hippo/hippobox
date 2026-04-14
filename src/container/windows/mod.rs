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
        target,
        ..
    } = spec;
    let cc = config.config.as_ref();
    let argv = super::build_argv(cc, user_cmd)?;
    let env_vars = super::build_env_vars(cc, &user_env, &target)?;

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

    let host_sep = if cfg!(windows) { ';' } else { ':' };
    for kv in &env_vars {
        if let Some((k, v)) = kv.split_once('=') {
            if !k.eq_ignore_ascii_case("PATH") {
                cmd.env(k, v);
            }
        }
    }

    // Resolve image PATH through merged rootfs; image uses ';' separators.
    let mut path_parts: Vec<String> = env_vars
        .iter()
        .find_map(|v| v.strip_prefix("PATH=").or_else(|| v.strip_prefix("Path=")))
        .into_iter()
        .flat_map(|p| p.split(';').filter(|s| !s.is_empty()))
        .map(|p| resolve_win_path(p, &merged_str))
        .collect();
    if let Ok(p) = std::env::var("PATH") {
        path_parts.extend(
            p.split(host_sep)
                .filter(|s| !s.is_empty())
                .map(String::from),
        );
    }
    if !path_parts.is_empty() {
        cmd.env("PATH", path_parts.join(&host_sep.to_string()));
    }

    let status = cmd.status().context("failed to launch Windows process")?;
    Ok(status.code().unwrap_or(1))
}

fn resolve_win_path(path: &str, merged: &str) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    let n = path
        .replace('/', &sep.to_string())
        .replace('\\', &sep.to_string());
    let s = if n.len() >= 2 && n.as_bytes()[0].is_ascii_alphabetic() && n.as_bytes()[1] == b':' {
        &n[2..]
    } else {
        &n
    };
    let s = s.strip_prefix(sep).unwrap_or(s);
    if s.contains(sep) {
        format!("{merged}{sep}Files{sep}{s}")
    } else {
        n
    }
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((s, d)) = stack.pop() {
        for entry in std::fs::read_dir(&s).with_context(|| format!("read {}", s.display()))? {
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

    fn read(p: &std::path::Path) -> String {
        std::fs::read_to_string(p).unwrap()
    }

    #[test]
    fn copy_dir_recursive_and_cleanup() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (src, dst) = (tmp.path().join("src"), tmp.path().join("dst"));
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "hello").unwrap();
        std::fs::write(src.join("sub/b.txt"), "world").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a.txt", src.join("link.txt")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        copy_dir_recursive(&src, &dst).unwrap();
        assert_eq!(read(&dst.join("a.txt")), "hello");
        assert_eq!(read(&dst.join("sub/b.txt")), "world");
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
        }

        // Overwrite: second copy replaces shared file
        std::fs::write(src.join("a.txt"), "new").unwrap();
        copy_dir_recursive(&src, &dst).unwrap();
        assert_eq!(read(&dst.join("a.txt")), "new");

        // CleanupGuard removes directory on drop
        let dir = tmp.path().join("ctest");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        {
            let _guard = CleanupGuard(dir.clone());
            assert!(dir.exists());
        }
        assert!(!dir.exists());
    }

    #[test]
    fn resolve_win_path_cases() {
        let sep = std::path::MAIN_SEPARATOR;
        let m = format!("C:{sep}merged");
        let f = |s: &str| format!("{m}{sep}Files{sep}{}", s.replace('/', &sep.to_string()));

        for (input, expected) in [
            (r"c:\win\sys\cmd.exe", f("win/sys/cmd.exe")),
            (r"C:\Program Files\pwsh.exe", f("Program Files/pwsh.exe")),
            (r"\Win\Sys\cmd.exe", f("Win/Sys/cmd.exe")),
            (r"Win\Sys\cmd.exe", f("Win/Sys/cmd.exe")),
            ("c:/a/b.exe", f("a/b.exe")), // forward slashes
            ("pwsh.exe", "pwsh.exe".to_string()),
        ] {
            assert_eq!(resolve_win_path(input, &m), expected, "input={input:?}");
        }
    }
}
