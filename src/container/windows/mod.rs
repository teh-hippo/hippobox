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
        volumes,
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
        super::copy_dir_recursive(&layer_dir, &merged)?;
    }

    // Apply volumes: tmpfs → create dir, real source → copy into merged
    for vol in &volumes {
        let target_path = merged.join(vol.target.trim_start_matches('/'));
        if vol.source == "tmpfs" {
            std::fs::create_dir_all(&target_path)?;
        } else {
            let src = std::path::Path::new(&vol.source);
            if src.is_dir() {
                std::fs::create_dir_all(&target_path)?;
                super::copy_dir_recursive(src, &target_path)?;
            } else {
                if let Some(p) = target_path.parent() {
                    std::fs::create_dir_all(p)?;
                }
                std::fs::copy(src, &target_path)
                    .with_context(|| format!("copy volume {}", vol.source))?;
            }
        }
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

    // Set working directory from image config
    let workdir = cc
        .and_then(|c| c.working_dir.as_deref())
        .filter(|w| !w.is_empty());
    if let Some(w) = workdir {
        cmd.current_dir(resolve_win_path(w, &merged_str));
    }

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

struct CleanupGuard(PathBuf);
impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(not(unix))]
pub(crate) fn gc_stale_containers(base_dir: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(base_dir.join("containers")) else {
        return 0;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
    0
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
        crate::container::copy_dir_recursive(&src, &dst).unwrap();
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
        crate::container::copy_dir_recursive(&src, &dst).unwrap();
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

    #[test]
    fn gc_stale_containers_removes_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let containers = tmp.path().join("containers");
        std::fs::create_dir_all(containers.join("stale1")).unwrap();
        std::fs::create_dir_all(containers.join("stale2/sub")).unwrap();
        // Files under containers/ are left alone
        std::fs::write(containers.join("not_a_dir"), "x").unwrap();
        crate::container::gc_stale_containers(tmp.path());
        assert!(!containers.join("stale1").exists());
        assert!(!containers.join("stale2").exists());
        assert!(containers.join("not_a_dir").exists());
    }

    #[test]
    fn gc_stale_containers_missing_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        // No containers/ directory — should not panic
        assert_eq!(crate::container::gc_stale_containers(tmp.path()), 0);
    }
}
