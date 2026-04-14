use anyhow::{Context, Result};

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
    let _guard = super::SimpleCleanupGuard(container_dir.clone());

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

#[cfg(test)]
mod tests {
    use super::*;

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
