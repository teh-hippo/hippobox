mod cgroups;
mod cleanup;
mod init;
mod mounts;
mod namespaces;
pub(crate) mod net;
mod process;
mod rootfs;
mod rootless;
mod seccomp;

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

use crate::image::ref_parser::ImageRef;
use crate::image::manifest::{ImageConfig, Manifest, StoredImage};

pub(crate) use init::container_init;
pub use cleanup::gc_stale_containers;
pub use mounts::parse_volume;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VolumeMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ContainerSpec {
    pub id: String,
    pub image_ref: ImageRef,
    pub manifest: Manifest,
    pub config: ImageConfig,
    pub base_dir: PathBuf,
    pub user_cmd: Vec<String>,
    pub user_env: Vec<String>,
    pub volumes: Vec<VolumeMount>,
    pub network_mode: net::NetworkMode,
    pub port_mappings: Vec<net::PortMapping>,
    /// Set when pasta (or another tool) has already created the network namespace.
    pub network_isolated: bool,
    pub rootless: bool,
}

pub fn run(spec: ContainerSpec) -> Result<i32> {
    if spec.rootless {
        return rootless::run_rootless_unshare(spec);
    }

    run_prepared(spec)
}

pub(crate) fn run_prepared(spec: ContainerSpec) -> Result<i32> {
    let container_config = spec.config.config.as_ref();
    let workdir = container_config
        .and_then(|c| c.working_dir.as_deref())
        .unwrap_or("/");
    let stop_signal = container_config
        .and_then(|c| c.stop_signal.as_deref())
        .unwrap_or("SIGTERM");
    let user = container_config
        .and_then(|c| c.user.clone())
        .filter(|u| !u.is_empty());

    let entrypoint = container_config.and_then(|c| c.entrypoint.as_deref());
    let tail: Vec<String> = if spec.user_cmd.is_empty() {
        container_config
            .and_then(|c| c.cmd.as_deref())
            .map(|c| c.to_vec())
            .unwrap_or_default()
    } else {
        spec.user_cmd.clone()
    };
    let argv: Vec<String> = match entrypoint {
        Some(ep) => ep.iter().cloned().chain(tail).collect(),
        None => tail,
    };
    if argv.is_empty() {
        bail!("no CMD or ENTRYPOINT in image config and no command provided");
    }

    let mut env_vars = container_config
        .and_then(|c| c.env.as_deref())
        .filter(|vars| !vars.is_empty())
        .map(|vars| vars.to_vec())
        .unwrap_or_else(|| {
            vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()]
        });
    // Ensure HOME and TERM have sensible defaults (image env or user -e can override).
    for (key, default) in [("HOME", "/root"), ("TERM", "xterm")] {
        if !env_vars.iter().any(|v| v.split_once('=').is_some_and(|(k, _)| k == key)) {
            env_vars.push(format!("{key}={default}"));
        }
    }
    let mut env_vars = apply_env_overrides(env_vars, &spec.user_env)?;

    let container_dir = spec.base_dir.join("containers").join(&spec.id);
    let upper = container_dir.join("upper");
    let work = container_dir.join("work");
    let merged = container_dir.join("merged");

    // Single create_dir_all for parent, then cheap mkdir for leaves.
    std::fs::create_dir_all(&container_dir)?;
    for dir in [&upper, &work, &merged] {
        std::fs::create_dir(dir)?;
    }

    let lock_file = cleanup::acquire_container_lock(&container_dir)?;

    let mut cleanup_guard = cleanup::CleanupGuard {
        id: spec.id.clone(),
        container_dir,
        merged: merged.clone(),
        layer_dirs: Vec::new(),
        overlay_mounted: false,
        rootless: spec.rootless,
        _lock: lock_file,
    };

    let layer_dirs: Vec<PathBuf> = spec
        .manifest
        .layers
        .iter()
        .rev()
        .map(|layer| layer.layer_dir(&spec.base_dir))
        .collect();

    // Validate all layer dirs exist before mounting overlay.
    for dir in &layer_dirs {
        if !dir.exists() {
            bail!(
                "layer directory missing: {} — image may need re-pulling",
                dir.display()
            );
        }
    }

    // Place in-use markers so GC won't prune layers while we're using them.
    for dir in &layer_dirs {
        let marker = dir.join(".in-use");
        let _ = std::fs::write(&marker, spec.id.as_bytes());
    }
    cleanup_guard.layer_dirs = layer_dirs.clone();

    rootfs::mount_overlay(&layer_dirs, &upper, &work, &merged, spec.rootless).with_context(|| {
        if spec.rootless {
            "overlay mount failed; Linux 5.11+ with unprivileged overlayfs support is required"
        } else {
            "overlay mount failed"
        }
    })?;
    cleanup_guard.overlay_mounted = true;

    // For rootless containers, install the rename shim to work around EXDEV on
    // unprivileged overlayfs (redirect_dir=nofollow blocks directory renames).
    if spec.rootless
        && let Some(shim_path) = find_rename_shim()
    {
        let dest_dir = merged.join(".hippobox");
        let _ = std::fs::create_dir(&dest_dir);
        let dest = dest_dir.join("rename_shim.so");
        if std::fs::copy(&shim_path, &dest).is_ok() {
            env_vars.push("LD_PRELOAD=/.hippobox/rename_shim.so".to_string());
        }
    }

    mounts::prepare_host_device_sources(&merged)?;

    let image = &spec.image_ref;
    eprintln!(
        "starting container {} ({}/{}/{})",
        &spec.id[..12],
        &image.registry,
        &image.repository,
        &image.tag
    );
    eprintln!("  cmd: {:?}", argv);

    let child_config = process::ChildConfig {
        rootfs: merged.to_string_lossy().to_string(),
        argv,
        env_vars,
        workdir: workdir.to_string(),
        container_id: spec.id,
        rootless: spec.rootless,
        user,
        volumes: spec.volumes,
        network_mode: spec.network_mode,
        port_mappings: spec.port_mappings,
        network_isolated: spec.network_isolated,
        ready_fd: None,
    };

    process::run_container(child_config, stop_signal).context("container execution failed")
}

pub(crate) fn resolve_self_exe() -> Result<PathBuf> {
    std::fs::read_link("/proc/self/exe")
        .or_else(|_| std::env::current_exe())
        .context("failed to locate current executable")
}

/// Locate the rename shim .so next to the hippobox binary.
fn find_rename_shim() -> Option<PathBuf> {
    let exe = resolve_self_exe().ok()?;
    let dir = exe.parent()?;
    let shim = dir.join("librename_shim.so");
    shim.exists().then_some(shim)
}

fn apply_env_overrides(mut env_vars: Vec<String>, overrides: &[String]) -> Result<Vec<String>> {
    for override_var in overrides {
        let Some((key, _)) = override_var.split_once('=') else {
            bail!("invalid environment override {override_var:?}, expected KEY=VALUE");
        };
        if key.is_empty() {
            bail!("invalid environment override {override_var:?}, empty key");
        }
        if let Some(existing) = env_vars.iter_mut().find(|v| {
            v.split_once('=')
                .is_some_and(|(k, _)| k == key)
        }) {
            *existing = override_var.clone();
        } else {
            env_vars.push(override_var.clone());
        }
    }
    Ok(env_vars)
}

pub fn load_image(image_ref: &ImageRef, base_dir: &Path) -> Result<(Manifest, ImageConfig)> {
    let config_path = image_ref.image_metadata_path(base_dir);
    let data = std::fs::read(&config_path).with_context(|| {
        format!(
            "image not found locally: {}/{}/{}",
            image_ref.registry, image_ref.repository, image_ref.tag
        )
    })?;
    let stored: StoredImage = serde_json::from_slice(&data).with_context(|| {
        format!(
            "failed to parse stored image metadata: {}",
            config_path.display()
        )
    })?;
    Ok((stored.manifest, stored.config))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_replaces_existing() {
        let base = vec!["PATH=/usr/bin".into(), "HOME=/root".into()];
        let result = apply_env_overrides(base, &["HOME=/home/user".into()]).unwrap();
        assert_eq!(result, vec!["PATH=/usr/bin", "HOME=/home/user"]);
    }

    #[test]
    fn env_override_appends_new() {
        let base = vec!["PATH=/usr/bin".into()];
        let result = apply_env_overrides(base, &["FOO=bar".into()]).unwrap();
        assert_eq!(result, vec!["PATH=/usr/bin", "FOO=bar"]);
    }

    #[test]
    fn env_override_rejects_missing_equals() {
        let base = vec![];
        assert!(apply_env_overrides(base, &["NOEQUALS".into()]).is_err());
    }

    #[test]
    fn env_override_rejects_empty_key() {
        let base = vec![];
        assert!(apply_env_overrides(base, &["=value".into()]).is_err());
    }

    #[test]
    fn env_override_value_with_equals() {
        let base = vec!["PATH=/usr/bin".into()];
        let result = apply_env_overrides(base, &["FOO=a=b=c".into()]).unwrap();
        assert_eq!(result, vec!["PATH=/usr/bin", "FOO=a=b=c"]);
    }
}
