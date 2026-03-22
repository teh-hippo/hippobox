mod cleanup;
mod init;
mod mounts;
pub(crate) mod net;
mod process;

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

use crate::image::{ImageConfig, ImageRef, Manifest, StoredImage};

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
    pub external_netns: bool,
    pub rootless: bool,
}

pub fn run(spec: ContainerSpec) -> Result<i32> {
    if spec.rootless { process::run_rootless_unshare(spec) } else { run_prepared(spec) }
}

pub(crate) fn run_prepared(spec: ContainerSpec) -> Result<i32> {
    let cc = spec.config.config.as_ref();
    let workdir = cc.and_then(|c| c.working_dir.as_deref()).unwrap_or("/");
    let stop_signal = cc.and_then(|c| c.stop_signal.as_deref()).unwrap_or("SIGTERM");
    let user = cc.and_then(|c| c.user.clone()).filter(|u| !u.is_empty());

    let tail: Vec<String> = if spec.user_cmd.is_empty() {
        cc.and_then(|c| c.cmd.clone()).unwrap_or_default()
    } else {
        spec.user_cmd
    };
    let argv: Vec<String> = match cc.and_then(|c| c.entrypoint.as_deref()) {
        Some(ep) => ep.iter().cloned().chain(tail).collect(),
        None => tail,
    };
    if argv.is_empty() {
        bail!("no CMD or ENTRYPOINT in image config and no command provided");
    }

    let mut env_vars = cc
        .and_then(|c| c.env.as_deref()).filter(|v| !v.is_empty()).map(|v| v.to_vec())
        .unwrap_or_else(|| vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()]);
    for (key, default) in [("HOME", "/root"), ("TERM", "xterm")] {
        if env_find_mut(&mut env_vars, key).is_none() {
            env_vars.push(format!("{key}={default}"));
        }
    }
    let mut env_vars = apply_env_overrides(env_vars, &spec.user_env)?;

    let container_dir = spec.base_dir.join("containers").join(&spec.id);
    let (upper, work, merged) = (
        container_dir.join("upper"), container_dir.join("work"), container_dir.join("merged"),
    );
    std::fs::create_dir_all(&container_dir)?;
    for dir in [&upper, &work, &merged] { std::fs::create_dir(dir)?; }

    let lock_file = cleanup::acquire_container_lock(&container_dir)?;
    let mut guard = cleanup::CleanupGuard {
        id: spec.id.clone(), container_dir, merged: merged.clone(),
        layer_dirs: Vec::new(), overlay_mounted: false, rootless: spec.rootless, _lock: lock_file,
    };

    let layer_dirs: Vec<PathBuf> = spec.manifest.layers.iter().rev()
        .map(|layer| layer.layer_dir(&spec.base_dir)).collect();
    for dir in &layer_dirs {
        if !dir.exists() {
            bail!("layer directory missing: {} — image may need re-pulling", dir.display());
        }
        let _ = std::fs::write(dir.join(".in-use"), spec.id.as_bytes());
    }

    mounts::mount_overlay(&layer_dirs, &upper, &work, &merged, spec.rootless).with_context(|| {
        if spec.rootless { "overlay mount failed; Linux 5.11+ with unprivileged overlayfs support is required" }
        else { "overlay mount failed" }
    })?;
    guard.layer_dirs = layer_dirs;
    guard.overlay_mounted = true;

    if spec.rootless && let Some(shim_path) = find_rename_shim() {
        let dest_dir = merged.join(".hippobox");
        let _ = std::fs::create_dir(&dest_dir);
        if std::fs::copy(&shim_path, dest_dir.join("rename_shim.so")).is_ok() {
            env_vars.push("LD_PRELOAD=/.hippobox/rename_shim.so".into());
        }
    }

    mounts::prepare_host_device_sources(&merged)?;

    let img = &spec.image_ref;
    eprintln!("starting container {} ({}/{}/{})", &spec.id[..12], img.registry, img.repository, img.tag);
    eprintln!("  cmd: {:?}", argv);

    process::run_container(process::ChildConfig {
        rootfs: merged.to_string_lossy().into_owned(), argv, env_vars,
        workdir: workdir.to_string(), container_id: spec.id,
        rootless: spec.rootless, user, volumes: spec.volumes,
        network_mode: spec.network_mode, port_mappings: spec.port_mappings,
        external_netns: spec.external_netns, ready_fd: None,
    }, stop_signal).context("container execution failed")
}

pub(crate) fn resolve_self_exe() -> Result<PathBuf> {
    std::fs::read_link("/proc/self/exe")
        .or_else(|_| std::env::current_exe())
        .context("failed to locate current executable")
}

pub(crate) fn set_pdeathsig() -> std::io::Result<()> {
    let ret = unsafe {
        nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGTERM as nix::libc::c_ulong, 0, 0, 0)
    };
    if ret != 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

pub(crate) fn set_pdeathsig_with_race_check() -> Result<()> {
    let ppid_before = nix::unistd::getppid();
    set_pdeathsig().context("failed to set PR_SET_PDEATHSIG")?;
    if nix::unistd::getppid() != ppid_before { std::process::exit(1); }
    Ok(())
}

fn find_rename_shim() -> Option<PathBuf> {
    let shim = resolve_self_exe().ok()?.parent()?.join("librename_shim.so");
    shim.exists().then_some(shim)
}

fn apply_env_overrides(mut vars: Vec<String>, overrides: &[String]) -> Result<Vec<String>> {
    for ov in overrides {
        let Some((key, _)) = ov.split_once('=') else {
            bail!("invalid env override {ov:?}, expected KEY=VALUE");
        };
        if key.is_empty() { bail!("invalid env override {ov:?}, empty key"); }
        if let Some(existing) = env_find_mut(&mut vars, key) {
            ov.clone_into(existing);
        } else {
            vars.push(ov.clone());
        }
    }
    Ok(vars)
}

pub(super) fn env_find_mut<'a>(vars: &'a mut [String], key: &str) -> Option<&'a mut String> {
    vars.iter_mut().find(|v| v.split_once('=').is_some_and(|(k, _)| k == key))
}

pub fn load_image(image_ref: &ImageRef, base_dir: &Path) -> Result<(Manifest, ImageConfig)> {
    let path = image_ref.image_metadata_path(base_dir);
    let data = std::fs::read(&path).with_context(|| {
        format!("image not found locally: {}/{}/{}", image_ref.registry, image_ref.repository, image_ref.tag)
    })?;
    let stored: StoredImage = serde_json::from_slice(&data)
        .with_context(|| format!("failed to parse stored image metadata: {}", path.display()))?;
    Ok((stored.manifest, stored.config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_overrides() {
        let r = apply_env_overrides(
            vec!["PATH=/usr/bin".into(), "HOME=/root".into()], &["HOME=/home/user".into()],
        ).unwrap();
        assert_eq!(r, vec!["PATH=/usr/bin", "HOME=/home/user"]);

        let r = apply_env_overrides(vec!["PATH=/usr/bin".into()], &["FOO=bar".into()]).unwrap();
        assert_eq!(r, vec!["PATH=/usr/bin", "FOO=bar"]);

        let r = apply_env_overrides(vec!["PATH=/usr/bin".into()], &["FOO=a=b=c".into()]).unwrap();
        assert_eq!(r, vec!["PATH=/usr/bin", "FOO=a=b=c"]);

        assert!(apply_env_overrides(vec![], &["NOEQUALS".into()]).is_err());
        assert!(apply_env_overrides(vec![], &["=value".into()]).is_err());
    }
}
