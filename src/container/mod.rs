pub mod cgroups;
pub mod mounts;
pub mod namespaces;
pub mod process;
pub mod rootfs;

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::image::ref_parser::ImageRef;
use crate::registry::manifest::{ImageConfig, Manifest, StoredImage};

pub struct ContainerSpec {
    pub id: String,
    pub image_ref: ImageRef,
    pub manifest: Manifest,
    pub config: ImageConfig,
    pub base_dir: PathBuf,
    pub user_cmd: Vec<String>,
}

pub fn run(spec: ContainerSpec) -> Result<i32> {
    let container_config = spec.config.config.as_ref();
    let (argv, env_vars) = process::build_command(container_config, &spec.user_cmd)?;
    let workdir = container_config
        .and_then(|c| c.working_dir.as_deref())
        .unwrap_or("/");
    let stop_signal = container_config
        .and_then(|c| c.stop_signal.as_deref())
        .unwrap_or("SIGTERM");

    let container_dir = spec.base_dir.join("containers").join(&spec.id);
    let upper = container_dir.join("upper");
    let work = container_dir.join("work");
    let merged = container_dir.join("merged");

    for dir in [&upper, &work, &merged] {
        std::fs::create_dir_all(dir)?;
    }

    let mut cleanup = CleanupGuard::new(spec.id.clone(), container_dir, merged.clone());

    let layer_dirs: Vec<PathBuf> = spec
        .manifest
        .layers
        .iter()
        .rev()
        .map(|layer| spec.base_dir.join("layers/sha256").join(layer.digest_hex()))
        .collect();

    rootfs::mount_overlay(&layer_dirs, &upper, &work, &merged)?;
    cleanup.overlay_mounted = true;

    eprintln!("starting container {} ({})", &spec.id[..12], spec.image_ref);
    eprintln!("  cmd: {:?}", argv);

    process::run_container(&spec.id, &merged, &argv, &env_vars, workdir, stop_signal)
        .context("container execution failed")
}

pub fn load_image(image_ref: &ImageRef, base_dir: &Path) -> Result<(Manifest, ImageConfig)> {
    let config_path = image_ref.image_metadata_path(base_dir);
    let data = std::fs::read(&config_path)
        .with_context(|| format!("image not found locally: {image_ref}"))?;
    let stored: StoredImage = serde_json::from_slice(&data)
        .with_context(|| format!("failed to parse stored image metadata: {}", config_path.display()))?;
    Ok((stored.manifest, stored.config))
}

struct CleanupGuard {
    id: String,
    container_dir: PathBuf,
    merged: PathBuf,
    overlay_mounted: bool,
}

impl CleanupGuard {
    fn new(id: String, container_dir: PathBuf, merged: PathBuf) -> Self {
        Self {
            id,
            container_dir,
            merged,
            overlay_mounted: false,
        }
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = cgroups::cleanup(&self.id);
        if self.overlay_mounted {
            let _ = rootfs::unmount_overlay(&self.merged);
        }
        if self.container_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.container_dir);
        }
    }
}
