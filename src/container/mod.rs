pub mod cgroups;
pub mod mounts;
pub mod namespaces;
pub mod process;
pub mod rootfs;

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::image::ref_parser::ImageRef;
use crate::registry::manifest::{ImageConfig, Manifest};

/// Everything needed to run a container.
pub struct ContainerSpec {
    pub id: String,
    pub image_ref: ImageRef,
    pub manifest: Manifest,
    pub config: ImageConfig,
    pub base_dir: PathBuf,
    pub user_cmd: Vec<String>,
}

/// Run a container from a pulled image.
pub fn run(spec: ContainerSpec) -> Result<i32> {
    let container_dir = spec.base_dir.join("containers").join(&spec.id);
    let upper = container_dir.join("upper");
    let work = container_dir.join("work");
    let merged = container_dir.join("merged");

    // Create container directories
    for dir in [&upper, &work, &merged] {
        std::fs::create_dir_all(dir)?;
    }

    // Build layer paths (reversed for overlayfs: manifest is bottom-to-top, overlayfs wants top-to-bottom)
    let layer_dirs: Vec<PathBuf> = spec
        .manifest
        .layers
        .iter()
        .rev()
        .map(|l| spec.base_dir.join("layers/sha256").join(l.digest_hex()))
        .collect();

    // Mount overlayfs
    rootfs::mount_overlay(&layer_dirs, &upper, &work, &merged)?;

    // Build the command to execute
    let container_config = spec.config.config.as_ref();
    let (argv, env_vars) = process::build_command(container_config, &spec.user_cmd)?;
    let workdir = container_config
        .and_then(|c| c.working_dir.as_deref())
        .unwrap_or("/");
    let stop_signal = container_config
        .and_then(|c| c.stop_signal.as_deref())
        .unwrap_or("SIGTERM");

    eprintln!("starting container {} ({})", &spec.id[..12], spec.image_ref);
    eprintln!("  cmd: {:?}", argv);

    // Fork and run in namespaces via re-exec
    let exit_code = process::run_container(
        &spec.id,
        &merged,
        &argv,
        &env_vars,
        workdir,
        stop_signal,
        &spec.base_dir,
    )
    .context("container execution failed")?;

    // Cleanup
    rootfs::unmount_overlay(&merged)?;
    if container_dir.exists() {
        std::fs::remove_dir_all(&container_dir)?;
    }
    cgroups::cleanup(&spec.id)?;

    Ok(exit_code)
}

/// Load a previously pulled image's manifest and config.
pub fn load_image(image_ref: &ImageRef, base_dir: &Path) -> Result<(Manifest, ImageConfig)> {
    let config_path = base_dir
        .join("images")
        .join(&image_ref.repository)
        .join(format!("{}.json", image_ref.tag));

    let data = std::fs::read_to_string(&config_path)
        .with_context(|| format!("image not found locally: {image_ref}"))?;

    let val: serde_json::Value = serde_json::from_str(&data)?;
    let manifest: Manifest = serde_json::from_value(
        val.get("manifest")
            .context("missing manifest in stored image")?
            .clone(),
    )?;
    let config: ImageConfig = serde_json::from_value(
        val.get("config")
            .context("missing config in stored image")?
            .clone(),
    )?;

    Ok((manifest, config))
}
