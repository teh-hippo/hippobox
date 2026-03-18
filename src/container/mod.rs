mod cgroups;
mod mounts;
mod namespaces;
mod process;
mod rootfs;

use anyhow::{Context, Result, bail};
use nix::sys::signal::{self, Signal};
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;
use std::time::Duration;

use crate::image::ref_parser::ImageRef;
use crate::registry::manifest::{ImageConfig, Manifest, StoredImage};

pub(crate) use process::container_init;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ContainerSpec {
    pub id: String,
    pub image_ref: ImageRef,
    pub manifest: Manifest,
    pub config: ImageConfig,
    pub base_dir: PathBuf,
    pub user_cmd: Vec<String>,
    pub user_env: Vec<String>,
    pub rootless: bool,
}

pub fn run(spec: ContainerSpec) -> Result<i32> {
    if spec.rootless {
        return run_rootless_unshare(spec);
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

    let entrypoint = container_config.and_then(|c| c.entrypoint.as_deref());
    let cmd = container_config.and_then(|c| c.cmd.as_deref());
    let argv = if spec.user_cmd.is_empty() {
        match (entrypoint, cmd) {
            (Some(ep), Some(cmd)) => ep.iter().cloned().chain(cmd.iter().cloned()).collect(),
            (Some(ep), None) => ep.to_vec(),
            (None, Some(cmd)) => cmd.to_vec(),
            (None, None) => bail!("no CMD or ENTRYPOINT in image config and no command provided"),
        }
    } else {
        entrypoint.map_or_else(
            || spec.user_cmd.clone(),
            |ep| {
                ep.iter()
                    .cloned()
                    .chain(spec.user_cmd.iter().cloned())
                    .collect()
            },
        )
    };
    if argv.is_empty() {
        bail!("resolved command is empty");
    }

    let env_vars = container_config
        .and_then(|c| c.env.as_deref())
        .filter(|vars| !vars.is_empty())
        .map(|vars| vars.to_vec())
        .unwrap_or_else(|| {
            vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()]
        });
    let env_vars = spec
        .user_env
        .iter()
        .try_fold(env_vars, |mut env_vars, override_var| {
            let Some((key, _)) = override_var.split_once('=') else {
                bail!("invalid environment override {override_var:?}, expected KEY=VALUE");
            };
            if key.is_empty() {
                bail!("invalid environment override {override_var:?}, empty key");
            }
            if let Some(existing) = env_vars.iter_mut().find(|value| {
                value
                    .split_once('=')
                    .is_some_and(|(existing, _)| existing == key)
            }) {
                *existing = override_var.clone();
            } else {
                env_vars.push(override_var.clone());
            }
            Ok(env_vars)
        })?;

    let container_dir = spec.base_dir.join("containers").join(&spec.id);
    let upper = container_dir.join("upper");
    let work = container_dir.join("work");
    let merged = container_dir.join("merged");

    for dir in [&upper, &work, &merged] {
        std::fs::create_dir_all(dir)?;
    }

    let mut cleanup = CleanupGuard {
        id: spec.id.clone(),
        container_dir,
        merged: merged.clone(),
        overlay_mounted: false,
        rootless: spec.rootless,
    };

    let layer_dirs: Vec<PathBuf> = spec
        .manifest
        .layers
        .iter()
        .rev()
        .map(|layer| {
            spec.base_dir.join("layers/sha256").join(
                layer
                    .digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&layer.digest),
            )
        })
        .collect();

    if spec.rootless {
        rootfs::mount_overlay(&layer_dirs, &upper, &work, &merged).with_context(|| {
            "rootless overlay mount failed; Linux 5.11+ with unprivileged overlayfs support is required"
        })?;
    } else {
        rootfs::mount_overlay(&layer_dirs, &upper, &work, &merged)?;
    }
    cleanup.overlay_mounted = true;

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

    process::run_container(
        &spec.id,
        &merged,
        &argv,
        &env_vars,
        workdir,
        stop_signal,
        spec.rootless,
    )
    .context("container execution failed")
}

fn run_rootless_unshare(spec: ContainerSpec) -> Result<i32> {
    let exe = std::fs::read_link("/proc/self/exe")
        .or_else(|_| std::env::current_exe())
        .context("failed to locate current executable")?;

    let mut command = Command::new("unshare");
    unsafe {
        command.pre_exec(|| {
            if nix::libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            let ret = nix::libc::prctl(
                nix::libc::PR_SET_PDEATHSIG,
                nix::libc::SIGTERM as nix::libc::c_ulong,
                0,
                0,
                0,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command
        .args([
            "--user",
            "--map-root-user",
            "--map-auto",
            "--mount",
            "--uts",
            "--ipc",
            "--",
        ])
        .arg(exe)
        .arg("--rootless-bootstrap")
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to execute unshare")?;
    {
        let mut stdin = child
            .stdin
            .take()
            .context("failed to open rootless bootstrap stdin")?;
        serde_json::to_writer(&mut stdin, &spec)
            .context("failed to send rootless bootstrap spec")?;
    }

    unsafe {
        signal::signal(
            Signal::SIGINT,
            signal::SigHandler::Handler(note_rootless_signal),
        )
        .context("failed to install rootless SIGINT handler")?;
        signal::signal(
            Signal::SIGTERM,
            signal::SigHandler::Handler(note_rootless_signal),
        )
        .context("failed to install rootless SIGTERM handler")?;
    }

    let child_pid = child.id() as i32;
    loop {
        if ROOTLESS_PENDING_SIGNAL.swap(0, Ordering::SeqCst) != 0 {
            let _ = unsafe { nix::libc::kill(-child_pid, nix::libc::SIGTERM) };
        }

        match child.try_wait().context("failed to wait for unshare")? {
            Some(status) => return Ok(status.code().unwrap_or(1)),
            None => thread::sleep(Duration::from_millis(50)),
        }
    }
}

static ROOTLESS_PENDING_SIGNAL: AtomicU8 = AtomicU8::new(0);

extern "C" fn note_rootless_signal(_: nix::libc::c_int) {
    ROOTLESS_PENDING_SIGNAL.store(1, Ordering::SeqCst);
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

struct CleanupGuard {
    id: String,
    container_dir: PathBuf,
    merged: PathBuf,
    overlay_mounted: bool,
    rootless: bool,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if !self.rootless {
            let _ = cgroups::cleanup(&self.id);
        }
        if self.overlay_mounted {
            let _ = rootfs::unmount_overlay(&self.merged);
            let _ = mounts::cleanup_host_device_sources(&self.merged);
        }
        let _ = std::fs::remove_dir_all(&self.container_dir);
    }
}
