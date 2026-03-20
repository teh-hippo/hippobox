mod cgroups;
mod mounts;
mod namespaces;
mod process;
mod rootfs;

use anyhow::{Context, Result, bail};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{self, Signal};
use std::fs::File;
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
    let user = container_config
        .and_then(|c| c.user.clone())
        .filter(|u| !u.is_empty());

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

    let lock_file = acquire_container_lock(&container_dir)?;

    let mut cleanup = CleanupGuard {
        id: spec.id.clone(),
        container_dir,
        merged: merged.clone(),
        overlay_mounted: false,
        rootless: spec.rootless,
        _lock: lock_file,
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
        user,
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

fn acquire_container_lock(container_dir: &Path) -> Result<Flock<File>> {
    let lock_path = container_dir.join("hippobox.lock");
    let lock_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("failed to open lock at {}", lock_path.display()))?;
    Flock::lock(lock_file, FlockArg::LockExclusive)
        .map_err(|(_, e)| e)
        .with_context(|| format!("failed to flock {}", lock_path.display()))
}

/// Clean up stale containers from previous runs that didn't get a chance to clean
/// up (e.g. the hippobox process was killed). Best-effort: logs warnings and
/// continues on individual failures.
pub fn gc_stale_containers(base_dir: &Path) {
    let containers_dir = base_dir.join("containers");
    let entries = match std::fs::read_dir(&containers_dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    let dirs: Vec<_> = entries.filter_map(|e| e.ok()).collect();

    for entry in dirs {
        let path = entry.path();
        if !entry.file_type().is_ok_and(|ft| ft.is_dir()) {
            continue;
        }

        if let Err(e) = gc_try_clean_container(&path) {
            eprintln!(
                "warning: gc failed for {}: {e}",
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
        }
    }
}

fn gc_try_clean_container(container_dir: &Path) -> Result<()> {
    let lock_path = container_dir.join("hippobox.lock");

    // No lock file means a legacy or partially-created container. Try to clean it.
    if lock_path.exists() {
        let lock_file = File::open(&lock_path)?;
        match Flock::lock(lock_file, FlockArg::LockExclusiveNonblock) {
            Ok(_flock) => {
                // Lock acquired — the owner process is dead. Proceed with cleanup.
            }
            Err((_, nix::errno::Errno::EAGAIN)) => {
                // Lock held by another process — container is active.
                return Ok(());
            }
            Err((_, e)) => return Err(e).context("failed to probe container lock"),
        }
    }

    let merged = container_dir.join("merged");
    if merged.exists() {
        // Unmount device bind mounts first (children before parent).
        let _ = mounts::cleanup_host_device_sources(&merged);

        // Try non-detach overlay unmount. If EBUSY, an orphaned container process
        // is still rooted there — don't remove the directory.
        match nix::mount::umount2(&merged, nix::mount::MntFlags::empty()) {
            Ok(_) => {}
            Err(
                nix::errno::Errno::EINVAL
                | nix::errno::Errno::ENOENT
                | nix::errno::Errno::EPERM,
            ) => {
                // EINVAL: not mounted. ENOENT: path gone. EPERM: not privileged
                // (rootless container mounts live in a user namespace and aren't
                // visible here). All fine — just remove the dir.
            }
            Err(nix::errno::Errno::EBUSY) => {
                eprintln!(
                    "warning: overlay still busy for {}, skipping",
                    container_dir
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                );
                return Ok(());
            }
            Err(e) => {
                return Err(e).context("failed to unmount stale overlay");
            }
        }
    }

    let _ = std::fs::remove_dir_all(container_dir);
    Ok(())
}

struct CleanupGuard {
    id: String,
    container_dir: PathBuf,
    merged: PathBuf,
    overlay_mounted: bool,
    rootless: bool,
    _lock: Flock<File>,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if !self.rootless {
            let _ = cgroups::cleanup(&self.id);
        }
        if self.overlay_mounted {
            let _ = mounts::cleanup_host_device_sources(&self.merged);
            let _ = rootfs::unmount_overlay(&self.merged);
        }
        let _ = std::fs::remove_dir_all(&self.container_dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_container_dir(base: &Path, name: &str) -> PathBuf {
        let dir = base.join("containers").join(name);
        std::fs::create_dir_all(dir.join("merged")).unwrap();
        std::fs::create_dir_all(dir.join("upper")).unwrap();
        std::fs::create_dir_all(dir.join("work")).unwrap();
        dir
    }

    #[test]
    fn gc_removes_dir_with_no_lock_file() {
        let tmp = TempDir::new().unwrap();
        let container = make_container_dir(tmp.path(), "stale-no-lock");

        gc_stale_containers(tmp.path());
        assert!(!container.exists(), "stale container without lock should be removed");
    }

    #[test]
    fn gc_skips_container_with_held_lock() {
        let tmp = TempDir::new().unwrap();
        let container = make_container_dir(tmp.path(), "active");
        let _lock = acquire_container_lock(&container).unwrap();

        gc_stale_containers(tmp.path());
        assert!(container.exists(), "active container should be kept");
    }

    #[test]
    fn gc_removes_container_with_released_lock() {
        let tmp = TempDir::new().unwrap();
        let container = make_container_dir(tmp.path(), "dead-owner");

        // Acquire and immediately release the lock.
        {
            let _lock = acquire_container_lock(&container).unwrap();
        }

        gc_stale_containers(tmp.path());
        assert!(!container.exists(), "container with released lock should be removed");
    }

    #[test]
    fn gc_handles_empty_containers_dir() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("containers")).unwrap();

        gc_stale_containers(tmp.path());
        // Should not panic or error.
    }

    #[test]
    fn gc_handles_missing_containers_dir() {
        let tmp = TempDir::new().unwrap();
        // No containers/ dir at all.

        gc_stale_containers(tmp.path());
        // Should not panic or error.
    }

    #[test]
    fn gc_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let container = make_container_dir(tmp.path(), "once-stale");

        gc_stale_containers(tmp.path());
        assert!(!container.exists());

        // Second run should be a no-op.
        gc_stale_containers(tmp.path());
    }
}
