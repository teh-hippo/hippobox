mod cgroups;
mod mounts;
mod namespaces;
pub(crate) mod net;
mod process;
mod rootfs;
mod seccomp;

use anyhow::{Context, Result, bail};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use std::fs::File;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};

use crate::image::ref_parser::ImageRef;
use crate::registry::manifest::{ImageConfig, Manifest, StoredImage};

pub(crate) use process::container_init;
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

    let lock_file = acquire_container_lock(&container_dir)?;

    let mut cleanup = CleanupGuard {
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
        .map(|layer| {
            spec.base_dir.join("layers/sha256").join(
                layer
                    .digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&layer.digest),
            )
        })
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
    cleanup.layer_dirs = layer_dirs.clone();

    rootfs::mount_overlay(&layer_dirs, &upper, &work, &merged, spec.rootless).with_context(|| {
        if spec.rootless {
            "overlay mount failed; Linux 5.11+ with unprivileged overlayfs support is required"
        } else {
            "overlay mount failed"
        }
    })?;
    cleanup.overlay_mounted = true;

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

/// Locate the rename shim .so next to the hippobox binary.
fn find_rename_shim() -> Option<PathBuf> {
    let exe = std::fs::read_link("/proc/self/exe")
        .or_else(|_| std::env::current_exe())
        .ok()?;
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

fn run_rootless_unshare(spec: ContainerSpec) -> Result<i32> {
    let exe = std::fs::read_link("/proc/self/exe")
        .or_else(|_| std::env::current_exe())
        .context("failed to locate current executable")?;

    let has_ports = !spec.port_mappings.is_empty();
    let isolate_network = spec.network_mode == net::NetworkMode::None || has_ports;

    if has_ports {
        net::check_pasta()?;
    }

    let pre_exec_fn = || unsafe {
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
    };

    let mut child = if has_ports {
        // pasta wraps the process: creates user+net namespace from the HOST,
        // binds host ports for forwarding, then runs unshare inside for
        // mount/uts/ipc isolation. pasta's user namespace has single-UID
        // mapping (0→real_uid) which is sufficient for most containers.
        let pasta_path = net::check_pasta()?;
        let mut cmd = Command::new(pasta_path);
        unsafe { cmd.pre_exec(pre_exec_fn); }
        cmd.args(["--config-net", "--quiet", "--foreground", "--no-map-gw"]);
        net::add_port_args(&mut cmd, &spec.port_mappings);
        cmd.args(["-u", "none", "-T", "none", "-U", "none"]);
        cmd.args(["--", "unshare", "--mount", "--uts", "--ipc", "--"]);
        cmd.arg(&exe).arg("--rootless-bootstrap");
        cmd.stdin(Stdio::piped())
            .spawn()
            .context("failed to execute pasta")?
    } else {
        // Standard rootless: unshare handles all namespaces with full
        // subordinate UID mapping (--map-auto).
        let mut unshare_args: Vec<&str> = vec![
            "--user", "--map-root-user", "--map-auto",
            "--mount", "--uts", "--ipc",
        ];
        if isolate_network {
            unshare_args.push("--net");
        }
        unshare_args.push("--");
        let mut cmd = Command::new("unshare");
        unsafe { cmd.pre_exec(pre_exec_fn); }
        cmd.args(&unshare_args).arg(&exe).arg("--rootless-bootstrap");
        cmd.stdin(Stdio::piped())
            .spawn()
            .context("failed to execute unshare")?
    };

    {
        let stdin = child
            .stdin
            .take()
            .context("failed to open rootless bootstrap stdin")?;
        let mut writer = std::io::BufWriter::new(stdin);
        serde_json::to_writer(&mut writer, &spec)
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

    // Use blocking waitpid instead of polling try_wait+sleep.
    // waitpid returns EINTR when our signal handler fires, letting us
    // forward signals immediately without a 50ms poll delay.
    let child_pid = Pid::from_raw(child.id() as i32);
    std::mem::forget(child);
    loop {
        match nix::sys::wait::waitpid(child_pid, None) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(128 + sig as i32),
            Err(nix::errno::Errno::EINTR) => {
                if ROOTLESS_PENDING_SIGNAL.swap(0, Ordering::SeqCst) != 0 {
                    let _ = unsafe { nix::libc::kill(-child_pid.as_raw(), nix::libc::SIGTERM) };
                }
            }
            Err(err) => return Err(err).context("failed to wait for unshare"),
            _ => continue,
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

    for entry in entries.flatten() {
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
    layer_dirs: Vec<PathBuf>,
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
        // Remove in-use markers so GC can prune these layers if orphaned.
        for dir in &self.layer_dirs {
            let _ = std::fs::remove_file(dir.join(".in-use"));
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
}
