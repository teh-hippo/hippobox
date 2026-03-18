use anyhow::{bail, Context, Result};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{self, ForkResult, Pid};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;

use crate::registry::manifest::ContainerConfig;

/// Build the argv and env for the container process from OCI config + user args.
pub fn build_command(
    config: Option<&ContainerConfig>,
    user_cmd: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    let entrypoint = config.and_then(|c| c.entrypoint.as_ref());
    let cmd = config.and_then(|c| c.cmd.as_ref());

    let argv = if !user_cmd.is_empty() {
        // User args replace CMD; ENTRYPOINT is kept
        match entrypoint {
            Some(ep) => {
                let mut v = ep.clone();
                v.extend(user_cmd.iter().cloned());
                v
            }
            None => user_cmd.to_vec(),
        }
    } else {
        match (entrypoint, cmd) {
            (Some(ep), Some(c)) => {
                let mut v = ep.clone();
                v.extend(c.iter().cloned());
                v
            }
            (Some(ep), None) => ep.clone(),
            (None, Some(c)) => c.clone(),
            (None, None) => bail!("no CMD or ENTRYPOINT in image config and no command provided"),
        }
    };

    let env_vars = config
        .and_then(|c| c.env.as_ref())
        .cloned()
        .unwrap_or_else(|| vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()]);

    Ok((argv, env_vars))
}

/// Run the container process using fork + re-exec pattern.
/// The parent manages the cgroup and waits for the child.
/// The child re-execs as the init shim.
pub fn run_container(
    container_id: &str,
    rootfs: &Path,
    argv: &[String],
    env_vars: &[String],
    workdir: &str,
    stop_signal: &str,
    base_dir: &Path,
) -> Result<i32> {
    // Check cgroup v2
    super::cgroups::check_cgroup_v2()?;

    // Create cgroup before fork
    super::cgroups::create(container_id)?;

    // Copy host files into rootfs before fork
    super::mounts::copy_host_files_to_rootfs(rootfs)?;

    // Create a pipe to pass config to the child
    let (read_fd, write_fd) = nix::unistd::pipe().context("failed to create pipe")?;
    let read_raw = read_fd.as_raw_fd();
    let write_raw = write_fd.as_raw_fd();

    // Fork
    let fork_result = unsafe { unistd::fork() }.context("fork failed")?;

    match fork_result {
        ForkResult::Parent { child } => {
            // Close read end in parent
            drop(read_fd);

            // Write config to child via pipe
            let config = ChildConfig {
                rootfs: rootfs.to_string_lossy().to_string(),
                argv: argv.to_vec(),
                env_vars: env_vars.to_vec(),
                workdir: workdir.to_string(),
                container_id: container_id.to_string(),
            };
            let config_json = serde_json::to_string(&config)?;
            {
                use std::io::Write;
                let mut pipe_write = unsafe { std::fs::File::from_raw_fd(write_raw) };
                pipe_write.write_all(config_json.as_bytes())?;
                // File drops here, closing the write end
            }
            // Prevent double-close
            std::mem::forget(write_fd);

            // Add child to cgroup
            super::cgroups::add_pid(container_id, child.as_raw() as u32)?;

            // Wait for child, forwarding signals
            let signal_name = parse_signal(stop_signal);
            parent_wait(child, signal_name)
        }
        ForkResult::Child => {
            // Close write end in child
            drop(write_fd);

            // Re-exec ourselves as the container init
            let exe = std::fs::read_link("/proc/self/exe")
                .unwrap_or_else(|_| std::env::current_exe().unwrap());
            let exe_c = CString::new(exe.to_string_lossy().as_bytes()).unwrap();

            let arg_init = CString::new("--container-init").unwrap();
            let arg_fd = CString::new(read_raw.to_string()).unwrap();

            // execv replaces the process — no allocations after this are needed
            nix::unistd::execv(&exe_c, &[exe_c.clone(), arg_init, arg_fd])
                .expect("execv failed");
            unreachable!()
        }
    }
}

/// Wait for the container child process, forwarding signals.
fn parent_wait(child: Pid, stop_signal: Signal) -> Result<i32> {
    // Install signal handler to forward signals to child
    let child_raw = child.as_raw();

    // Set up signal forwarding via a simple approach:
    // We catch SIGINT and SIGTERM, forward the configured stop signal
    unsafe {
        signal::signal(Signal::SIGINT, signal::SigHandler::Handler(noop_handler)).ok();
        signal::signal(Signal::SIGTERM, signal::SigHandler::Handler(noop_handler)).ok();
    }

    // Store child PID for signal forwarding
    CHILD_PID.store(child_raw, std::sync::atomic::Ordering::SeqCst);
    STOP_SIGNAL.store(stop_signal as i32, std::sync::atomic::Ordering::SeqCst);

    // Wait for child
    loop {
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(128 + sig as i32),
            Ok(WaitStatus::StillAlive) => {
                // Check if we should forward a signal
                let pending = PENDING_SIGNAL.swap(0, std::sync::atomic::Ordering::SeqCst);
                if pending != 0 {
                    let sig = STOP_SIGNAL.load(std::sync::atomic::Ordering::SeqCst);
                    signal::kill(child, Signal::try_from(sig).unwrap_or(Signal::SIGTERM)).ok();
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
            _ => continue,
        }
    }
}

static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
static STOP_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(15); // SIGTERM
static PENDING_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn noop_handler(_: nix::libc::c_int) {
    PENDING_SIGNAL.store(1, std::sync::atomic::Ordering::SeqCst);
}

/// The container init entry point (called via re-exec with --container-init).
pub fn container_init(config_fd: i32) -> Result<()> {
    // Read config from pipe
    use std::io::Read;
    let mut pipe_read = unsafe { std::fs::File::from_raw_fd(config_fd) };
    let mut config_json = String::new();
    pipe_read.read_to_string(&mut config_json)?;
    drop(pipe_read);

    let config: ChildConfig = serde_json::from_str(&config_json)?;

    // Set up namespaces and pivot_root
    super::namespaces::setup_namespaces_and_pivot(Path::new(&config.rootfs))?;

    // Set up container mounts
    super::mounts::setup_container_mounts()?;

    // Set hostname
    nix::unistd::sethostname(&config.container_id[..12]).ok();

    // prctl(PR_SET_NO_NEW_PRIVS)
    unsafe {
        nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }

    // chdir to workdir
    if !config.workdir.is_empty() && config.workdir != "/" {
        std::env::set_current_dir(&config.workdir).ok();
    }

    // Now fork again: we become the init shim (PID 1), child is the actual process
    let fork_result = unsafe { unistd::fork() }.context("inner fork failed")?;

    match fork_result {
        ForkResult::Parent { child } => {
            // We are the init shim (PID 1 in the container)
            init_shim(child)
        }
        ForkResult::Child => {
            // Execute the actual container process
            let program = CString::new(config.argv[0].as_str())
                .context("invalid program name")?;
            let c_argv: Vec<CString> = config
                .argv
                .iter()
                .map(|a| CString::new(a.as_str()).unwrap())
                .collect();
            let c_env: Vec<CString> = config
                .env_vars
                .iter()
                .map(|e| CString::new(e.as_str()).unwrap())
                .collect();

            nix::unistd::execve(&program, &c_argv, &c_env)
                .with_context(|| format!("execve failed for {:?}", config.argv[0]))?;
            unreachable!()
        }
    }
}

/// Init shim: runs as PID 1, forwards signals, reaps zombies.
fn init_shim(child: Pid) -> Result<()> {
    // Wait for child, reaping any zombies
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::empty())) {
            Ok(WaitStatus::Exited(pid, code)) if pid == child => {
                std::process::exit(code);
            }
            Ok(WaitStatus::Signaled(pid, sig, _)) if pid == child => {
                std::process::exit(128 + sig as i32);
            }
            Ok(_) => {
                // Reaped a zombie that wasn't our direct child, continue
                continue;
            }
            Err(nix::errno::Errno::ECHILD) => {
                // No more children
                std::process::exit(0);
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                eprintln!("init shim waitpid error: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn parse_signal(name: &str) -> Signal {
    match name.trim_start_matches("SIG") {
        "QUIT" => Signal::SIGQUIT,
        "TERM" => Signal::SIGTERM,
        "INT" => Signal::SIGINT,
        "HUP" => Signal::SIGHUP,
        "USR1" => Signal::SIGUSR1,
        "USR2" => Signal::SIGUSR2,
        "KILL" => Signal::SIGKILL,
        _ => Signal::SIGTERM,
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ChildConfig {
    rootfs: String,
    argv: Vec<String>,
    env_vars: Vec<String>,
    workdir: String,
    container_id: String,
}
