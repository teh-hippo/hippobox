use anyhow::{Context, Result};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{self, ForkResult, Pid};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

pub(super) fn run_container(mut config: ChildConfig, stop_signal: &str) -> Result<i32> {
    if !config.rootless {
        super::cgroups::check_cgroup_v2()?;
        super::cgroups::create(&config.container_id)?;
    }

    let has_ports = !config.port_mappings.is_empty();

    // Ready pipe: child signals parent when netns is ready (for pasta).
    let (ready_read, ready_write) = if has_ports {
        let (r, w) = nix::unistd::pipe().context("failed to create ready pipe")?;
        (Some(r), Some(w))
    } else {
        (None, None)
    };

    let (read_fd, write_fd) = nix::unistd::pipe().context("failed to create pipe")?;
    let read_raw = read_fd.as_raw_fd();
    let write_raw = write_fd.into_raw_fd();

    // Store the ready write fd in config so the child can signal us.
    config.ready_fd = ready_write.as_ref().map(|fd| fd.as_raw_fd());

    let fork_result = unsafe { unistd::fork() };
    // If fork fails, close the leaked write_raw fd before propagating.
    let fork_result = match fork_result {
        Ok(result) => result,
        Err(e) => {
            let _ = nix::unistd::close(write_raw);
            return Err(e).context("fork failed");
        }
    };

    match fork_result {
        ForkResult::Parent { child } => {
            drop(read_fd);
            drop(ready_write);

            let pipe_file = unsafe { std::fs::File::from_raw_fd(write_raw) };
            let mut pipe_write = std::io::BufWriter::new(pipe_file);
            serde_json::to_writer(&mut pipe_write, &config)?;
            drop(pipe_write);

            if !config.rootless {
                super::cgroups::add_pid(&config.container_id, child.as_raw() as u32)?;
            }

            // Wait for child to signal netns ready, then start pasta.
            let mut pasta_child = None;
            if has_ports {
                if let Some(ready_fd) = ready_read {
                    let mut buf = [0u8; 1];
                    let _ = nix::unistd::read(&ready_fd, &mut buf);
                    drop(ready_fd);
                }
                pasta_child = Some(
                    super::net::spawn_pasta_for_pid(child.as_raw() as u32, &config.port_mappings)
                        .context("failed to start port forwarding")?,
                );
            }

            let stop_signal = match stop_signal.trim_start_matches("SIG") {
                "QUIT" => Signal::SIGQUIT,
                "INT" => Signal::SIGINT,
                "HUP" => Signal::SIGHUP,
                "USR1" => Signal::SIGUSR1,
                "USR2" => Signal::SIGUSR2,
                "KILL" => Signal::SIGKILL,
                _ => Signal::SIGTERM,
            };
            let exit_code = parent_wait(child, || {
                let _ = signal::kill(child, stop_signal);
            })?;

            // Clean up pasta on container exit.
            if let Some(mut pasta) = pasta_child {
                let _ = pasta.kill();
                let _ = pasta.wait();
            }

            Ok(exit_code)
        }
        ForkResult::Child => {
            nix::unistd::close(write_raw).context("failed to close config pipe write end")?;
            // Close ready pipe fds in child — they're only needed by the parent.
            // pipe() doesn't set CLOEXEC, so these would leak across execv.
            drop(ready_read);
            if let Some(rw) = ready_write {
                // Keep the raw fd alive for container_init (stored in config.ready_fd)
                // but relinquish Rust ownership so Drop doesn't close it.
                let _ = rw.into_raw_fd();
            }

            super::set_pdeathsig_with_race_check()?;

            let exe = super::resolve_self_exe()?;
            let exe_c = CString::new(exe.to_string_lossy().as_bytes())
                .context("current executable path contains NUL")?;
            let arg_init = CString::new("--container-init")?;
            let arg_fd = CString::new(read_raw.to_string())?;

            let err = nix::unistd::execv(&exe_c, &[exe_c.clone(), arg_init, arg_fd]).unwrap_err();
            // Don't bail!/return here — unwinding would run CleanupGuard::drop
            // in this child process while the parent is still waiting.
            eprintln!("execv failed: {err}");
            std::process::exit(127)
        }
    }
}

pub(crate) fn parent_wait(child: Pid, forward: impl Fn()) -> Result<i32> {
    unsafe {
        signal::signal(
            Signal::SIGINT,
            signal::SigHandler::Handler(note_pending_signal),
        )
        .context("failed to install SIGINT handler")?;
        signal::signal(
            Signal::SIGTERM,
            signal::SigHandler::Handler(note_pending_signal),
        )
        .context("failed to install SIGTERM handler")?;
    }

    loop {
        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(128 + sig as i32),
            Err(nix::errno::Errno::EINTR) => {
                if PENDING_SIGNAL.swap(0, std::sync::atomic::Ordering::SeqCst) != 0 {
                    forward();
                }
            }
            Err(err) => return Err(err.into()),
            _ => continue,
        }
    }
}

pub(super) static PENDING_SIGNAL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

pub(super) extern "C" fn note_pending_signal(_: nix::libc::c_int) {
    PENDING_SIGNAL.store(1, std::sync::atomic::Ordering::SeqCst);
}


pub(super) fn to_cstrings(values: &[String], label: &str) -> Result<Vec<CString>> {
    values
        .iter()
        .map(|value| {
            CString::new(value.as_str())
                .with_context(|| format!("{label} contains NUL byte: {value:?}"))
        })
        .collect()
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct ChildConfig {
    pub rootfs: String,
    pub argv: Vec<String>,
    pub env_vars: Vec<String>,
    pub workdir: String,
    pub container_id: String,
    pub rootless: bool,
    pub user: Option<String>,
    pub volumes: Vec<super::VolumeMount>,
    pub network_mode: super::net::NetworkMode,
    pub port_mappings: Vec<super::net::PortMapping>,
    pub external_netns: bool,
    pub ready_fd: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_cstrings_basic() {
        let input = vec!["hello".to_string(), "world".to_string()];
        let result = to_cstrings(&input, "test").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].to_bytes(), b"hello");
        assert_eq!(result[1].to_bytes(), b"world");
    }

    #[test]
    fn to_cstrings_empty() {
        let result = to_cstrings(&[], "test").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn to_cstrings_rejects_nul() {
        let input = vec!["hello\0world".to_string()];
        assert!(to_cstrings(&input, "test").is_err());
    }

    #[test]
    fn to_cstrings_empty_string() {
        let input = vec!["".to_string()];
        let result = to_cstrings(&input, "test").unwrap();
        assert_eq!(result[0].to_bytes(), b"");
    }
}
