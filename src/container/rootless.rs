use anyhow::{Context, Result};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicU8, Ordering};

pub(super) fn run_rootless_unshare(spec: super::ContainerSpec) -> Result<i32> {
    let exe = super::resolve_self_exe()?;

    let has_ports = !spec.port_mappings.is_empty();
    let isolate_network = spec.network_mode == super::net::NetworkMode::None || has_ports;

    if has_ports {
        super::net::check_pasta()?;
    }

    // Pass the spec over a dedicated pipe so stdin stays connected to the
    // terminal/caller for the container process (needed by MCP stdio, etc).
    let (spec_read, spec_write) = nix::unistd::pipe().context("failed to create spec pipe")?;
    let spec_read_raw = spec_read.into_raw_fd();
    let spec_write_raw = spec_write.as_raw_fd();
    let spec_read_str = spec_read_raw.to_string();

    let pre_exec_fn = move || unsafe {
        if nix::libc::setpgid(0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        let ret = nix::libc::prctl(
            nix::libc::PR_SET_PDEATHSIG,
            nix::libc::SIGTERM as nix::libc::c_ulong,
            0, 0, 0,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        // Ensure the spec pipe read fd survives across exec.
        nix::libc::fcntl(spec_read_raw, nix::libc::F_SETFD, 0);
        // Close write end so the child doesn't keep it open (would prevent EOF).
        nix::libc::close(spec_write_raw);
        Ok(())
    };

    let child = if has_ports {
        // pasta wraps the process: creates user+net namespace from the HOST,
        // binds host ports for forwarding, then runs unshare inside for
        // mount/uts/ipc isolation. pasta's user namespace has single-UID
        // mapping (0→real_uid) which is sufficient for most containers.
        let pasta_path = super::net::check_pasta()?;
        let mut cmd = Command::new(pasta_path);
        unsafe { cmd.pre_exec(pre_exec_fn); }
        cmd.args(["--config-net", "--quiet", "--foreground", "--no-map-gw"]);
        super::net::add_port_args(&mut cmd, &spec.port_mappings);
        cmd.args(["-u", "none", "-T", "none", "-U", "none"]);
        cmd.args(["--", "unshare", "--mount", "--uts", "--ipc", "--"]);
        cmd.arg(&exe).arg("--rootless-bootstrap").arg(&spec_read_str);
        cmd.spawn()
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
        let unshare_path = super::net::which("unshare")
            .context("unshare not found in PATH")?;
        let mut cmd = Command::new(unshare_path);
        unsafe { cmd.pre_exec(pre_exec_fn); }
        cmd.args(&unshare_args).arg(&exe).arg("--rootless-bootstrap").arg(&spec_read_str);
        cmd.spawn()
            .context("failed to execute unshare")?
    };

    // Close read end in parent, write spec to the pipe, then close write end.
    unsafe { nix::libc::close(spec_read_raw); }
    {
        let pipe_file = unsafe { std::fs::File::from_raw_fd(spec_write.into_raw_fd()) };
        let mut writer = std::io::BufWriter::new(pipe_file);
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
