use anyhow::{Context, Result};
use nix::unistd::Pid;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

pub(super) fn run_rootless_unshare(spec: super::ContainerSpec) -> Result<i32> {
    let exe = super::resolve_self_exe()?;
    let has_ports = !spec.port_mappings.is_empty();
    let isolate_network = spec.network_mode == super::net::NetworkMode::None || has_ports;

    let (spec_read, spec_write) = nix::unistd::pipe().context("failed to create spec pipe")?;
    let spec_read_raw = spec_read.into_raw_fd();
    let spec_write_raw = spec_write.as_raw_fd();
    let spec_read_str = spec_read_raw.to_string();

    let pre_exec_fn = move || unsafe {
        if nix::libc::setpgid(0, 0) != 0 { return Err(io::Error::last_os_error()); }
        super::set_pdeathsig()?;
        nix::libc::fcntl(spec_read_raw, nix::libc::F_SETFD, 0);
        nix::libc::close(spec_write_raw);
        Ok(())
    };

    let child = if has_ports {
        let pasta_path = super::net::check_pasta()?;
        let mut cmd = Command::new(pasta_path);
        unsafe { cmd.pre_exec(pre_exec_fn); }
        cmd.args(["--config-net", "--quiet", "--foreground", "--no-map-gw"]);
        super::net::add_port_args(&mut cmd, &spec.port_mappings);
        cmd.args(["-u", "none", "-T", "none", "-U", "none"]);
        cmd.args(["--", "unshare", "--mount", "--uts", "--ipc", "--"]);
        cmd.arg(&exe).arg("--rootless-bootstrap").arg(&spec_read_str);
        cmd.spawn().context("failed to execute pasta")?
    } else {
        let mut unshare_args = vec!["--user", "--map-root-user", "--map-auto", "--mount", "--uts", "--ipc"];
        if isolate_network { unshare_args.push("--net"); }
        unshare_args.push("--");
        let unshare_path = super::net::which("unshare").context("unshare not found in PATH")?;
        let mut cmd = Command::new(unshare_path);
        unsafe { cmd.pre_exec(pre_exec_fn); }
        cmd.args(&unshare_args).arg(&exe).arg("--rootless-bootstrap").arg(&spec_read_str);
        cmd.spawn().context("failed to execute unshare")?
    };

    unsafe { nix::libc::close(spec_read_raw); }
    {
        let pipe_file = unsafe { std::fs::File::from_raw_fd(spec_write.into_raw_fd()) };
        serde_json::to_writer(std::io::BufWriter::new(pipe_file), &spec)
            .context("failed to send rootless bootstrap spec")?;
    }

    let child_pid = Pid::from_raw(child.id() as i32);
    std::mem::forget(child);
    super::process::parent_wait(child_pid, || {
        let _ = unsafe { nix::libc::kill(-child_pid.as_raw(), nix::libc::SIGTERM) };
    }).context("failed to wait for unshare")
}
