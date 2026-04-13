use anyhow::{Context, Result};
use nix::{
    sys::{
        signal::{self, Signal},
        wait::{WaitStatus, waitpid},
    },
    unistd::{self, ForkResult, Pid},
};
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::process::CommandExt,
    },
};

pub(super) fn run_container(mut config: ChildConfig, stop_signal: &str) -> Result<i32> {
    if !config.rootless {
        super::cleanup::check_cgroup_v2()?;
        super::cleanup::cgroup_create(&config.container_id)?;
    }
    let has_ports = !config.port_mappings.is_empty();
    let (ready_read, ready_write) = if has_ports {
        let (r, w) = nix::unistd::pipe().context("failed to create ready pipe")?;
        (Some(r), Some(w))
    } else {
        (None, None)
    };
    let (read_fd, write_fd) = nix::unistd::pipe().context("failed to create pipe")?;
    let read_raw = read_fd.as_raw_fd();
    let write_raw = write_fd.into_raw_fd();
    config.ready_fd = ready_write.as_ref().map(|fd| fd.as_raw_fd());
    let fork_result = match unsafe { unistd::fork() } {
        Ok(r) => r,
        Err(e) => {
            let _ = nix::unistd::close(write_raw);
            return Err(e).context("fork failed");
        }
    };

    match fork_result {
        ForkResult::Parent { child } => {
            drop(read_fd);
            drop(ready_write);
            serde_json::to_writer(
                std::io::BufWriter::new(unsafe { std::fs::File::from_raw_fd(write_raw) }),
                &config,
            )?;
            if !config.rootless {
                super::cleanup::cgroup_add_pid(&config.container_id, child.as_raw() as u32)?;
            }
            let pasta_child = if has_ports {
                if let Some(ready_fd) = ready_read {
                    let _ = nix::unistd::read(&ready_fd, &mut [0u8; 1]);
                    drop(ready_fd);
                }
                Some(
                    super::spawn_pasta_for_pid(child.as_raw() as u32, &config.port_mappings)
                        .context("failed to start port forwarding")?,
                )
            } else {
                None
            };
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
            if let Some(mut pasta) = pasta_child {
                let _ = pasta.kill();
                let _ = pasta.wait();
            }
            Ok(exit_code)
        }
        ForkResult::Child => {
            nix::unistd::close(write_raw).context("failed to close config pipe write end")?;
            drop(ready_read);
            if let Some(rw) = ready_write {
                let _ = rw.into_raw_fd();
            }
            super::set_pdeathsig_with_race_check()?;
            let exe = super::resolve_self_exe()?;
            let exe_c = CString::new(exe.to_string_lossy().as_bytes())
                .context("current executable path contains NUL")?;
            let err = nix::unistd::execv(
                &exe_c,
                &[
                    exe_c.clone(),
                    CString::new("--container-init")?,
                    CString::new(read_raw.to_string())?,
                ],
            )
            .unwrap_err();
            eprintln!("execv failed: {err}");
            std::process::exit(127)
        }
    }
}

pub(crate) fn parent_wait(child: Pid, forward: impl Fn()) -> Result<i32> {
    for sig in [Signal::SIGINT, Signal::SIGTERM] {
        unsafe { signal::signal(sig, signal::SigHandler::Handler(note_pending_signal)) }
            .with_context(|| format!("failed to install {sig} handler"))?;
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
        .map(|v| {
            CString::new(v.as_str()).with_context(|| format!("{label} contains NUL byte: {v:?}"))
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
    pub volumes: Vec<super::super::VolumeMount>,
    pub network_mode: super::super::NetworkMode,
    pub port_mappings: Vec<super::super::PortMapping>,
    pub external_netns: bool,
    pub ready_fd: Option<i32>,
}

pub(super) fn run_rootless_unshare(spec: super::super::ContainerSpec) -> Result<i32> {
    let exe = super::resolve_self_exe()?;
    let has_ports = !spec.port_mappings.is_empty();
    let isolate_network = spec.network_mode == super::super::NetworkMode::None || has_ports;
    let (spec_read, spec_write) = nix::unistd::pipe().context("failed to create spec pipe")?;
    let (spec_read_raw, spec_write_raw) = (spec_read.into_raw_fd(), spec_write.as_raw_fd());
    let spec_read_str = spec_read_raw.to_string();
    let pre_exec_fn = move || unsafe {
        if nix::libc::setpgid(0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        super::set_pdeathsig()?;
        nix::libc::fcntl(spec_read_raw, nix::libc::F_SETFD, 0);
        nix::libc::close(spec_write_raw);
        Ok(())
    };

    let child = if has_ports {
        let mut cmd = std::process::Command::new(super::check_pasta()?);
        unsafe {
            cmd.pre_exec(pre_exec_fn);
        }
        cmd.args(["--config-net", "--quiet", "--foreground", "--no-map-gw"]);
        super::add_port_args(&mut cmd, &spec.port_mappings);
        cmd.args([
            "-u", "none", "-T", "none", "-U", "none", "--", "unshare", "--mount", "--uts", "--ipc",
            "--",
        ]);
        cmd.arg(&exe)
            .arg("--rootless-bootstrap")
            .arg(&spec_read_str);
        cmd.spawn().context("failed to execute pasta")?
    } else {
        let mut args = vec![
            "--user",
            "--map-root-user",
            "--map-auto",
            "--mount",
            "--uts",
            "--ipc",
        ];
        if isolate_network {
            args.push("--net");
        }
        args.push("--");
        let mut cmd = std::process::Command::new(
            super::super::which("unshare").context("unshare not found in PATH")?,
        );
        unsafe {
            cmd.pre_exec(pre_exec_fn);
        }
        cmd.args(&args)
            .arg(&exe)
            .arg("--rootless-bootstrap")
            .arg(&spec_read_str);
        cmd.spawn().context("failed to execute unshare")?
    };
    unsafe {
        nix::libc::close(spec_read_raw);
    }
    serde_json::to_writer(
        std::io::BufWriter::new(unsafe { std::fs::File::from_raw_fd(spec_write.into_raw_fd()) }),
        &spec,
    )
    .context("failed to send rootless bootstrap spec")?;

    let child_pid = Pid::from_raw(child.id() as i32);
    std::mem::forget(child);
    parent_wait(child_pid, || {
        let _ = unsafe { nix::libc::kill(-child_pid.as_raw(), nix::libc::SIGTERM) };
    })
    .context("failed to wait for unshare")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_cstrings_all_cases() {
        let r = to_cstrings(&["hello".into(), "world".into()], "t").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].to_bytes(), b"hello");
        assert!(to_cstrings(&[], "t").unwrap().is_empty());
        assert_eq!(to_cstrings(&["".into()], "t").unwrap()[0].to_bytes(), b"");
        // Special characters: paths, spaces, unicode, flags
        let inputs: Vec<String> = vec![
            "/usr/local/bin/my-tool".into(),
            "hello world".into(),
            "caf\u{00e9}".into(),
            "--flag=value".into(),
        ];
        let r = to_cstrings(&inputs, "args").unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!(r[0].to_str().unwrap(), "/usr/local/bin/my-tool");
        assert_eq!(r[3].to_str().unwrap(), "--flag=value");
        // NUL rejection with label in error
        assert!(to_cstrings(&["a\0b".into()], "t").is_err());
        let err = to_cstrings(&["bad\0value".into()], "my_label").unwrap_err();
        assert!(
            format!("{err:#}").contains("my_label"),
            "error should mention the label"
        );
    }
    #[test]
    fn child_config_serialisation_round_trip() {
        use crate::container::{NetworkMode, PortMapping, VolumeMount};
        let config = ChildConfig {
            rootfs: "/merged".into(),
            argv: vec!["/bin/sh".into(), "-c".into(), "echo hello".into()],
            env_vars: vec!["PATH=/usr/bin".into(), "HOME=/root".into()],
            workdir: "/app".into(),
            container_id: "abc123def456".into(),
            rootless: false,
            user: Some("1000:1000".into()),
            volumes: vec![VolumeMount {
                source: "/host/data".into(),
                target: "/data".into(),
                read_only: true,
            }],
            network_mode: NetworkMode::None,
            port_mappings: vec![PortMapping {
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".into(),
            }],
            external_netns: true,
            ready_fd: Some(5),
        };
        let back: ChildConfig =
            serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
        assert_eq!(back.rootfs, "/merged");
        assert_eq!(back.argv, vec!["/bin/sh", "-c", "echo hello"]);
        assert_eq!(back.container_id, "abc123def456");
        assert_eq!(back.user, Some("1000:1000".into()));
        assert_eq!(back.volumes.len(), 1);
        assert!(back.volumes[0].read_only);
        assert_eq!(back.port_mappings.len(), 1);
        assert_eq!(back.ready_fd, Some(5));
    }
    #[test]
    fn pending_signal_atomic_behaviour() {
        use std::sync::atomic::Ordering::SeqCst;
        PENDING_SIGNAL.store(0, SeqCst);
        assert_eq!(PENDING_SIGNAL.load(SeqCst), 0);
        note_pending_signal(0);
        assert_eq!(PENDING_SIGNAL.load(SeqCst), 1);
        assert_eq!(PENDING_SIGNAL.swap(0, SeqCst), 1);
        assert_eq!(PENDING_SIGNAL.load(SeqCst), 0);
    }
}
