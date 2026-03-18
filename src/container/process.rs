use anyhow::{bail, Context, Result};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{self, ForkResult, Pid};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::path::Path;

use crate::registry::manifest::ContainerConfig;

pub fn build_command(
    config: Option<&ContainerConfig>,
    user_cmd: &[String],
    user_env: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    let entrypoint = non_empty(config.and_then(|c| c.entrypoint.as_ref()));
    let cmd = non_empty(config.and_then(|c| c.cmd.as_ref()));

    let argv = if !user_cmd.is_empty() {
        match entrypoint {
            Some(ep) => {
                let mut argv = ep.to_vec();
                argv.extend(user_cmd.iter().cloned());
                argv
            }
            None => user_cmd.to_vec(),
        }
    } else {
        match (entrypoint, cmd) {
            (Some(ep), Some(cmd)) => {
                let mut argv = ep.to_vec();
                argv.extend(cmd.iter().cloned());
                argv
            }
            (Some(ep), None) => ep.to_vec(),
            (None, Some(cmd)) => cmd.to_vec(),
            (None, None) => bail!("no CMD or ENTRYPOINT in image config and no command provided"),
        }
    };

    if argv.is_empty() {
        bail!("resolved command is empty");
    }

    let env_vars = config
        .and_then(|c| c.env.as_ref())
        .filter(|vars| !vars.is_empty())
        .cloned()
        .unwrap_or_else(|| {
            vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()]
        });
    let env_vars = merge_env_vars(env_vars, user_env)?;

    Ok((argv, env_vars))
}

fn merge_env_vars(mut env_vars: Vec<String>, overrides: &[String]) -> Result<Vec<String>> {
    for override_var in overrides {
        let key = env_key(override_var)?;
        if let Some(existing) = env_vars.iter_mut().find(|value| env_key_matches(value, key)) {
            *existing = override_var.clone();
        } else {
            env_vars.push(override_var.clone());
        }
    }

    Ok(env_vars)
}

fn env_key_matches(value: &str, key: &str) -> bool {
    value.split_once('=').map(|(existing, _)| existing == key).unwrap_or(false)
}

fn env_key(value: &str) -> Result<&str> {
    let Some((key, _)) = value.split_once('=') else {
        bail!("invalid environment override {value:?}, expected KEY=VALUE");
    };
    if key.is_empty() {
        bail!("invalid environment override {value:?}, empty key");
    }
    Ok(key)
}

pub fn run_container(
    container_id: &str,
    rootfs: &Path,
    argv: &[String],
    env_vars: &[String],
    workdir: &str,
    stop_signal: &str,
    rootless: bool,
) -> Result<i32> {
    if !rootless {
        super::cgroups::check_cgroup_v2()?;
        super::cgroups::create(container_id)?;
    }
    super::mounts::copy_host_files_to_rootfs(rootfs)?;

    let (read_fd, write_fd) = nix::unistd::pipe().context("failed to create pipe")?;
    let read_raw = read_fd.as_raw_fd();
    let write_raw = write_fd.into_raw_fd();

    match unsafe { unistd::fork() }.context("fork failed")? {
        ForkResult::Parent { child } => {
            drop(read_fd);

            let config = ChildConfig {
                rootfs: rootfs.to_string_lossy().to_string(),
                argv: argv.to_vec(),
                env_vars: env_vars.to_vec(),
                workdir: workdir.to_string(),
                container_id: container_id.to_string(),
                rootless,
            };
            let mut pipe_write = unsafe { std::fs::File::from_raw_fd(write_raw) };
            serde_json::to_writer(&mut pipe_write, &config)?;
            drop(pipe_write);

            if !rootless {
                super::cgroups::add_pid(container_id, child.as_raw() as u32)?;
            }
            parent_wait(child, parse_signal(stop_signal))
        }
        ForkResult::Child => {
            nix::unistd::close(write_raw).context("failed to close config pipe write end")?;

            let exe = std::fs::read_link("/proc/self/exe")
                .or_else(|_| std::env::current_exe())
                .context("failed to locate current executable")?;
            let exe_c = CString::new(exe.to_string_lossy().as_bytes())
                .context("current executable path contains NUL")?;
            let arg_init = CString::new("--container-init")?;
            let arg_fd = CString::new(read_raw.to_string())?;

            let err = nix::unistd::execv(&exe_c, &[exe_c.clone(), arg_init, arg_fd]).unwrap_err();
            bail!("execv failed: {err}")
        }
    }
}

pub(crate) fn parent_wait(child: Pid, stop_signal: Signal) -> Result<i32> {
    unsafe {
        signal::signal(Signal::SIGINT, signal::SigHandler::Handler(note_pending_signal))
            .context("failed to install SIGINT handler")?;
        signal::signal(Signal::SIGTERM, signal::SigHandler::Handler(note_pending_signal))
            .context("failed to install SIGTERM handler")?;
    }

    loop {
        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(128 + sig as i32),
            Err(nix::errno::Errno::EINTR) => {
                if PENDING_SIGNAL.swap(0, std::sync::atomic::Ordering::SeqCst) != 0 {
                    let _ = signal::kill(child, stop_signal);
                }
            }
            Err(err) => return Err(err.into()),
            _ => continue,
        }
    }
}

static PENDING_SIGNAL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

extern "C" fn note_pending_signal(_: nix::libc::c_int) {
    PENDING_SIGNAL.store(1, std::sync::atomic::Ordering::SeqCst);
}

pub fn container_init(config_fd: i32) -> Result<()> {
    let pipe_read = unsafe { std::fs::File::from_raw_fd(config_fd) };
    let config: ChildConfig = serde_json::from_reader(pipe_read)?;

    super::namespaces::setup_namespaces_and_pivot(Path::new(&config.rootfs), config.rootless)?;
    super::mounts::setup_container_mounts(config.rootless)?;

    let hostname = &config.container_id[..config.container_id.len().min(12)];
    nix::unistd::sethostname(hostname).context("failed to set hostname")?;

    let prctl_ret = unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if prctl_ret != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set PR_SET_NO_NEW_PRIVS");
    }

    if !config.workdir.is_empty() && config.workdir != "/" {
        std::env::set_current_dir(&config.workdir)
            .with_context(|| format!("failed to chdir to {}", config.workdir))?;
    }

    let program = CString::new(config.argv.first().context("empty argv in child config")?.as_str())
        .context("program contains NUL")?;
    let c_argv = to_cstrings(&config.argv, "argv")?;
    let c_env = to_cstrings(&config.env_vars, "env")?;

    let err = nix::unistd::execvpe(&program, &c_argv, &c_env)
        .expect_err("execvpe unexpectedly returned success");
    bail!("execvpe failed for {:?}: {err}", config.argv[0])
}

pub(crate) fn parse_signal(name: &str) -> Signal {
    match name.trim_start_matches("SIG") {
        "QUIT" => Signal::SIGQUIT,
        "INT" => Signal::SIGINT,
        "HUP" => Signal::SIGHUP,
        "USR1" => Signal::SIGUSR1,
        "USR2" => Signal::SIGUSR2,
        "KILL" => Signal::SIGKILL,
        _ => Signal::SIGTERM,
    }
}

fn non_empty(value: Option<&Vec<String>>) -> Option<&[String]> {
    value.filter(|items| !items.is_empty()).map(Vec::as_slice)
}

fn to_cstrings(values: &[String], label: &str) -> Result<Vec<CString>> {
    values
        .iter()
        .map(|value| CString::new(value.as_str()).with_context(|| format!("{label} contains NUL byte: {value:?}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(env: Option<Vec<String>>) -> ContainerConfig {
        ContainerConfig {
            cmd: Some(vec!["redis-server".to_string()]),
            entrypoint: None,
            env,
            working_dir: None,
            user: None,
            stop_signal: None,
            exposed_ports: None,
            volumes: None,
        }
    }

    #[test]
    fn env_overrides_replace_image_values() {
        let cfg = config(Some(vec![
            "PATH=/usr/local/bin".to_string(),
            "FOO=bar".to_string(),
        ]));

        let (_, env_vars) = build_command(
            Some(&cfg),
            &[],
            &[
                "FOO=baz".to_string(),
                "POSTGRES_HOST_AUTH_METHOD=trust".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(
            env_vars,
            vec![
                "PATH=/usr/local/bin".to_string(),
                "FOO=baz".to_string(),
                "POSTGRES_HOST_AUTH_METHOD=trust".to_string(),
            ],
        );
    }

    #[test]
    fn invalid_env_overrides_fail_fast() {
        let cfg = config(None);
        let err = build_command(Some(&cfg), &[], &["INVALID".to_string()]).unwrap_err();
        assert!(err.to_string().contains("expected KEY=VALUE"));
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ChildConfig {
    rootfs: String,
    argv: Vec<String>,
    env_vars: Vec<String>,
    workdir: String,
    container_id: String,
    rootless: bool,
}
