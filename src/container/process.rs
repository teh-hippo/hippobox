use anyhow::{Context, Result, bail};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{self, ForkResult, Pid};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::path::Path;

pub fn run_container(config: ChildConfig, stop_signal: &str) -> Result<i32> {
    if !config.rootless {
        super::cgroups::check_cgroup_v2()?;
        super::cgroups::create(&config.container_id)?;
    }
    super::mounts::copy_host_files_to_rootfs(Path::new(&config.rootfs))?;

    let (read_fd, write_fd) = nix::unistd::pipe().context("failed to create pipe")?;
    let read_raw = read_fd.as_raw_fd();
    let write_raw = write_fd.into_raw_fd();

    match unsafe { unistd::fork() }.context("fork failed")? {
        ForkResult::Parent { child } => {
            drop(read_fd);

            let mut pipe_write = unsafe { std::fs::File::from_raw_fd(write_raw) };
            serde_json::to_writer(&mut pipe_write, &config)?;
            drop(pipe_write);

            if !config.rootless {
                super::cgroups::add_pid(&config.container_id, child.as_raw() as u32)?;
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
            parent_wait(child, stop_signal)
        }
        ForkResult::Child => {
            nix::unistd::close(write_raw).context("failed to close config pipe write end")?;

            let ppid_before = nix::unistd::getppid();
            let prctl_ret = unsafe {
                nix::libc::prctl(
                    nix::libc::PR_SET_PDEATHSIG,
                    nix::libc::SIGTERM as nix::libc::c_ulong,
                    0,
                    0,
                    0,
                )
            };
            if prctl_ret != 0 {
                bail!(
                    "failed to set PR_SET_PDEATHSIG: {}",
                    std::io::Error::last_os_error()
                );
            }
            if nix::unistd::getppid() != ppid_before {
                std::process::exit(1);
            }

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

    std::fs::create_dir_all("/etc").context("failed to create /etc")?;
    std::fs::write(
        "/etc/hosts",
        format!("127.0.0.1\tlocalhost\n::1\tlocalhost\n127.0.0.1\t{hostname}\n"),
    )
    .context("failed to write /etc/hosts")?;

    if let Some(ref user_str) = config.user {
        setup_user(user_str, config.rootless)?;
    }

    let prctl_ret = unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if prctl_ret != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set PR_SET_NO_NEW_PRIVS");
    }

    if !config.workdir.is_empty() && config.workdir != "/" {
        std::env::set_current_dir(&config.workdir)
            .with_context(|| format!("failed to chdir to {}", config.workdir))?;
    }

    let program = CString::new(
        config
            .argv
            .first()
            .context("empty argv in child config")?
            .as_str(),
    )
    .context("program contains NUL")?;
    let c_argv = to_cstrings(&config.argv, "argv")?;
    let c_env = to_cstrings(&config.env_vars, "env")?;

    let err = nix::unistd::execvpe(&program, &c_argv, &c_env)
        .expect_err("execvpe unexpectedly returned success");
    bail!("execvpe failed for {:?}: {err}", config.argv[0])
}

fn to_cstrings(values: &[String], label: &str) -> Result<Vec<CString>> {
    values
        .iter()
        .map(|value| {
            CString::new(value.as_str())
                .with_context(|| format!("{label} contains NUL byte: {value:?}"))
        })
        .collect()
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ChildConfig {
    pub rootfs: String,
    pub argv: Vec<String>,
    pub env_vars: Vec<String>,
    pub workdir: String,
    pub container_id: String,
    pub rootless: bool,
    pub user: Option<String>,
}

fn setup_user(user_str: &str, rootless: bool) -> Result<()> {
    if rootless {
        eprintln!("warning: USER directive ignored in rootless mode ({user_str})");
        return Ok(());
    }

    let (uid, gid) = match user_str.split_once(':') {
        Some((u, g)) => (resolve_uid(u)?, resolve_gid(g)?),
        None => {
            let uid = resolve_uid(user_str)?;
            // When no group specified, look up the user's primary group from /etc/passwd.
            let gid = passwd_field_by_uid(uid, 3)
                .and_then(|g| g.parse::<u32>().ok())
                .unwrap_or(uid);
            (uid, gid)
        }
    };

    nix::unistd::setgroups(&[nix::unistd::Gid::from_raw(gid)])
        .context("failed to set supplementary groups")?;
    nix::unistd::setgid(nix::unistd::Gid::from_raw(gid))
        .context("failed to setgid")?;
    nix::unistd::setuid(nix::unistd::Uid::from_raw(uid))
        .context("failed to setuid")?;

    if uid != 0
        && let Some(home) = passwd_field_by_uid(uid, 5)
    {
        // Safe: we're single-threaded in the container init process before exec.
        unsafe { std::env::set_var("HOME", home) };
    }
    Ok(())
}

fn resolve_uid(s: &str) -> Result<u32> {
    if let Ok(uid) = s.parse::<u32>() {
        return Ok(uid);
    }
    resolve_name_to_id("/etc/passwd", 0, 2, s)
        .with_context(|| format!("user not found in /etc/passwd: {s}"))
}

fn resolve_gid(s: &str) -> Result<u32> {
    if let Ok(gid) = s.parse::<u32>() {
        return Ok(gid);
    }
    resolve_name_to_id("/etc/group", 0, 2, s)
        .with_context(|| format!("group not found in /etc/group: {s}"))
}

/// Look up a field by name match in a colon-separated file (passwd/group).
fn resolve_name_to_id(path: &str, name_col: usize, id_col: usize, name: &str) -> Result<u32> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {path}"))?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() > id_col && fields[name_col] == name {
            return fields[id_col]
                .parse::<u32>()
                .with_context(|| format!("invalid id in {path} for {name}"));
        }
    }
    bail!("name {name:?} not found in {path}")
}

/// Look up fields from /etc/passwd by UID match.
fn passwd_field_by_uid(uid: u32, field_idx: usize) -> Option<String> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    content.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.len() > field_idx && fields[2].parse::<u32>().ok() == Some(uid))
            .then(|| fields[field_idx].to_string())
    })
}
