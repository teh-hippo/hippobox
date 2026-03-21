use anyhow::{Context, Result, bail};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{self, ForkResult};
use std::ffi::CString;
use std::os::fd::FromRawFd;
use std::path::Path;

use super::process::{PENDING_SIGNAL, ChildConfig, note_pending_signal, to_cstrings};

pub fn container_init(config_fd: i32) -> Result<()> {
    let pipe_file = unsafe { std::fs::File::from_raw_fd(config_fd) };
    let mut config: ChildConfig = serde_json::from_reader(std::io::BufReader::new(pipe_file))?;

    // Create network namespace only if isolation is requested and not already
    // provided (pasta creates the netns externally for port-mapped containers).
    let needs_netns = config.network_mode == super::net::NetworkMode::None
        && !config.network_isolated;

    // Copy host files into rootfs before pivot (host /etc is still accessible).
    super::mounts::copy_host_files_to_rootfs(Path::new(&config.rootfs))?;

    super::namespaces::setup_namespaces_and_pivot(
        Path::new(&config.rootfs),
        config.rootless,
        &config.volumes,
        needs_netns,
    )?;

    // Bring up loopback when WE created the netns (not when pasta did —
    // pasta configures the full network including loopback and tap).
    if needs_netns {
        super::net::bring_up_loopback().context("failed to bring up loopback")?;
    }

    // Signal parent that netns is ready (for rootful pasta synchronisation).
    if let Some(fd) = config.ready_fd {
        let _ = nix::unistd::write(unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }, &[1u8]);
        let _ = nix::unistd::close(fd);
    }

    super::mounts::setup_container_mounts(config.rootless)?;

    let hostname = &config.container_id[..config.container_id.len().min(12)];
    nix::unistd::sethostname(hostname).context("failed to set hostname")?;

    // /etc exists in most images; skip the recursive walk of create_dir_all.
    if let Err(e) = std::fs::create_dir("/etc")
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(e).context("failed to create /etc");
    }
    // Write hosts file directly to avoid format! allocation.
    use std::io::Write;
    let mut f = std::fs::File::create("/etc/hosts").context("failed to create /etc/hosts")?;
    write!(f, "127.0.0.1\tlocalhost\n::1\tlocalhost\n127.0.0.1\t{hostname}\n")
        .context("failed to write /etc/hosts")?;

    // Create PID namespace so the container command runs as PID 1.
    // unshare(CLONE_NEWPID) affects children only, so we fork immediately
    // after — the child becomes PID 1 in the new namespace.
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWPID)
        .context("failed to create PID namespace")?;

    match unsafe { unistd::fork() }.context("PID namespace fork failed")? {
        ForkResult::Parent { child } => {
            // Intermediate: forward signals and propagate child's exit code.
            unsafe {
                signal::signal(Signal::SIGINT, signal::SigHandler::Handler(note_pending_signal))
                    .ok();
                signal::signal(Signal::SIGTERM, signal::SigHandler::Handler(note_pending_signal))
                    .ok();
            }
            loop {
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, code)) => std::process::exit(code),
                    Ok(WaitStatus::Signaled(_, sig, _)) => std::process::exit(128 + sig as i32),
                    Err(nix::errno::Errno::EINTR) => {
                        if PENDING_SIGNAL.swap(0, std::sync::atomic::Ordering::SeqCst) != 0 {
                            let _ = signal::kill(child, Signal::SIGTERM);
                        }
                        continue;
                    }
                    _ => std::process::exit(1),
                }
            }
        }
        ForkResult::Child => {
            // PID 1 in the new namespace. Re-arm death signal (cleared by fork)
            // with race check against intermediate parent.
            let ppid_before = nix::unistd::getppid();
            unsafe {
                nix::libc::prctl(
                    nix::libc::PR_SET_PDEATHSIG,
                    nix::libc::SIGTERM as nix::libc::c_ulong,
                    0, 0, 0,
                );
            }
            if nix::unistd::getppid() != ppid_before {
                std::process::exit(1);
            }
            // Mount fresh /proc for the new PID namespace view.
            let _ = std::fs::create_dir_all("/proc");
            nix::mount::mount(
                Some("proc"),
                "/proc",
                Some("proc"),
                nix::mount::MsFlags::MS_NOSUID
                    | nix::mount::MsFlags::MS_NODEV
                    | nix::mount::MsFlags::MS_NOEXEC,
                None::<&str>,
            )
            .context("failed to mount /proc in PID namespace")?;
            super::mounts::mask_proc_paths()?;
        }
    }

    if let Some(ref user_str) = config.user
        && let Some(home) = setup_user(user_str, config.rootless)?
    {
        // Update HOME in env_vars for the exec'd process.
        if let Some(existing) = config.env_vars.iter_mut().find(|v| {
            v.split_once('=').is_some_and(|(k, _)| k == "HOME")
        }) {
            *existing = format!("HOME={home}");
        } else {
            config.env_vars.push(format!("HOME={home}"));
        }
    }

    let prctl_ret = unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if prctl_ret != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set PR_SET_NO_NEW_PRIVS");
    }

    super::seccomp::apply_seccomp_filter()?;

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

/// Set up user/group identity. Returns the home directory if it should
/// override the default HOME in env_vars.
fn setup_user(user_str: &str, rootless: bool) -> Result<Option<String>> {
    if rootless {
        eprintln!("warning: USER directive ignored in rootless mode ({user_str})");
        return Ok(None);
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

    let home = passwd_field_by_uid(uid, 5).unwrap_or_else(|| {
        if uid == 0 { "/root".to_string() } else { "/".to_string() }
    });
    Ok(Some(home))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_name_to_id_finds_match() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(
            &mut std::fs::File::create(tmp.path()).unwrap(),
            b"root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n",
        ).unwrap();

        let result = resolve_name_to_id(tmp.path().to_str().unwrap(), 0, 2, "nobody").unwrap();
        assert_eq!(result, 65534);
    }

    #[test]
    fn resolve_name_to_id_not_found() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(
            &mut std::fs::File::create(tmp.path()).unwrap(),
            b"root:x:0:0:root:/root:/bin/bash\n",
        ).unwrap();

        assert!(resolve_name_to_id(tmp.path().to_str().unwrap(), 0, 2, "nonexistent").is_err());
    }
}
