use anyhow::{Context, Result, bail};
use nix::sys::signal::{self, Signal};
use nix::unistd::{self, ForkResult};
use std::ffi::CString;
use std::os::fd::FromRawFd;
use std::path::Path;

use super::process::{ChildConfig, to_cstrings};

pub fn container_init(config_fd: i32) -> Result<()> {
    let pipe_file = unsafe { std::fs::File::from_raw_fd(config_fd) };
    let mut config: ChildConfig = serde_json::from_reader(std::io::BufReader::new(pipe_file))?;

    let needs_netns = config.network_mode == super::net::NetworkMode::None && !config.external_netns;

    super::mounts::copy_host_files_to_rootfs(Path::new(&config.rootfs))?;
    super::namespaces::setup_namespaces_and_pivot(
        Path::new(&config.rootfs), config.rootless, &config.volumes, needs_netns,
    )?;

    if needs_netns {
        super::net::bring_up_loopback().context("failed to bring up loopback")?;
    }
    if let Some(fd) = config.ready_fd {
        let _ = nix::unistd::write(unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }, &[1u8]);
        let _ = nix::unistd::close(fd);
    }

    super::mounts::setup_container_mounts(config.rootless)?;

    let hostname = &config.container_id[..config.container_id.len().min(12)];
    nix::unistd::sethostname(hostname).context("failed to set hostname")?;
    if let Err(e) = std::fs::create_dir("/etc")
        && e.kind() != std::io::ErrorKind::AlreadyExists
    { return Err(e).context("failed to create /etc"); }

    use std::io::Write;
    let mut f = std::fs::File::create("/etc/hosts").context("failed to create /etc/hosts")?;
    write!(f, "127.0.0.1\tlocalhost\n::1\tlocalhost\n127.0.0.1\t{hostname}\n")
        .context("failed to write /etc/hosts")?;

    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWPID)
        .context("failed to create PID namespace")?;

    match unsafe { unistd::fork() }.context("PID namespace fork failed")? {
        ForkResult::Parent { child } => {
            let code = super::process::parent_wait(child, || {
                let _ = signal::kill(child, Signal::SIGTERM);
            }).unwrap_or(1);
            std::process::exit(code);
        }
        ForkResult::Child => {
            super::set_pdeathsig_with_race_check()?;
            super::mounts::mount_fs("/proc", "proc", "proc",
                nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV | nix::mount::MsFlags::MS_NOEXEC,
                None::<&str>, "failed to mount /proc in PID namespace")?;
            super::mounts::mask_proc_paths()?;
        }
    }

    if let Some(ref user_str) = config.user
        && let Some(home) = setup_user(user_str, config.rootless)?
    {
        if let Some(existing) = super::env_find_mut(&mut config.env_vars, "HOME") {
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

    let program = CString::new(config.argv.first().context("empty argv in child config")?.as_str())
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
        Some((u, g)) => (resolve_id(u, "/etc/passwd", "user")?, resolve_id(g, "/etc/group", "group")?),
        None => {
            let uid = resolve_id(user_str, "/etc/passwd", "user")?;
            let gid = passwd_field_by_uid(uid, 3).and_then(|g| g.parse().ok()).unwrap_or(uid);
            (uid, gid)
        }
    };
    let gid = nix::unistd::Gid::from_raw(gid);
    nix::unistd::setgroups(&[gid]).context("failed to set supplementary groups")?;
    nix::unistd::setgid(gid).context("failed to setgid")?;
    nix::unistd::setuid(nix::unistd::Uid::from_raw(uid)).context("failed to setuid")?;
    Ok(Some(passwd_field_by_uid(uid, 5).unwrap_or_else(|| {
        if uid == 0 { "/root".into() } else { "/".into() }
    })))
}

fn resolve_id(s: &str, file: &str, label: &str) -> Result<u32> {
    s.parse::<u32>().or_else(|_| {
        let content = std::fs::read_to_string(file).with_context(|| format!("failed to read {file}"))?;
        content.lines().find_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            (f.len() > 2 && f[0] == s).then(|| f[2].parse::<u32>().ok()).flatten()
        }).with_context(|| format!("{label} not found in {file}: {s}"))
    })
}

fn passwd_field_by_uid(uid: u32, idx: usize) -> Option<String> {
    std::fs::read_to_string("/etc/passwd").ok()?.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        (f.len() > idx && f[2].parse::<u32>().ok() == Some(uid)).then(|| f[idx].to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_id_numeric_and_named() {
        assert_eq!(resolve_id("0", "/etc/passwd", "user").unwrap(), 0);
        assert_eq!(resolve_id("65534", "/etc/group", "group").unwrap(), 65534);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(
            &mut std::fs::File::create(tmp.path()).unwrap(),
            b"root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n",
        ).unwrap();
        let path = tmp.path().to_str().unwrap();
        assert_eq!(resolve_id("nobody", path, "user").unwrap(), 65534);
        assert!(resolve_id("nonexistent", path, "user").is_err());
    }
}
