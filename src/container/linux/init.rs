use anyhow::{Context, Result, bail};
use nix::{
    mount::MsFlags,
    sys::signal::{self, Signal},
    unistd::{self, ForkResult},
};
use std::{ffi::CString, os::fd::FromRawFd, path::Path};

use super::process::{ChildConfig, to_cstrings};

pub fn container_init(config_fd: i32) -> Result<()> {
    let pipe_file = unsafe { std::fs::File::from_raw_fd(config_fd) };
    let mut config: ChildConfig = serde_json::from_reader(std::io::BufReader::new(pipe_file))?;
    let needs_netns =
        config.network_mode == super::super::NetworkMode::None && !config.external_netns;
    super::mounts::copy_host_files_to_rootfs(Path::new(&config.rootfs))?;
    setup_namespaces_and_pivot(
        Path::new(&config.rootfs),
        config.rootless,
        &config.volumes,
        needs_netns,
    )?;
    if needs_netns {
        super::bring_up_loopback().context("failed to bring up loopback")?;
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
    {
        return Err(e).context("failed to create /etc");
    }
    std::fs::write(
        "/etc/hosts",
        format!("127.0.0.1\tlocalhost\n::1\tlocalhost\n127.0.0.1\t{hostname}\n"),
    )
    .context("failed to write /etc/hosts")?;
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWPID)
        .context("failed to create PID namespace")?;
    match unsafe { unistd::fork() }.context("PID namespace fork failed")? {
        ForkResult::Parent { child } => {
            let code = super::process::parent_wait(child, || {
                let _ = signal::kill(child, Signal::SIGTERM);
            })
            .unwrap_or(1);
            std::process::exit(code);
        }
        ForkResult::Child => {
            super::set_pdeathsig_with_race_check()?;
            super::mounts::mount_fs(
                "/proc",
                "proc",
                "proc",
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                None::<&str>,
                "failed to mount /proc in PID namespace",
            )?;
            super::mounts::mask_proc_paths()?;
        }
    }
    if let Some(ref user_str) = config.user
        && let Some(home) = setup_user(user_str, config.rootless)?
    {
        let entry = format!("HOME={home}");
        match super::super::env_find_mut(&mut config.env_vars, "HOME") {
            Some(e) => *e = entry,
            None => config.env_vars.push(entry),
        }
    }

    let ret = unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set PR_SET_NO_NEW_PRIVS");
    }
    apply_seccomp_filter()?;
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
    let (c_argv, c_env) = (
        to_cstrings(&config.argv, "argv")?,
        to_cstrings(&config.env_vars, "env")?,
    );
    let err = nix::unistd::execvpe(&program, &c_argv, &c_env)
        .expect_err("execvpe unexpectedly returned success");
    bail!("execvpe failed for {:?}: {err}", config.argv[0])
}

fn setup_user(user_str: &str, rootless: bool) -> Result<Option<String>> {
    if rootless {
        eprintln!("warning: USER directive ignored in rootless mode ({user_str})");
        return Ok(None);
    }
    let (uid, gid) = match user_str.split_once(':') {
        Some((u, g)) => (
            resolve_id(u, "/etc/passwd", "user")?,
            resolve_id(g, "/etc/group", "group")?,
        ),
        None => {
            let uid = resolve_id(user_str, "/etc/passwd", "user")?;
            (
                uid,
                passwd_field_by_uid(uid, 3)
                    .and_then(|g| g.parse().ok())
                    .unwrap_or(uid),
            )
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
        let content =
            std::fs::read_to_string(file).with_context(|| format!("failed to read {file}"))?;
        content
            .lines()
            .find_map(|line| {
                let f: Vec<&str> = line.split(':').collect();
                (f.len() > 2 && f[0] == s)
                    .then(|| f[2].parse::<u32>().ok())
                    .flatten()
            })
            .with_context(|| format!("{label} not found in {file}: {s}"))
    })
}

fn passwd_field_by_uid(uid: u32, idx: usize) -> Option<String> {
    std::fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            (f.len() > idx && f[2].parse::<u32>().ok() == Some(uid)).then(|| f[idx].to_string())
        })
}

fn setup_namespaces_and_pivot(
    new_root: &Path,
    rootless: bool,
    volumes: &[super::super::VolumeMount],
    isolate_network: bool,
) -> Result<()> {
    use nix::mount::mount;
    use nix::sched::{CloneFlags, unshare};
    let mut flags = CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWIPC;
    if isolate_network {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    unshare(flags).context("failed to unshare namespaces")?;
    let bind_rec = MsFlags::MS_BIND | MsFlags::MS_REC;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("failed to set mount propagation to private")?;
    mount(
        Some(new_root),
        new_root,
        None::<&str>,
        bind_rec,
        None::<&str>,
    )
    .context("failed to bind-mount new root")?;
    if rootless {
        for (host, sub) in [("/proc", "proc"), ("/sys", "sys")] {
            let target = new_root.join(sub);
            std::fs::create_dir_all(&target)?;
            let _ = mount(Some(host), &target, None::<&str>, bind_rec, None::<&str>);
        }
    }
    super::mounts::mount_volumes(new_root, volumes)?;
    let old_root = new_root.join("old_root");
    std::fs::create_dir_all(&old_root)?;
    nix::unistd::pivot_root(new_root, &old_root).context("pivot_root failed")?;
    nix::unistd::chdir("/").context("chdir to / failed")?;
    nix::mount::umount2("/old_root", nix::mount::MntFlags::MNT_DETACH)
        .context("failed to unmount old root")?;
    let _ = std::fs::remove_dir("/old_root");
    Ok(())
}

// Seccomp filter: per-arch tables of syscall numbers we deny via EPERM.
//
// The same *named* set of dangerous syscalls is denied on every supported arch.
// Because syscall numbers differ per ABI, we resolve names to numbers via
// `nix::libc::SYS_*` constants (which are themselves cfg-gated per target_arch),
// then pick the matching `seccompiler::TargetArch`.
//
// Adding support for a new arch is a deliberate audit step — see the
// `compile_error!` fallback at the end.

#[cfg(target_arch = "x86_64")]
#[allow(deprecated)] // Legacy syscalls still exist as kernel stubs; blocking is intentional.
const BLOCKED: &[i64] = &[
    nix::libc::SYS_ptrace,
    nix::libc::SYS_syslog,
    nix::libc::SYS_uselib,
    nix::libc::SYS_personality,
    nix::libc::SYS_ustat,
    nix::libc::SYS_sysfs,
    nix::libc::SYS_pivot_root,
    nix::libc::SYS_acct,
    nix::libc::SYS_settimeofday,
    nix::libc::SYS_mount,
    nix::libc::SYS_umount2,
    nix::libc::SYS_swapon,
    nix::libc::SYS_swapoff,
    nix::libc::SYS_reboot,
    nix::libc::SYS_iopl,
    nix::libc::SYS_ioperm,
    nix::libc::SYS_create_module,
    nix::libc::SYS_init_module,
    nix::libc::SYS_delete_module,
    nix::libc::SYS_get_kernel_syms,
    nix::libc::SYS_query_module,
    nix::libc::SYS_quotactl,
    nix::libc::SYS_nfsservctl,
    nix::libc::SYS_io_setup,
    nix::libc::SYS_lookup_dcookie,
    nix::libc::SYS_clock_settime,
    nix::libc::SYS_mbind,
    nix::libc::SYS_set_mempolicy,
    nix::libc::SYS_get_mempolicy,
    nix::libc::SYS_kexec_load,
    nix::libc::SYS_add_key,
    nix::libc::SYS_request_key,
    nix::libc::SYS_keyctl,
    nix::libc::SYS_unshare,
    nix::libc::SYS_move_pages,
    nix::libc::SYS_perf_event_open,
    nix::libc::SYS_open_by_handle_at,
    nix::libc::SYS_clock_adjtime,
    nix::libc::SYS_setns,
    nix::libc::SYS_process_vm_readv,
    nix::libc::SYS_process_vm_writev,
    nix::libc::SYS_kcmp,
    nix::libc::SYS_finit_module,
    nix::libc::SYS_kexec_file_load,
    nix::libc::SYS_bpf,
    nix::libc::SYS_userfaultfd,
    nix::libc::SYS_io_uring_setup,
    nix::libc::SYS_io_uring_enter,
    nix::libc::SYS_io_uring_register,
    nix::libc::SYS_open_tree,
    nix::libc::SYS_move_mount,
    nix::libc::SYS_fsopen,
    nix::libc::SYS_fsconfig,
    nix::libc::SYS_fsmount,
    nix::libc::SYS_pidfd_open,
    nix::libc::SYS_mount_setattr,
];

// aarch64 omits the legacy x86-only entries (uselib, ustat, sysfs, iopl,
// ioperm, create_module, get_kernel_syms, query_module) — those syscalls
// don't exist on this ABI, so there's nothing to block.
#[cfg(target_arch = "aarch64")]
#[allow(deprecated)] // Legacy syscalls still exist as kernel stubs; blocking is intentional.
const BLOCKED: &[i64] = &[
    nix::libc::SYS_ptrace,
    nix::libc::SYS_syslog,
    nix::libc::SYS_personality,
    nix::libc::SYS_pivot_root,
    nix::libc::SYS_acct,
    nix::libc::SYS_settimeofday,
    nix::libc::SYS_mount,
    nix::libc::SYS_umount2,
    nix::libc::SYS_swapon,
    nix::libc::SYS_swapoff,
    nix::libc::SYS_reboot,
    nix::libc::SYS_init_module,
    nix::libc::SYS_delete_module,
    nix::libc::SYS_quotactl,
    nix::libc::SYS_nfsservctl,
    nix::libc::SYS_io_setup,
    nix::libc::SYS_lookup_dcookie,
    nix::libc::SYS_clock_settime,
    nix::libc::SYS_mbind,
    nix::libc::SYS_set_mempolicy,
    nix::libc::SYS_get_mempolicy,
    nix::libc::SYS_kexec_load,
    nix::libc::SYS_add_key,
    nix::libc::SYS_request_key,
    nix::libc::SYS_keyctl,
    nix::libc::SYS_unshare,
    nix::libc::SYS_move_pages,
    nix::libc::SYS_perf_event_open,
    nix::libc::SYS_open_by_handle_at,
    nix::libc::SYS_clock_adjtime,
    nix::libc::SYS_setns,
    nix::libc::SYS_process_vm_readv,
    nix::libc::SYS_process_vm_writev,
    nix::libc::SYS_kcmp,
    nix::libc::SYS_finit_module,
    nix::libc::SYS_kexec_file_load,
    nix::libc::SYS_bpf,
    nix::libc::SYS_userfaultfd,
    nix::libc::SYS_io_uring_setup,
    nix::libc::SYS_io_uring_enter,
    nix::libc::SYS_io_uring_register,
    nix::libc::SYS_open_tree,
    nix::libc::SYS_move_mount,
    nix::libc::SYS_fsopen,
    nix::libc::SYS_fsconfig,
    nix::libc::SYS_fsmount,
    nix::libc::SYS_pidfd_open,
    nix::libc::SYS_mount_setattr,
];

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "hippobox: seccomp filter not implemented for this architecture; \
     audit and add a BLOCKED table + TargetArch in src/container/linux/init.rs"
);

#[cfg(target_arch = "x86_64")]
const FILTER_TARGET_ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const FILTER_TARGET_ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;

fn apply_seccomp_filter() -> Result<()> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
    let rules: std::collections::BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        BLOCKED.iter().map(|&nr| (nr, vec![])).collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(1),
        FILTER_TARGET_ARCH,
    )
    .context("failed to build seccomp filter")?;
    let prog: BpfProgram = filter.try_into().context("failed to compile BPF program")?;
    seccompiler::apply_filter(&prog).context("failed to install seccomp filter")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolve_id_and_user_setup() {
        // Numeric IDs work even with nonexistent files
        assert_eq!(resolve_id("0", "/nonexistent/file", "user").unwrap(), 0);
        assert_eq!(
            resolve_id("1000", "/nonexistent/file", "user").unwrap(),
            1000
        );
        assert_eq!(resolve_id("65534", "/etc/group", "group").unwrap(), 65534);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n").unwrap();
        let path = tmp.path().to_str().unwrap();
        assert_eq!(resolve_id("nobody", path, "user").unwrap(), 65534);
        assert!(resolve_id("nonexistent", path, "user").is_err());
        assert!(
            format!(
                "{:#}",
                resolve_id("someuser", "/nonexistent/path/passwd", "user").unwrap_err()
            )
            .contains("failed to read")
        );
        let tmp2 = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp2.path(), b"short\n\nempty:::\nuser:x:notanumber:0::/home/user:/bin/bash\ngood:x:42:42:Good:/home/good:/bin/sh\n").unwrap();
        let path2 = tmp2.path().to_str().unwrap();
        assert_eq!(resolve_id("good", path2, "user").unwrap(), 42);
        assert!(resolve_id("user", path2, "user").is_err());

        // passwd_field_by_uid
        if let Some(home) = passwd_field_by_uid(0, 5) {
            assert!(
                home == "/root" || home.starts_with('/'),
                "root home should be an absolute path"
            );
        }
        assert!(passwd_field_by_uid(99999, 5).is_none());
        // Rootless mode skips user setup
        assert!(
            setup_user("1000", true).unwrap().is_none(),
            "rootless mode should skip user setup"
        );
    }
    #[test]
    fn seccomp_blocked_list_is_valid() {
        use seccompiler::{SeccompAction, SeccompFilter};
        let mut sorted = BLOCKED.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), BLOCKED.len(), "BLOCKED contains duplicates");
        let rules: std::collections::BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
            BLOCKED.iter().map(|&nr| (nr, vec![])).collect();
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(1),
            FILTER_TARGET_ARCH,
        )
        .unwrap();
        let _: seccompiler::BpfProgram = filter.try_into().unwrap();
    }
}
