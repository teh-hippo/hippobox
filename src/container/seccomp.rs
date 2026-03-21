// Seccomp BPF filter — x86_64 only. Syscall numbers are arch-specific.
#[cfg(not(target_arch = "x86_64"))]
compile_error!("seccomp filter only supports x86_64; add syscall numbers for your arch");

use anyhow::{Context, Result};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter,
    TargetArch,
};
use std::collections::BTreeMap;

/// Blocked syscalls matching Docker's default seccomp profile.
/// Default action is ALLOW; these specific syscalls are blocked with EPERM.
const BLOCKED_SYSCALLS: &[&str] = &[
    "acct",
    "add_key",
    "bpf",
    "clock_adjtime",
    "clock_settime",
    "create_module",
    "delete_module",
    "finit_module",
    "fsconfig",
    "fsmount",
    "fsopen",
    "get_kernel_syms",
    "get_mempolicy",
    "init_module",
    "io_setup",
    "ioperm",
    "iopl",
    "kcmp",
    "kexec_file_load",
    "kexec_load",
    "keyctl",
    "lookup_dcookie",
    "mbind",
    "mount",
    "mount_setattr",
    "move_mount",
    "move_pages",
    "nfsservctl",
    "open_by_handle_at",
    "open_tree",
    "perf_event_open",
    "pidfd_open",
    "pivot_root",
    "process_vm_readv",
    "process_vm_writev",
    "ptrace",
    "query_module",
    "quotactl",
    "reboot",
    "request_key",
    "set_mempolicy",
    "setns",
    "settimeofday",
    "swapon",
    "swapoff",
    "sysfs",
    "syslog",
    "umount2",
    "unshare",
    "uselib",
    "userfaultfd",
    "ustat",
];

/// Build and install a seccomp BPF filter blocking dangerous syscalls.
/// Must be called after PR_SET_NO_NEW_PRIVS and before execvpe.
pub fn apply_seccomp_filter() -> Result<()> {
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();

    for name in BLOCKED_SYSCALLS {
        if let Some(nr) = syscall_number(name) {
            // Empty rule vec = unconditional match -> triggers match_action (EPERM).
            rules.insert(nr, vec![]);
        }
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,   // default for unmatched syscalls
        SeccompAction::Errno(1), // EPERM for blocked syscalls
        TargetArch::x86_64,
    )
    .context("failed to build seccomp filter")?;

    let prog: BpfProgram = filter.try_into().context("failed to compile BPF program")?;
    seccompiler::apply_filter(&prog).context("failed to install seccomp filter")?;

    Ok(())
}

fn syscall_number(name: &str) -> Option<i64> {
    // x86_64 syscall numbers. Only includes syscalls we block.
    Some(match name {
        "acct" => 163,
        "add_key" => 248,
        "bpf" => 321,
        "clock_adjtime" => 305,
        "clock_settime" => 227,
        "create_module" => 174,
        "delete_module" => 176,
        "finit_module" => 313,
        "fsconfig" => 431,
        "fsmount" => 432,
        "fsopen" => 430,
        "get_kernel_syms" => 177,
        "get_mempolicy" => 239,
        "init_module" => 175,
        "io_setup" => 206,
        "ioperm" => 173,
        "iopl" => 172,
        "kcmp" => 312,
        "kexec_file_load" => 320,
        "kexec_load" => 246,
        "keyctl" => 250,
        "lookup_dcookie" => 212,
        "mbind" => 237,
        "mount" => 165,
        "mount_setattr" => 442,
        "move_mount" => 429,
        "move_pages" => 279,
        "nfsservctl" => 180,
        "open_by_handle_at" => 304,
        "open_tree" => 428,
        "perf_event_open" => 298,
        "pidfd_open" => 434,
        "pivot_root" => 155,
        "process_vm_readv" => 310,
        "process_vm_writev" => 311,
        "ptrace" => 101,
        "query_module" => 178,
        "quotactl" => 179,
        "reboot" => 169,
        "request_key" => 249,
        "set_mempolicy" => 238,
        "setns" => 308,
        "settimeofday" => 164,
        "swapon" => 167,
        "swapoff" => 168,
        "sysfs" => 139,
        "syslog" => 103,
        "umount2" => 166,
        "unshare" => 272,
        "uselib" => 134,
        "userfaultfd" => 323,
        "ustat" => 136,
        _ => return None,
    })
}
