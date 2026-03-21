// Seccomp BPF filter — x86_64 only. Syscall numbers are arch-specific.
#[cfg(not(target_arch = "x86_64"))]
compile_error!("seccomp filter only supports x86_64; add syscall numbers for your arch");

use anyhow::{Context, Result};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
use std::collections::BTreeMap;

/// Blocked syscalls (name + x86_64 number) matching Docker's default seccomp profile.
/// Default action is ALLOW; these specific syscalls are blocked with EPERM.
const BLOCKED_SYSCALLS: &[(&str, i64)] = &[
    ("acct", 163),
    ("add_key", 248),
    ("bpf", 321),
    ("clock_adjtime", 305),
    ("clock_settime", 227),
    ("create_module", 174),
    ("delete_module", 176),
    ("finit_module", 313),
    ("fsconfig", 431),
    ("fsmount", 432),
    ("fsopen", 430),
    ("get_kernel_syms", 177),
    ("get_mempolicy", 239),
    ("init_module", 175),
    ("io_setup", 206),
    ("io_uring_enter", 426),
    ("io_uring_register", 427),
    ("io_uring_setup", 425),
    ("ioperm", 173),
    ("iopl", 172),
    ("kcmp", 312),
    ("kexec_file_load", 320),
    ("kexec_load", 246),
    ("keyctl", 250),
    ("lookup_dcookie", 212),
    ("mbind", 237),
    ("mount", 165),
    ("mount_setattr", 442),
    ("move_mount", 429),
    ("move_pages", 279),
    ("nfsservctl", 180),
    ("open_by_handle_at", 304),
    ("open_tree", 428),
    ("perf_event_open", 298),
    ("personality", 135),
    ("pidfd_open", 434),
    ("pivot_root", 155),
    ("process_vm_readv", 310),
    ("process_vm_writev", 311),
    ("ptrace", 101),
    ("query_module", 178),
    ("quotactl", 179),
    ("reboot", 169),
    ("request_key", 249),
    ("set_mempolicy", 238),
    ("setns", 308),
    ("settimeofday", 164),
    ("swapon", 167),
    ("swapoff", 168),
    ("sysfs", 139),
    ("syslog", 103),
    ("umount2", 166),
    ("unshare", 272),
    ("uselib", 134),
    ("userfaultfd", 323),
    ("ustat", 136),
];

/// Build and install a seccomp BPF filter blocking dangerous syscalls.
/// Must be called after PR_SET_NO_NEW_PRIVS and before execvpe.
pub(super) fn apply_seccomp_filter() -> Result<()> {
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        BLOCKED_SYSCALLS.iter().map(|&(_, nr)| (nr, vec![])).collect();

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(1),
        TargetArch::x86_64,
    )
    .context("failed to build seccomp filter")?;

    let prog: BpfProgram = filter.try_into().context("failed to compile BPF program")?;
    seccompiler::apply_filter(&prog).context("failed to install seccomp filter")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_duplicate_syscall_numbers() {
        let mut seen = std::collections::HashSet::new();
        for &(name, nr) in BLOCKED_SYSCALLS {
            assert!(seen.insert(nr), "duplicate syscall number {nr} for {name:?}");
        }
    }

    #[test]
    fn spot_check_syscall_numbers() {
        let lookup = |name| BLOCKED_SYSCALLS.iter().find(|(n, _)| *n == name).map(|(_, nr)| *nr);
        assert_eq!(lookup("mount"), Some(165));
        assert_eq!(lookup("ptrace"), Some(101));
        assert_eq!(lookup("reboot"), Some(169));
        assert_eq!(lookup("bpf"), Some(321));
        assert_eq!(lookup("unshare"), Some(272));
    }
}
