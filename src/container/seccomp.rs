// Seccomp BPF filter — x86_64 only. Syscall numbers are arch-specific.
#[cfg(not(target_arch = "x86_64"))]
compile_error!("seccomp filter only supports x86_64; add syscall numbers for your arch");

use anyhow::{Context, Result};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
use std::collections::BTreeMap;

/// Blocked x86_64 syscall numbers matching Docker's default seccomp profile.
const BLOCKED_SYSCALLS: &[i64] = &[
    101, 103, 134, 135, 136, 139, 155, 163, 164, 165, 166, 167, 168, 169,
    172, 173, 174, 175, 176, 177, 178, 179, 180, 206, 212, 227, 237, 238,
    239, 246, 248, 249, 250, 272, 279, 298, 304, 305, 308, 310, 311, 312,
    313, 320, 321, 323, 425, 426, 427, 428, 429, 430, 431, 432, 434, 442,
];

pub(super) fn apply_seccomp_filter() -> Result<()> {
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        BLOCKED_SYSCALLS.iter().map(|&nr| (nr, vec![])).collect();
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(1), TargetArch::x86_64)
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
        for &nr in BLOCKED_SYSCALLS {
            assert!(seen.insert(nr), "duplicate syscall number {nr}");
        }
    }

    #[test]
    fn spot_check_syscall_numbers() {
        // mount=165, ptrace=101, reboot=169, bpf=321, unshare=272
        for nr in [165, 101, 169, 321, 272] {
            assert!(BLOCKED_SYSCALLS.contains(&nr), "missing syscall {nr}");
        }
    }
}
