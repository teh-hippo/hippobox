use anyhow::{Context, Result, bail};
use std::path::Path;
use std::time::Duration;

const CGROUP_BASE: &str = "/sys/fs/cgroup/hippobox";

pub(super) fn check_cgroup_v2() -> Result<()> {
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        bail!("cgroup v2 not available (missing /sys/fs/cgroup/cgroup.controllers)");
    }
    Ok(())
}

pub(super) fn create(container_id: &str) -> Result<()> {
    std::fs::create_dir_all(CGROUP_BASE)
        .with_context(|| format!("failed to create cgroup base at {CGROUP_BASE}"))?;
    std::fs::create_dir_all(cgroup_path(container_id))
        .with_context(|| format!("failed to create cgroup for {container_id}"))
}

pub(super) fn add_pid(container_id: &str, pid: u32) -> Result<()> {
    let procs_path = format!("{}/cgroup.procs", cgroup_path(container_id));
    std::fs::write(&procs_path, pid.to_string())
        .with_context(|| format!("failed to write PID to {procs_path}"))
}

pub(super) fn cleanup(container_id: &str) -> Result<()> {
    let cgroup_path = cgroup_path(container_id);
    if !Path::new(&cgroup_path).exists() {
        return Ok(());
    }

    let cgroup_kill = format!("{cgroup_path}/cgroup.kill");
    if Path::new(&cgroup_kill).exists() {
        let _ = std::fs::write(&cgroup_kill, "1");
    } else {
        let procs_path = format!("{cgroup_path}/cgroup.procs");
        if let Ok(content) = std::fs::read_to_string(&procs_path) {
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
            }
        }
    }

    let mut removed = false;
    for _ in 0..10 {
        if std::fs::remove_dir(&cgroup_path).is_ok() {
            removed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    if !removed {
        eprintln!("warning: cgroup cleanup stalled for {cgroup_path}");
    }

    let _ = std::fs::remove_dir(CGROUP_BASE);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_path_format() {
        let path = cgroup_path("abc123");
        assert!(path.ends_with("/abc123"));
        assert!(path.contains("hippobox"));
    }
}

pub(super) fn cgroup_path(container_id: &str) -> String {
    format!("{CGROUP_BASE}/{container_id}")
}
