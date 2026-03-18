use anyhow::{Context, Result};
use std::path::Path;

const CGROUP_BASE: &str = "/sys/fs/cgroup/hippobox";

/// Check that cgroup v2 is available.
pub fn check_cgroup_v2() -> Result<()> {
    let controllers = Path::new("/sys/fs/cgroup/cgroup.controllers");
    if !controllers.exists() {
        anyhow::bail!("cgroup v2 not available (missing /sys/fs/cgroup/cgroup.controllers)");
    }
    Ok(())
}

/// Create a cgroup for a container and return the path.
pub fn create(container_id: &str) -> Result<String> {
    let cgroup_path = format!("{CGROUP_BASE}/{container_id}");
    std::fs::create_dir_all(&cgroup_path)
        .with_context(|| format!("failed to create cgroup at {cgroup_path}"))?;
    Ok(cgroup_path)
}

/// Write a PID into the container's cgroup.
pub fn add_pid(container_id: &str, pid: u32) -> Result<()> {
    let procs_path = format!("{CGROUP_BASE}/{container_id}/cgroup.procs");
    std::fs::write(&procs_path, pid.to_string())
        .with_context(|| format!("failed to write PID to {procs_path}"))?;
    Ok(())
}

/// Clean up a container's cgroup.
pub fn cleanup(container_id: &str) -> Result<()> {
    let cgroup_path = format!("{CGROUP_BASE}/{container_id}");
    if Path::new(&cgroup_path).exists() {
        // Kill any remaining processes
        let procs_path = format!("{cgroup_path}/cgroup.procs");
        if let Ok(content) = std::fs::read_to_string(&procs_path) {
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGKILL,
                    )
                    .ok();
                }
            }
        }
        // Wait briefly for processes to die
        std::thread::sleep(std::time::Duration::from_millis(100));
        // Remove the cgroup directory
        std::fs::remove_dir(&cgroup_path).ok();
    }

    // Clean up parent if empty
    if Path::new(CGROUP_BASE).exists() {
        std::fs::remove_dir(CGROUP_BASE).ok();
    }

    Ok(())
}
