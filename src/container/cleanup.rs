use anyhow::{Context, Result, bail};
use nix::fcntl::{Flock, FlockArg};
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const CGROUP_BASE: &str = "/sys/fs/cgroup/hippobox";
fn cgroup_path(id: &str) -> String { format!("{CGROUP_BASE}/{id}") }

pub(super) fn check_cgroup_v2() -> Result<()> {
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        bail!("cgroup v2 not available (missing /sys/fs/cgroup/cgroup.controllers)");
    }
    Ok(())
}
pub(super) fn cgroup_create(id: &str) -> Result<()> {
    std::fs::create_dir_all(CGROUP_BASE).with_context(|| format!("failed to create cgroup base at {CGROUP_BASE}"))?;
    std::fs::create_dir_all(cgroup_path(id)).with_context(|| format!("failed to create cgroup for {id}"))
}
pub(super) fn cgroup_add_pid(id: &str, pid: u32) -> Result<()> {
    let p = format!("{}/cgroup.procs", cgroup_path(id));
    std::fs::write(&p, pid.to_string()).with_context(|| format!("failed to write PID to {p}"))
}
fn cgroup_cleanup(id: &str) -> Result<()> {
    let path = cgroup_path(id);
    if !Path::new(&path).exists() { return Ok(()); }
    let kill = format!("{path}/cgroup.kill");
    if Path::new(&kill).exists() { let _ = std::fs::write(&kill, "1"); }
    else if let Ok(content) = std::fs::read_to_string(format!("{path}/cgroup.procs")) {
        for pid in content.lines().filter_map(|l| l.trim().parse::<i32>().ok()) {
            let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
        }
    }
    for _ in 0..10 {
        if std::fs::remove_dir(&path).is_ok() { break; }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let _ = std::fs::remove_dir(CGROUP_BASE);
    Ok(())
}

pub(super) fn acquire_container_lock(container_dir: &Path) -> Result<Flock<File>> {
    let lock_path = container_dir.join("hippobox.lock");
    let lock_file = File::options().read(true).write(true).create(true).truncate(false)
        .open(&lock_path).with_context(|| format!("failed to open lock at {}", lock_path.display()))?;
    Flock::lock(lock_file, FlockArg::LockExclusive).map_err(|(_, e)| e)
        .with_context(|| format!("failed to flock {}", lock_path.display()))
}
pub fn gc_stale_containers(base_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(base_dir.join("containers")) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if !entry.file_type().is_ok_and(|ft| ft.is_dir()) { continue; }
        if let Ok(meta) = std::fs::metadata(&path) {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != nix::unistd::getuid().as_raw() { continue; }
        }
        if let Err(e) = gc_try_clean_container(&path) {
            eprintln!("warning: gc failed for {}: {e}", path.file_name().unwrap_or_default().to_string_lossy());
        }
    }
}
fn gc_try_clean_container(container_dir: &Path) -> Result<()> {
    let lock_path = container_dir.join("hippobox.lock");
    if lock_path.exists() {
        let lock_file = File::open(&lock_path)?;
        match Flock::lock(lock_file, FlockArg::LockExclusiveNonblock) {
            Ok(_) => {}
            Err((_, nix::errno::Errno::EAGAIN)) => return Ok(()),
            Err((_, e)) => return Err(e).context("failed to probe container lock"),
        }
    }
    let merged = container_dir.join("merged");
    if merged.exists() {
        let _ = super::mounts::cleanup_host_device_sources(&merged);
        match nix::mount::umount2(&merged, nix::mount::MntFlags::empty()) {
            Ok(()) | Err(nix::errno::Errno::EINVAL | nix::errno::Errno::ENOENT | nix::errno::Errno::EPERM) => {}
            Err(nix::errno::Errno::EBUSY) => {
                eprintln!("warning: overlay still busy for {}, skipping",
                    container_dir.file_name().unwrap_or_default().to_string_lossy());
                return Ok(());
            }
            Err(e) => return Err(e).context("failed to unmount stale overlay"),
        }
    }
    fix_overlay_workdir(container_dir);
    let _ = std::fs::remove_dir_all(container_dir);
    Ok(())
}
fn fix_overlay_workdir(container_dir: &Path) {
    let work_dir = container_dir.join("work");
    if !work_dir.exists() { return; }
    let mut stack = vec![work_dir];
    while let Some(dir) = stack.pop() {
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() { stack.push(p); }
            }
        }
    }
}

pub(super) struct CleanupGuard {
    pub id: String,
    pub container_dir: PathBuf,
    pub merged: PathBuf,
    pub layer_dirs: Vec<PathBuf>,
    pub overlay_mounted: bool,
    pub rootless: bool,
    pub _lock: Flock<File>,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if !self.rootless { let _ = cgroup_cleanup(&self.id); }
        let can_remove = !self.overlay_mounted || {
            let _ = super::mounts::cleanup_host_device_sources(&self.merged);
            super::mounts::unmount_overlay(&self.merged).is_ok()
        };
        for dir in &self.layer_dirs { let _ = std::fs::remove_file(dir.join(".in-use")); }
        if can_remove { fix_overlay_workdir(&self.container_dir); let _ = std::fs::remove_dir_all(&self.container_dir); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_container_dir(base: &Path, name: &str) -> PathBuf {
        let dir = base.join("containers").join(name);
        for sub in ["merged", "upper", "work"] { std::fs::create_dir_all(dir.join(sub)).unwrap(); }
        dir
    }

    #[test]
    fn gc_removes_stale_and_keeps_active() {
        let tmp = TempDir::new().unwrap();
        let stale = make_container_dir(tmp.path(), "stale-no-lock");
        gc_stale_containers(tmp.path());
        assert!(!stale.exists());

        let active = make_container_dir(tmp.path(), "active");
        let _lock = acquire_container_lock(&active).unwrap();
        gc_stale_containers(tmp.path());
        assert!(active.exists());

        let dead = make_container_dir(tmp.path(), "dead-owner");
        { let _lock = acquire_container_lock(&dead).unwrap(); }
        gc_stale_containers(tmp.path());
        assert!(!dead.exists());
    }

    #[test]
    fn gc_handles_edge_cases() {
        let tmp = TempDir::new().unwrap();
        gc_stale_containers(tmp.path());
        std::fs::create_dir_all(tmp.path().join("containers")).unwrap();
        gc_stale_containers(tmp.path());
        let c = make_container_dir(tmp.path(), "once");
        gc_stale_containers(tmp.path());
        assert!(!c.exists());
        gc_stale_containers(tmp.path());
    }

    #[test]
    fn cgroup_path_format() {
        let path = cgroup_path("abc123");
        assert!(path.ends_with("/abc123") && path.contains("hippobox"));
    }
}
