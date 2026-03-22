use anyhow::{Context, Result, bail};
use nix::fcntl::{Flock, FlockArg};
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const CGROUP_BASE: &str = "/sys/fs/cgroup/hippobox";
fn cgroup_path(id: &str) -> String {
    format!("{CGROUP_BASE}/{id}")
}

pub(super) fn check_cgroup_v2() -> Result<()> {
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        bail!("cgroup v2 not available");
    }
    Ok(())
}
pub(super) fn cgroup_create(id: &str) -> Result<()> {
    std::fs::create_dir_all(CGROUP_BASE)?;
    std::fs::create_dir_all(cgroup_path(id))
        .with_context(|| format!("failed to create cgroup for {id}"))
}
pub(super) fn cgroup_add_pid(id: &str, pid: u32) -> Result<()> {
    std::fs::write(format!("{}/cgroup.procs", cgroup_path(id)), pid.to_string())
        .context("failed to write PID to cgroup")
}
fn cgroup_cleanup(id: &str) {
    let path = cgroup_path(id);
    if !Path::new(&path).exists() {
        return;
    }
    let kill = format!("{path}/cgroup.kill");
    if Path::new(&kill).exists() {
        let _ = std::fs::write(&kill, "1");
    } else if let Ok(content) = std::fs::read_to_string(format!("{path}/cgroup.procs")) {
        for pid in content.lines().filter_map(|l| l.trim().parse::<i32>().ok()) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
    for _ in 0..10 {
        if std::fs::remove_dir(&path).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let _ = std::fs::remove_dir(CGROUP_BASE);
}

pub(super) fn acquire_container_lock(container_dir: &Path) -> Result<Flock<File>> {
    let p = container_dir.join("hippobox.lock");
    let f = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&p)
        .with_context(|| format!("failed to open lock at {}", p.display()))?;
    Flock::lock(f, FlockArg::LockExclusive)
        .map_err(|(_, e)| e)
        .with_context(|| format!("failed to flock {}", p.display()))
}
pub fn gc_stale_containers(base_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(base_dir.join("containers")) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !entry.file_type().is_ok_and(|ft| ft.is_dir()) {
            continue;
        }
        if let Ok(meta) = std::fs::metadata(&path) {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != nix::unistd::getuid().as_raw() {
                continue;
            }
        }
        let lock_path = path.join("hippobox.lock");
        if lock_path.exists() {
            match File::open(&lock_path).and_then(|f| {
                Flock::lock(f, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| e.into())
            }) {
                Ok(_) => {}
                Err(_) => continue,
            }
        }
        let merged = path.join("merged");
        if merged.exists() {
            let _ = super::mounts::cleanup_host_device_sources(&merged);
            match nix::mount::umount2(&merged, nix::mount::MntFlags::empty()) {
                Ok(())
                | Err(
                    nix::errno::Errno::EINVAL
                    | nix::errno::Errno::ENOENT
                    | nix::errno::Errno::EPERM,
                ) => {}
                Err(nix::errno::Errno::EBUSY) => {
                    eprintln!("warning: overlay still busy, skipping {}", path.display());
                    continue;
                }
                Err(e) => {
                    eprintln!("warning: gc unmount failed for {}: {e}", path.display());
                    continue;
                }
            }
        }
        fix_overlay_workdir(&path);
        let _ = std::fs::remove_dir_all(&path);
    }
}
fn fix_overlay_workdir(container_dir: &Path) {
    let work = container_dir.join("work");
    if !work.exists() {
        return;
    }
    let mut stack = vec![work];
    while let Some(dir) = stack.pop() {
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                if e.path().is_dir() {
                    stack.push(e.path());
                }
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
        if !self.rootless {
            cgroup_cleanup(&self.id);
        }
        let can_remove = !self.overlay_mounted || {
            let _ = super::mounts::cleanup_host_device_sources(&self.merged);
            super::mounts::unmount_overlay(&self.merged).is_ok()
        };
        for dir in &self.layer_dirs {
            let _ = std::fs::remove_file(dir.join(".in-use"));
        }
        if can_remove {
            fix_overlay_workdir(&self.container_dir);
            let _ = std::fs::remove_dir_all(&self.container_dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    fn mk(base: &Path, name: &str) -> PathBuf {
        let dir = base.join("containers").join(name);
        for sub in ["merged", "upper", "work"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        dir
    }
    #[test]
    fn gc_stale_and_active() {
        let tmp = TempDir::new().unwrap();
        let stale = mk(tmp.path(), "stale");
        gc_stale_containers(tmp.path());
        assert!(!stale.exists());
        let active = mk(tmp.path(), "active");
        let _lock = acquire_container_lock(&active).unwrap();
        gc_stale_containers(tmp.path());
        assert!(active.exists());
        let dead = mk(tmp.path(), "dead");
        {
            let _lock = acquire_container_lock(&dead).unwrap();
        }
        gc_stale_containers(tmp.path());
        assert!(!dead.exists());
    }
    #[test]
    fn gc_edge_cases() {
        let tmp = TempDir::new().unwrap();
        gc_stale_containers(tmp.path());
        std::fs::create_dir_all(tmp.path().join("containers")).unwrap();
        gc_stale_containers(tmp.path());
        let dirs: Vec<_> = (0..3).map(|i| mk(tmp.path(), &format!("s{i}"))).collect();
        gc_stale_containers(tmp.path());
        for d in &dirs {
            assert!(!d.exists());
        }
        std::fs::write(tmp.path().join("containers/file"), "x").unwrap();
        gc_stale_containers(tmp.path());
        assert!(tmp.path().join("containers/file").exists());
        let bad = mk(tmp.path(), "bad");
        std::fs::create_dir(bad.join("hippobox.lock")).unwrap();
        gc_stale_containers(tmp.path());
    }
    #[test]
    fn fix_overlay_workdir_behaviour() {
        let tmp = TempDir::new().unwrap();
        fix_overlay_workdir(tmp.path());
        let dir = tmp.path().join("container");
        std::fs::create_dir_all(dir.join("work/deep/nested")).unwrap();
        std::fs::set_permissions(dir.join("work"), std::fs::Permissions::from_mode(0o000)).unwrap();
        fix_overlay_workdir(&dir);
        assert_eq!(
            std::fs::metadata(dir.join("work"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let _ = std::fs::set_permissions(dir.join("work"), std::fs::Permissions::from_mode(0o755));
    }
    #[test]
    fn acquire_lock_is_exclusive() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("c");
        std::fs::create_dir_all(&dir).unwrap();
        let _lock = acquire_container_lock(&dir).unwrap();
        assert!(
            Flock::lock(
                File::open(dir.join("hippobox.lock")).unwrap(),
                FlockArg::LockExclusiveNonblock
            )
            .is_err()
        );
    }
    #[test]
    fn cgroup_path_format() {
        let p = cgroup_path("abc");
        assert!(p.ends_with("/abc") && p.starts_with("/sys/fs/cgroup"));
        assert_ne!(cgroup_path("a"), cgroup_path("b"));
    }
}
