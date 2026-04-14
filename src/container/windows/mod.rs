use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) fn run(spec: super::ContainerSpec) -> Result<i32> {
    let super::ContainerSpec {
        id,
        image_ref,
        manifest,
        config,
        base_dir,
        user_cmd,
        user_env,
        target,
        volumes,
        network_mode,
        port_mappings,
        rootless,
        external_netns,
    } = spec;

    // These fields are not applicable on Windows — containers share the host
    // network stack and run as the current user with no namespace isolation.
    let _ = network_mode;
    let _ = rootless;
    let _ = external_netns;
    if !port_mappings.is_empty() {
        eprintln!("  warning: port mappings are not supported on Windows (host network shared)");
    }

    let cc = config.config.as_ref();
    let argv = super::build_argv(cc, user_cmd)?;
    let env_vars = super::build_env_vars(cc, &user_env, &target)?;

    let container_dir = base_dir.join("containers").join(&id);
    let merged = container_dir.join("merged");
    std::fs::create_dir_all(&merged)?;
    let _guard = super::SimpleCleanupGuard(container_dir.clone());

    // Acquire an exclusive lock file so gc_simple knows this container is active.
    let _lock = acquire_container_lock(&container_dir);

    for layer in manifest.layers.iter().rev() {
        let layer_dir = layer.layer_dir(&base_dir);
        if !layer_dir.exists() {
            anyhow::bail!(
                "layer directory missing: {} — image may need re-pulling",
                layer_dir.display()
            );
        }
        super::copy_dir_recursive(&layer_dir, &merged, false)?;
    }

    // Apply volumes: tmpfs → create dir, real source → copy into merged
    for vol in &volumes {
        let target_path = merged.join(vol.target.trim_start_matches('/'));
        if vol.source == "tmpfs" {
            std::fs::create_dir_all(&target_path)?;
        } else {
            let src = std::path::Path::new(&vol.source);
            if src.is_dir() {
                std::fs::create_dir_all(&target_path)?;
                super::copy_dir_recursive(src, &target_path, true)?;
            } else {
                if let Some(p) = target_path.parent() {
                    std::fs::create_dir_all(p)?;
                }
                std::fs::copy(src, &target_path)
                    .with_context(|| format!("copy volume {}", vol.source))?;
            }
        }
    }

    eprintln!(
        "starting windows container {} ({}/{}/{})",
        &id[..12.min(id.len())],
        image_ref.registry,
        image_ref.repository,
        image_ref.tag
    );

    let merged_str = merged.to_string_lossy();
    let resolved = resolve_win_path(&argv[0], &merged_str);
    eprintln!("  cmd: {:?}", argv);

    let mut cmd = std::process::Command::new(&resolved);
    cmd.args(&argv[1..]);

    // Set working directory from image config
    let workdir = cc
        .and_then(|c| c.working_dir.as_deref())
        .filter(|w| !w.is_empty());
    if let Some(w) = workdir {
        cmd.current_dir(resolve_win_path(w, &merged_str));
    }

    for kv in &env_vars {
        if let Some((k, v)) = kv.split_once('=') {
            if !k.eq_ignore_ascii_case("PATH") {
                cmd.env(k, v);
            }
        }
    }

    // Resolve image PATH through merged rootfs; image uses ';' separators.
    let mut path_parts: Vec<String> = env_vars
        .iter()
        .find_map(|v| v.strip_prefix("PATH=").or_else(|| v.strip_prefix("Path=")))
        .into_iter()
        .flat_map(|p| p.split(';').filter(|s| !s.is_empty()))
        .map(|p| resolve_win_path(p, &merged_str))
        .collect();
    if let Ok(p) = std::env::var("PATH") {
        path_parts.extend(p.split(';').filter(|s| !s.is_empty()).map(String::from));
    }
    if !path_parts.is_empty() {
        cmd.env("PATH", path_parts.join(";"));
    }

    // Spawn child in a new process group so we can target it with CTRL_BREAK_EVENT.
    // CTRL_C_EVENT cannot be directed to a specific process group (it always goes
    // to all processes sharing the console), but CTRL_BREAK_EVENT can.
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = cmd.spawn().context("failed to launch Windows process")?;
    let child_pid = child.id();

    let _job = match JobObjectGuard::new() {
        Ok(job) => {
            if let Err(e) = job.assign(&child) {
                eprintln!("  warning: failed to assign process to job object: {e}");
            }
            Some(job)
        }
        Err(e) => {
            eprintln!("  warning: failed to create job object: {e}");
            None
        }
    };

    // Install a console Ctrl handler to catch Ctrl+C / Ctrl+Break / close events.
    let _ctrl_guard = CtrlHandlerGuard::install();

    // Poll the child, forwarding Ctrl events as CTRL_BREAK_EVENT.
    let exit_code = wait_with_signal_forwarding(&mut child, child_pid)?;
    Ok(exit_code)
}

/// Acquire an exclusive lock file in the container directory.
/// The returned `File` handle holds the lock until dropped.
/// Returns `None` if the lock cannot be acquired (non-fatal).
fn acquire_container_lock(container_dir: &std::path::Path) -> Option<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .share_mode(0) // exclusive — no other process can open this file
        .open(container_dir.join("hippobox.lock"))
        .ok()
}

/// Check if a container directory has an active lock.
/// Returns `true` if the container is locked (running), `false` otherwise.
pub(crate) fn is_container_locked(container_dir: &std::path::Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    let lock_path = container_dir.join("hippobox.lock");
    if !lock_path.exists() {
        return false;
    }
    // Try to open exclusively — if it fails, another process holds the lock.
    std::fs::OpenOptions::new()
        .write(true)
        .share_mode(0)
        .open(&lock_path)
        .is_err()
}

fn resolve_win_path(path: &str, merged: &str) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    let n = path
        .replace('/', &sep.to_string())
        .replace('\\', &sep.to_string());
    let s = if n.len() >= 2 && n.as_bytes()[0].is_ascii_alphabetic() && n.as_bytes()[1] == b':' {
        &n[2..]
    } else {
        &n
    };
    let s = s.strip_prefix(sep).unwrap_or(s);
    if s.contains(sep) {
        format!("{merged}{sep}Files{sep}{s}")
    } else {
        n
    }
}

/// Atomic flag set by the console Ctrl handler when Ctrl+C, Ctrl+Break, or
/// console close events are received.
static PENDING_CTRL: AtomicBool = AtomicBool::new(false);

/// Console Ctrl handler — sets `PENDING_CTRL` and returns TRUE (handled) so
/// the default handler (which calls `ExitProcess`) is not invoked.
unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> i32 {
    PENDING_CTRL.store(true, Ordering::SeqCst);
    1 // TRUE — we handled it
}

/// RAII guard that installs/uninstalls the console Ctrl handler.
struct CtrlHandlerGuard;

impl CtrlHandlerGuard {
    fn install() -> Self {
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(ctrl_handler), 1);
        }
        Self
    }
}

impl Drop for CtrlHandlerGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(ctrl_handler), 0);
        }
    }
}

/// Wait for the child process, forwarding console Ctrl events as CTRL_BREAK_EVENT.
///
/// When the user presses Ctrl+C (or the console is closed), we send
/// CTRL_BREAK_EVENT to the child's process group and give it up to 10 seconds
/// to exit gracefully.  After the timeout, we return and let the Job Object
/// hard-kill any remaining processes.
fn wait_with_signal_forwarding(child: &mut std::process::Child, child_pid: u32) -> Result<i32> {
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
    const GRACEFUL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    loop {
        match child.try_wait().context("failed to check child status")? {
            Some(status) => return Ok(status.code().unwrap_or(1)),
            None => {
                if PENDING_CTRL.swap(false, Ordering::SeqCst) {
                    // Forward as CTRL_BREAK_EVENT to the child's process group.
                    unsafe {
                        windows_sys::Win32::System::Console::GenerateConsoleCtrlEvent(
                            windows_sys::Win32::System::Console::CTRL_BREAK_EVENT,
                            child_pid,
                        );
                    }
                    // Give the child time to exit gracefully.
                    let deadline = std::time::Instant::now() + GRACEFUL_TIMEOUT;
                    while std::time::Instant::now() < deadline {
                        if let Some(status) = child.try_wait()? {
                            return Ok(status.code().unwrap_or(1));
                        }
                        std::thread::sleep(POLL_INTERVAL);
                    }
                    eprintln!("  container did not exit within 10s — terminating");
                    let _ = child.kill();
                    let status = child.wait()?;
                    return Ok(status.code().unwrap_or(1));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

/// RAII guard that wraps a Windows Job Object handle.
/// When dropped, `CloseHandle` fires and — because `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
/// is set — all processes in the job are terminated.
struct JobObjectGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

impl JobObjectGuard {
    fn new() -> Result<Self> {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, SetInformationJobObject,
        };

        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            anyhow::bail!("CreateJobObjectW failed: error {}", unsafe {
                GetLastError()
            });
        }

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

        let ok = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            unsafe { CloseHandle(handle) };
            anyhow::bail!("SetInformationJobObject failed: error {}", unsafe {
                GetLastError()
            });
        }

        Ok(Self { handle })
    }

    fn assign(&self, child: &std::process::Child) -> Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

        let process_handle = child.as_raw_handle();
        let ok = unsafe { AssignProcessToJobObject(self.handle, process_handle as _) };
        if ok == 0 {
            anyhow::bail!("AssignProcessToJobObject failed: error {}", unsafe {
                GetLastError()
            });
        }
        Ok(())
    }
}

impl Drop for JobObjectGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_win_path_cases() {
        let sep = std::path::MAIN_SEPARATOR;
        let m = format!("C:{sep}merged");
        let f = |s: &str| format!("{m}{sep}Files{sep}{}", s.replace('/', &sep.to_string()));

        for (input, expected) in [
            (r"c:\win\sys\cmd.exe", f("win/sys/cmd.exe")),
            (r"C:\Program Files\pwsh.exe", f("Program Files/pwsh.exe")),
            (r"\Win\Sys\cmd.exe", f("Win/Sys/cmd.exe")),
            (r"Win\Sys\cmd.exe", f("Win/Sys/cmd.exe")),
            ("c:/a/b.exe", f("a/b.exe")), // forward slashes
            ("pwsh.exe", "pwsh.exe".to_string()),
        ] {
            assert_eq!(resolve_win_path(input, &m), expected, "input={input:?}");
        }
    }

    #[test]
    fn job_object_guard_lifecycle() {
        // Create a job object and verify it doesn't panic
        let job = JobObjectGuard::new().expect("failed to create job object");

        // Spawn a short-lived child process and assign it
        let child = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .expect("failed to spawn cmd.exe");
        job.assign(&child).expect("failed to assign to job");

        // Drop the job — should not panic
        drop(job);
    }

    #[test]
    fn container_lock_lifecycle() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        // No lock file → not locked
        assert!(!is_container_locked(&dir));

        // Acquire lock → locked
        let lock = acquire_container_lock(&dir);
        assert!(lock.is_some());
        assert!(is_container_locked(&dir));

        // Release lock → not locked
        drop(lock);
        assert!(!is_container_locked(&dir));
    }

    #[test]
    fn ctrl_handler_guard_lifecycle() {
        // Install and uninstall the Ctrl handler without panicking.
        let guard = CtrlHandlerGuard::install();

        // Verify the atomic flag is initially false
        assert!(!PENDING_CTRL.load(Ordering::SeqCst));

        // Simulate setting the flag (as the handler would)
        PENDING_CTRL.store(true, Ordering::SeqCst);
        assert!(PENDING_CTRL.swap(false, Ordering::SeqCst));

        // Drop uninstalls the handler
        drop(guard);
    }

    #[test]
    fn signal_forwarding_exits_child() {
        use std::os::windows::process::CommandExt;

        // Spawn a long-running child in a new process group
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "ping -n 60 127.0.0.1 >nul"])
            .creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP)
            .spawn()
            .expect("failed to spawn cmd.exe");
        let pid = child.id();

        // Send CTRL_BREAK_EVENT to terminate it
        unsafe {
            windows_sys::Win32::System::Console::GenerateConsoleCtrlEvent(
                windows_sys::Win32::System::Console::CTRL_BREAK_EVENT,
                pid,
            );
        }

        // It should exit within a few seconds
        let status = child.wait().expect("failed to wait for child");
        // The exit code is non-zero (interrupted)
        assert_ne!(status.code(), Some(0));
    }
}
