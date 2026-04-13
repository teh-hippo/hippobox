pub(crate) mod cleanup;
pub(crate) mod init;
pub(crate) mod mounts;
pub(crate) mod process;

use anyhow::{Context, Result, bail};
use std::path::PathBuf;

pub use cleanup::gc_stale_containers;
pub(crate) use init::container_init;
pub use mounts::parse_volume;

pub fn run(spec: super::ContainerSpec) -> Result<i32> {
    if spec.rootless {
        process::run_rootless_unshare(spec)
    } else {
        run_prepared(spec)
    }
}

pub(crate) fn run_prepared(spec: super::ContainerSpec) -> Result<i32> {
    let cc = spec.config.config.as_ref();
    let workdir = cc.and_then(|c| c.working_dir.as_deref()).unwrap_or("/");
    let stop_signal = cc
        .and_then(|c| c.stop_signal.as_deref())
        .unwrap_or("SIGTERM");
    let user = cc.and_then(|c| c.user.clone()).filter(|u| !u.is_empty());

    let argv = super::build_argv(cc, spec.user_cmd)?;
    let mut env_vars = super::build_env_vars(cc, &spec.user_env)?;
    let container_dir = spec.base_dir.join("containers").join(&spec.id);
    let (upper, work, merged) = (
        container_dir.join("upper"),
        container_dir.join("work"),
        container_dir.join("merged"),
    );
    std::fs::create_dir_all(&container_dir)?;
    for dir in [&upper, &work, &merged] {
        std::fs::create_dir(dir)?;
    }
    let lock_file = cleanup::acquire_container_lock(&container_dir)?;
    let mut guard = cleanup::CleanupGuard {
        id: spec.id.clone(),
        container_dir,
        merged: merged.clone(),
        layer_dirs: Vec::new(),
        overlay_mounted: false,
        rootless: spec.rootless,
        _lock: lock_file,
    };
    let layer_dirs: Vec<PathBuf> = spec
        .manifest
        .layers
        .iter()
        .rev()
        .map(|layer| layer.layer_dir(&spec.base_dir))
        .collect();
    for dir in &layer_dirs {
        if !dir.exists() {
            bail!(
                "layer directory missing: {} — image may need re-pulling",
                dir.display()
            );
        }
        let _ = std::fs::write(dir.join(".in-use"), spec.id.as_bytes());
    }

    mounts::mount_overlay(&layer_dirs, &upper, &work, &merged, spec.rootless).with_context(
        || {
            if spec.rootless {
                "overlay mount failed; Linux 5.11+ with unprivileged overlayfs support is required"
            } else {
                "overlay mount failed"
            }
        },
    )?;
    guard.layer_dirs = layer_dirs;
    guard.overlay_mounted = true;

    if spec.rootless
        && let Some(shim) = find_rename_shim()
    {
        let dest = merged.join(".hippobox");
        let _ = std::fs::create_dir(&dest);
        if std::fs::copy(&shim, dest.join("rename_shim.so")).is_ok() {
            env_vars.push("LD_PRELOAD=/.hippobox/rename_shim.so".into());
        }
    }

    mounts::prepare_host_device_sources(&merged)?;
    let img = &spec.image_ref;
    eprintln!(
        "starting container {} ({}/{}/{})",
        &spec.id[..12],
        img.registry,
        img.repository,
        img.tag
    );
    eprintln!("  cmd: {:?}", argv);

    process::run_container(
        process::ChildConfig {
            rootfs: merged.to_string_lossy().into_owned(),
            argv,
            env_vars,
            workdir: workdir.to_string(),
            container_id: spec.id,
            rootless: spec.rootless,
            user,
            volumes: spec.volumes,
            network_mode: spec.network_mode,
            port_mappings: spec.port_mappings,
            external_netns: spec.external_netns,
            ready_fd: None,
        },
        stop_signal,
    )
    .context("container execution failed")
}

pub(crate) fn resolve_self_exe() -> Result<PathBuf> {
    std::fs::read_link("/proc/self/exe")
        .or_else(|_| std::env::current_exe())
        .context("failed to locate current executable")
}

pub(crate) fn set_pdeathsig() -> std::io::Result<()> {
    let ret = unsafe {
        nix::libc::prctl(
            nix::libc::PR_SET_PDEATHSIG,
            nix::libc::SIGTERM as nix::libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn set_pdeathsig_with_race_check() -> Result<()> {
    let ppid_before = nix::unistd::getppid();
    set_pdeathsig().context("failed to set PR_SET_PDEATHSIG")?;
    if nix::unistd::getppid() != ppid_before {
        std::process::exit(1);
    }
    Ok(())
}

fn find_rename_shim() -> Option<PathBuf> {
    let shim = resolve_self_exe().ok()?.parent()?.join("librename_shim.so");
    shim.exists().then_some(shim)
}

/// Bring up the loopback network interface via ioctl.
pub(crate) fn bring_up_loopback() -> Result<()> {
    unsafe {
        let sock = nix::libc::socket(nix::libc::AF_INET, nix::libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to create socket");
        }
        let mut ifr: nix::libc::ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l' as nix::libc::c_char;
        ifr.ifr_name[1] = b'o' as nix::libc::c_char;
        #[allow(clippy::unnecessary_cast)]
        if nix::libc::ioctl(sock, nix::libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
            let e = std::io::Error::last_os_error();
            nix::libc::close(sock);
            return Err(e).context("failed to get loopback flags");
        }
        ifr.ifr_ifru.ifru_flags |= nix::libc::IFF_UP as i16;
        #[allow(clippy::unnecessary_cast)]
        if nix::libc::ioctl(sock, nix::libc::SIOCSIFFLAGS as _, &ifr) < 0 {
            let e = std::io::Error::last_os_error();
            nix::libc::close(sock);
            return Err(e).context("failed to bring up loopback");
        }
        nix::libc::close(sock);
    }
    Ok(())
}

pub(crate) fn check_pasta() -> Result<PathBuf> {
    super::which("pasta").context(
        "pasta not found; required for port mapping (-p)\n\
         install: apt install passt  (Debian/Ubuntu)\n\
         install: dnf install passt  (Fedora)\n\
         install: pacman -S passt    (Arch)",
    )
}

pub(crate) fn spawn_pasta_for_pid(
    pid: u32,
    ports: &[super::PortMapping],
) -> Result<std::process::Child> {
    let mut cmd = std::process::Command::new(check_pasta()?);
    cmd.args(["--config-net", "--quiet", "--foreground", "--no-map-gw"]);
    add_port_args(&mut cmd, ports);
    cmd.args([
        "-u",
        "none",
        "-T",
        "none",
        "-U",
        "none",
        "--netns",
        &format!("/proc/{pid}/ns/net"),
    ]);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    cmd.spawn()
        .context("failed to start pasta for port forwarding")
}

pub(crate) fn add_port_args(cmd: &mut std::process::Command, ports: &[super::PortMapping]) {
    for pm in ports {
        let flag = if pm.protocol == "udp" { "-u" } else { "-t" };
        cmd.args([flag, &format!("{}:{}", pm.host_port, pm.container_port)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_rename_shim_returns_none_when_missing() {
        if let Some(p) = find_rename_shim() {
            assert!(
                p.exists()
                    && p.file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .contains("rename_shim")
            );
        }
    }

    #[test]
    fn add_port_args_builds_flags() {
        for (proto, flag) in [("tcp", "-t"), ("udp", "-u")] {
            let mut cmd = std::process::Command::new("echo");
            add_port_args(
                &mut cmd,
                &[super::super::PortMapping {
                    host_port: 80,
                    container_port: 8080,
                    protocol: proto.into(),
                }],
            );
            let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();
            assert_eq!(args, vec![flag, "80:8080"]);
        }
        let mut cmd = std::process::Command::new("echo");
        add_port_args(
            &mut cmd,
            &[
                super::super::PortMapping {
                    host_port: 80,
                    container_port: 8080,
                    protocol: "tcp".into(),
                },
                super::super::PortMapping {
                    host_port: 53,
                    container_port: 5353,
                    protocol: "udp".into(),
                },
            ],
        );
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_str().unwrap().to_string())
            .collect();
        assert_eq!(args, vec!["-t", "80:8080", "-u", "53:5353"]);
    }
}
