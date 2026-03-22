mod cleanup;
mod init;
mod mounts;
mod process;

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

use crate::image::{ImageConfig, ImageRef, Manifest, StoredImage};

pub use cleanup::gc_stale_containers;
pub(crate) use init::container_init;
pub use mounts::parse_volume;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VolumeMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NetworkMode {
    Host,
    None,
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ContainerSpec {
    pub id: String,
    pub image_ref: ImageRef,
    pub manifest: Manifest,
    pub config: ImageConfig,
    pub base_dir: PathBuf,
    pub user_cmd: Vec<String>,
    pub user_env: Vec<String>,
    pub volumes: Vec<VolumeMount>,
    pub network_mode: NetworkMode,
    pub port_mappings: Vec<PortMapping>,
    pub external_netns: bool,
    pub rootless: bool,
}

pub fn run(spec: ContainerSpec) -> Result<i32> {
    if spec.rootless {
        process::run_rootless_unshare(spec)
    } else {
        run_prepared(spec)
    }
}

pub(crate) fn run_prepared(spec: ContainerSpec) -> Result<i32> {
    let cc = spec.config.config.as_ref();
    let workdir = cc.and_then(|c| c.working_dir.as_deref()).unwrap_or("/");
    let stop_signal = cc
        .and_then(|c| c.stop_signal.as_deref())
        .unwrap_or("SIGTERM");
    let user = cc.and_then(|c| c.user.clone()).filter(|u| !u.is_empty());

    let argv = build_argv(cc, spec.user_cmd)?;

    let mut env_vars = cc
        .and_then(|c| c.env.as_deref())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_vec())
        .unwrap_or_else(|| {
            vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()]
        });
    for (key, default) in [("HOME", "/root"), ("TERM", "xterm")] {
        if env_find_mut(&mut env_vars, key).is_none() {
            env_vars.push(format!("{key}={default}"));
        }
    }
    let mut env_vars = apply_env_overrides(env_vars, &spec.user_env)?;
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

fn apply_env_overrides(mut vars: Vec<String>, overrides: &[String]) -> Result<Vec<String>> {
    for ov in overrides {
        let Some((key, _)) = ov.split_once('=') else {
            bail!("invalid env override {ov:?}, expected KEY=VALUE")
        };
        if key.is_empty() {
            bail!("invalid env override {ov:?}, empty key");
        }
        match env_find_mut(&mut vars, key) {
            Some(existing) => ov.clone_into(existing),
            None => vars.push(ov.clone()),
        }
    }
    Ok(vars)
}

pub(super) fn env_find_mut<'a>(vars: &'a mut [String], key: &str) -> Option<&'a mut String> {
    vars.iter_mut()
        .find(|v| v.split_once('=').is_some_and(|(k, _)| k == key))
}

fn build_argv(
    cc: Option<&crate::image::ContainerConfig>,
    user_cmd: Vec<String>,
) -> Result<Vec<String>> {
    let tail = if user_cmd.is_empty() {
        cc.and_then(|c| c.cmd.clone()).unwrap_or_default()
    } else {
        user_cmd
    };
    let argv = match cc.and_then(|c| c.entrypoint.as_deref()) {
        Some(ep) => ep.iter().cloned().chain(tail).collect(),
        None => tail,
    };
    if argv.is_empty() {
        bail!("no CMD or ENTRYPOINT in image config and no command provided");
    }
    Ok(argv)
}

pub fn load_image(image_ref: &ImageRef, base_dir: &Path) -> Result<(Manifest, ImageConfig)> {
    let path = image_ref.image_metadata_path(base_dir);
    let data = std::fs::read(&path).with_context(|| {
        format!(
            "image not found locally: {}/{}/{}",
            image_ref.registry, image_ref.repository, image_ref.tag
        )
    })?;
    let stored: StoredImage = serde_json::from_slice(&data)
        .with_context(|| format!("failed to parse stored image metadata: {}", path.display()))?;
    Ok((stored.manifest, stored.config))
}
pub fn parse_port(spec: &str) -> Result<PortMapping> {
    let (port_part, protocol) = match spec.rsplit_once('/') {
        Some((p, proto)) if proto == "tcp" || proto == "udp" => (p, proto.to_string()),
        Some((_, proto)) => bail!("invalid protocol {proto:?}, expected 'tcp' or 'udp'"),
        None => (spec, "tcp".to_string()),
    };
    let (host, cont) = port_part
        .split_once(':')
        .context("invalid port mapping, expected HOST_PORT:CONTAINER_PORT")?;
    let host_port: u16 = host
        .parse()
        .with_context(|| format!("invalid host port: {host:?}"))?;
    let container_port: u16 = cont
        .parse()
        .with_context(|| format!("invalid container port: {cont:?}"))?;
    if host_port == 0 || container_port == 0 {
        bail!("port numbers must be non-zero");
    }
    Ok(PortMapping {
        host_port,
        container_port,
        protocol,
    })
}
pub fn parse_network_mode(s: &str) -> Result<NetworkMode> {
    match s {
        "host" => Ok(NetworkMode::Host),
        "none" => Ok(NetworkMode::None),
        _ => bail!("invalid network mode {s:?}, expected 'host' or 'none'"),
    }
}
/// Bring up the loopback network interface via ioctl.
fn bring_up_loopback() -> Result<()> {
    unsafe {
        let sock = nix::libc::socket(nix::libc::AF_INET, nix::libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to create socket");
        }
        let mut ifr: nix::libc::ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l' as i8;
        ifr.ifr_name[1] = b'o' as i8;
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
fn check_pasta() -> Result<PathBuf> {
    which("pasta").context(
        "pasta not found; required for port mapping (-p)\n\
         install: apt install passt  (Debian/Ubuntu)\n\
         install: dnf install passt  (Fedora)\n\
         install: pacman -S passt    (Arch)",
    )
}
fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| PathBuf::from(dir).join(name))
        .find(|p| p.is_file())
}
fn spawn_pasta_for_pid(pid: u32, ports: &[PortMapping]) -> Result<std::process::Child> {
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
fn add_port_args(cmd: &mut std::process::Command, ports: &[PortMapping]) {
    for pm in ports {
        let flag = if pm.protocol == "udp" { "-u" } else { "-t" };
        cmd.args([flag, &format!("{}:{}", pm.host_port, pm.container_port)]);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn env_overrides_all_cases() {
        let ov = apply_env_overrides;
        assert_eq!(
            ov(
                vec!["PATH=/usr/bin".into(), "HOME=/root".into()],
                &["HOME=/home/user".into()]
            )
            .unwrap(),
            vec!["PATH=/usr/bin", "HOME=/home/user"]
        );
        assert_eq!(
            ov(vec!["PATH=/usr/bin".into()], &["FOO=bar".into()]).unwrap(),
            vec!["PATH=/usr/bin", "FOO=bar"]
        );
        assert_eq!(
            ov(vec!["PATH=/usr/bin".into()], &["FOO=a=b=c".into()]).unwrap(),
            vec!["PATH=/usr/bin", "FOO=a=b=c"]
        );
        assert_eq!(ov(vec![], &["EMPTY=".into()]).unwrap(), vec!["EMPTY="]);
        assert_eq!(
            ov(
                vec!["A=1".into(), "B=2".into(), "C=3".into()],
                &["B=new".into(), "D=4".into(), "A=replaced".into()]
            )
            .unwrap(),
            vec!["A=replaced", "B=new", "C=3", "D=4"]
        );
        let orig = vec!["PATH=/usr/bin".into(), "HOME=/root".into()];
        assert_eq!(ov(orig.clone(), &[]).unwrap(), orig);
        assert!(ov(vec![], &["NOEQUALS".into()]).is_err());
        assert!(ov(vec![], &["=value".into()]).is_err());
    }
    #[test]
    fn env_find_mut_cases() {
        let mut vars = vec![
            "PATH=/usr/bin".into(),
            "HOME=/root".into(),
            "TERM=xterm".into(),
        ];
        assert_eq!(
            env_find_mut(&mut vars, "HOME").unwrap().as_str(),
            "HOME=/root"
        );
        assert_eq!(
            env_find_mut(&mut vars, "PATH").unwrap().as_str(),
            "PATH=/usr/bin"
        );
        for key in ["MISSING", "PAT", "PATHX"] {
            assert!(env_find_mut(&mut vars, key).is_none());
        }
        assert!(env_find_mut(&mut Vec::<String>::new(), "ANY").is_none());
    }
    #[test]
    fn load_image_valid_missing_and_corrupt() {
        let tmp = tempfile::TempDir::new().unwrap();
        let desc = |d: &str, s| crate::image::Descriptor {
            media_type: None,
            digest: d.into(),
            size: s,
        };
        let img = crate::image::ImageRef::parse("nginx:1.25").unwrap();
        let stored = crate::image::StoredImage {
            manifest: crate::image::Manifest {
                config: desc("sha256:cfg", 10),
                layers: vec![desc("sha256:layer1", 100)],
            },
            config: crate::image::ImageConfig {
                config: None,
                rootfs: None,
            },
        };
        let path = img.image_metadata_path(tmp.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        let (m, _) = load_image(&img, tmp.path()).unwrap();
        assert_eq!(m.layers[0].digest, "sha256:layer1");
        let missing = crate::image::ImageRef::parse("nonexistent:latest").unwrap();
        assert!(
            format!("{:#}", load_image(&missing, tmp.path()).unwrap_err())
                .contains("image not found locally")
        );
        let corrupt = crate::image::ImageRef::parse("nginx:bad").unwrap();
        let cp = corrupt.image_metadata_path(tmp.path());
        std::fs::create_dir_all(cp.parent().unwrap()).unwrap();
        std::fs::write(&cp, "not json").unwrap();
        assert!(
            format!("{:#}", load_image(&corrupt, tmp.path()).unwrap_err())
                .contains("failed to parse")
        );
    }
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
    fn container_spec_serialisation_round_trip() {
        let desc = |d: &str, s| crate::image::Descriptor {
            media_type: None,
            digest: d.into(),
            size: s,
        };
        let spec = ContainerSpec {
            id: "test123".into(),
            image_ref: crate::image::ImageRef::parse("alpine:3.19").unwrap(),
            manifest: crate::image::Manifest {
                config: desc("sha256:cfg", 10),
                layers: vec![],
            },
            config: crate::image::ImageConfig {
                config: None,
                rootfs: None,
            },
            base_dir: PathBuf::from("/tmp/hb"),
            user_cmd: vec!["sh".into()],
            user_env: vec!["FOO=bar".into()],
            volumes: vec![],
            network_mode: NetworkMode::None,
            port_mappings: vec![],
            external_netns: false,
            rootless: true,
        };
        let back: ContainerSpec =
            serde_json::from_str(&serde_json::to_string(&spec).unwrap()).unwrap();
        assert_eq!(back.id, "test123");
        assert!(back.rootless);
        assert_eq!(back.network_mode, NetworkMode::None);
    }
    #[test]
    fn build_argv_success_cases() {
        let mk = |ep, cmd| crate::image::ContainerConfig {
            entrypoint: ep,
            cmd,
            ..Default::default()
        };
        let cc = mk(None, Some(vec!["default-cmd".into()]));
        assert_eq!(
            build_argv(Some(&cc), vec!["custom".into()]).unwrap(),
            ["custom"]
        );
        let cc = mk(
            Some(vec!["/ep.sh".into()]),
            Some(vec!["a1".into(), "a2".into()]),
        );
        assert_eq!(
            build_argv(Some(&cc), vec![]).unwrap(),
            ["/ep.sh", "a1", "a2"]
        );
        let cc = mk(Some(vec!["/ep.sh".into()]), Some(vec!["default".into()]));
        assert_eq!(
            build_argv(Some(&cc), vec!["override".into()]).unwrap(),
            ["/ep.sh", "override"]
        );
        let cc = mk(Some(vec!["/bin/server".into()]), None);
        assert_eq!(build_argv(Some(&cc), vec![]).unwrap(), ["/bin/server"]);
        let cc = mk(
            None,
            Some(vec!["/bin/sh".into(), "-c".into(), "echo hi".into()]),
        );
        assert_eq!(
            build_argv(Some(&cc), vec![]).unwrap(),
            ["/bin/sh", "-c", "echo hi"]
        );
        assert_eq!(
            build_argv(None, vec!["/bin/bash".into()]).unwrap(),
            ["/bin/bash"]
        );
    }
    #[test]
    fn build_argv_error_cases() {
        let cc = crate::image::ContainerConfig::default();
        for e in [
            build_argv(Some(&cc), vec![]).unwrap_err(),
            build_argv(None, vec![]).unwrap_err(),
        ] {
            assert!(format!("{e}").contains("no CMD or ENTRYPOINT"));
        }
    }
    #[test]
    fn parse_port_valid_and_invalid() {
        for (spec, hp, cp, proto) in [
            ("8080:80", 8080, 80, "tcp"),
            ("5353:53/udp", 5353, 53, "udp"),
            ("3000:3000/tcp", 3000, 3000, "tcp"),
            ("65535:65535", 65535, 65535, "tcp"),
            ("1:1", 1, 1, "tcp"),
        ] {
            let pm = parse_port(spec).unwrap();
            assert_eq!(
                (pm.host_port, pm.container_port, pm.protocol.as_str()),
                (hp, cp, proto),
                "spec={spec}"
            );
        }
        for bad in [
            "0:80",
            "8080:0",
            "8080",
            "abc:80",
            "8080:abc",
            "8080:80/sctp",
            "65536:80",
        ] {
            assert!(parse_port(bad).is_err(), "should reject {bad:?}");
        }
    }
    #[test]
    fn parse_network_mode_valid_and_invalid() {
        assert_eq!(parse_network_mode("host").unwrap(), NetworkMode::Host);
        assert_eq!(parse_network_mode("none").unwrap(), NetworkMode::None);
        for bad in ["bridge", ""] {
            assert!(parse_network_mode(bad).is_err());
        }
    }
    #[test]
    fn add_port_args_builds_flags() {
        for (proto, flag) in [("tcp", "-t"), ("udp", "-u")] {
            let mut cmd = std::process::Command::new("echo");
            add_port_args(
                &mut cmd,
                &[PortMapping {
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
                PortMapping {
                    host_port: 80,
                    container_port: 8080,
                    protocol: "tcp".into(),
                },
                PortMapping {
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
    #[test]
    fn which_lookup() {
        assert!(which("env").unwrap().is_file());
        assert!(which("hippobox_nonexistent_binary_xyz").is_none());
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("mytool"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            tmp.path().join("mytool"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let original = std::env::var_os("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", tmp.path().display(), original.to_string_lossy());
        unsafe {
            std::env::set_var("PATH", &new_path);
        }
        let result = which("mytool");
        unsafe {
            std::env::set_var("PATH", &original);
        }
        assert_eq!(result.unwrap().file_name().unwrap(), "mytool");
    }
    #[test]
    fn serialisation_round_trips() {
        for mode in [NetworkMode::Host, NetworkMode::None] {
            assert_eq!(
                serde_json::from_str::<NetworkMode>(&serde_json::to_string(&mode).unwrap())
                    .unwrap(),
                mode
            );
        }
        let pm = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".into(),
        };
        let back: PortMapping = serde_json::from_str(&serde_json::to_string(&pm).unwrap()).unwrap();
        assert_eq!(
            (back.host_port, back.container_port, back.protocol.as_str()),
            (8080, 80, "tcp")
        );
    }
}
