#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(unix))]
mod windows;

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

use crate::image::{ImageConfig, ImageRef, Manifest, StoredImage};
use crate::platform::{Os, Target};

#[cfg(target_os = "linux")]
pub(crate) use linux::container_init;

pub fn gc_stale_containers(base_dir: &Path) -> usize {
    #[cfg(target_os = "linux")]
    {
        linux::gc_stale_containers(base_dir)
    }
    #[cfg(not(target_os = "linux"))]
    {
        gc_simple(base_dir)
    }
}

/// Simple GC for non-Linux hosts: walk containers/, remove_dir_all each subdir.
/// Used by Windows (and future macOS) where there are no overlayfs mounts or flocks.
#[allow(dead_code)] // called from #[cfg(not(target_os = "linux"))] branch + tests
fn gc_simple(base_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(base_dir.join("containers")) else {
        return 0;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
    0
}

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
    #[serde(default)]
    pub target: Target,
}

pub fn run(spec: ContainerSpec) -> Result<i32> {
    match spec.target.os {
        #[cfg(target_os = "linux")]
        Os::Linux => linux::run(spec),
        #[cfg(not(target_os = "linux"))]
        Os::Linux => bail!("Linux containers require a Linux host"),
        #[cfg(not(unix))]
        Os::Windows => windows::run(spec),
        #[cfg(unix)]
        Os::Windows => bail!("Windows containers require a Windows host"),
        Os::Darwin => bail!("Darwin containers are not yet supported"),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn run_prepared(spec: ContainerSpec) -> Result<i32> {
    match spec.target.os {
        Os::Linux => linux::run_prepared(spec),
        Os::Windows => bail!("Windows containers require a Windows host"),
        Os::Darwin => bail!("Darwin containers are not yet supported"),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn set_pdeathsig() -> std::io::Result<()> {
    linux::set_pdeathsig()
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

fn build_env_vars(
    cc: Option<&crate::image::ContainerConfig>,
    user_env: &[String],
    target: &Target,
) -> Result<Vec<String>> {
    let mut env_vars = cc
        .and_then(|c| c.env.as_deref())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_vec())
        .unwrap_or_else(|| match target.os {
            Os::Windows => vec![],
            _ => vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()],
        });
    if target.os != Os::Windows {
        for (key, default) in [("HOME", "/root"), ("TERM", "xterm")] {
            if env_find_mut(&mut env_vars, key).is_none() {
                env_vars.push(format!("{key}={default}"));
            }
        }
    }
    apply_env_overrides(env_vars, user_env)
}

pub fn load_image(
    image_ref: &ImageRef,
    base_dir: &Path,
    target: &Target,
) -> Result<(Manifest, ImageConfig)> {
    let path = image_ref.image_metadata_path(base_dir, target);
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

pub fn parse_volume(spec: &str) -> Result<VolumeMount> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (source, target, read_only) = match parts.len() {
        2 => (parts[0], parts[1], false),
        3 => match parts[2] {
            "ro" => (parts[0], parts[1], true),
            "rw" => (parts[0], parts[1], false),
            opt => bail!("invalid volume option {opt:?}, expected 'ro' or 'rw'"),
        },
        _ => bail!("invalid volume spec {spec:?}, expected SRC:DST[:ro|rw]"),
    };
    if source.is_empty() || target.is_empty() {
        bail!("invalid volume spec {spec:?}, empty source or target");
    }
    if !Path::new(source).is_absolute() {
        bail!("volume source must be absolute: {source:?}");
    }
    if !target.starts_with('/') {
        bail!("volume target must be absolute: {target:?}");
    }
    if Path::new(target)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        bail!("volume target must not contain '..': {target:?}");
    }
    if !Path::new(source).exists() {
        bail!("volume source does not exist: {source:?}");
    }
    Ok(VolumeMount {
        source: Path::new(source)
            .canonicalize()
            .with_context(|| format!("failed to resolve volume source {source:?}"))?
            .to_string_lossy()
            .to_string(),
        target: target.to_string(),
        read_only,
    })
}

#[allow(dead_code)] // used by #[cfg(not(unix))] Windows module + tests
pub(crate) fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((s, d)) = stack.pop() {
        for entry in std::fs::read_dir(&s).with_context(|| format!("read {}", s.display()))? {
            let entry = entry?;
            let (sp, dp) = (entry.path(), d.join(entry.file_name()));
            let ft = entry.file_type()?;
            if ft.is_dir() {
                let _ = std::fs::create_dir(&dp);
                stack.push((sp, dp));
            } else if ft.is_symlink() {
                let tgt = std::fs::read_link(&sp)?;
                let _ = std::fs::remove_file(&dp);
                crate::registry::create_symlink(&tgt, &dp)?;
            } else {
                let _ = std::fs::remove_file(&dp);
                if std::fs::hard_link(&sp, &dp).is_err() {
                    std::fs::copy(&sp, &dp).with_context(|| format!("copy {}", sp.display()))?;
                }
            }
        }
    }
    Ok(())
}

/// Simple cleanup guard for non-Linux runtimes (Windows, future macOS).
/// Removes the container directory on drop. The Linux runtime has its own
/// CleanupGuard with overlay unmount and cgroup cleanup.
#[allow(dead_code)] // used by #[cfg(not(unix))] Windows module + tests
pub(crate) struct SimpleCleanupGuard(pub PathBuf);
impl Drop for SimpleCleanupGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[allow(dead_code)]
fn which(name: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    let separator = ';';
    #[cfg(not(windows))]
    let separator = ':';
    std::env::var_os("PATH")?
        .to_str()?
        .split(separator)
        .map(|dir| PathBuf::from(dir).join(name))
        .find(|p| p.is_file())
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
        let target = crate::platform::Target::host();
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
            target: target.clone(),
        };
        let path = img.image_metadata_path(tmp.path(), &target);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        let (m, _) = load_image(&img, tmp.path(), &target).unwrap();
        assert_eq!(m.layers[0].digest, "sha256:layer1");
        let missing = crate::image::ImageRef::parse("nonexistent:latest").unwrap();
        assert!(
            format!(
                "{:#}",
                load_image(&missing, tmp.path(), &target).unwrap_err()
            )
            .contains("image not found locally")
        );
        let corrupt = crate::image::ImageRef::parse("nginx:bad").unwrap();
        let cp = corrupt.image_metadata_path(tmp.path(), &target);
        std::fs::create_dir_all(cp.parent().unwrap()).unwrap();
        std::fs::write(&cp, "not json").unwrap();
        assert!(
            format!(
                "{:#}",
                load_image(&corrupt, tmp.path(), &target).unwrap_err()
            )
            .contains("failed to parse")
        );
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
            target: crate::platform::Target::host(),
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
    #[cfg(unix)]
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

    #[test]
    fn build_env_vars_defaults() {
        let linux = crate::platform::Target::host();
        // No image config — should get default PATH, HOME, and TERM
        let vars = build_env_vars(None, &[], &linux).unwrap();
        assert!(vars.iter().any(|v| v.starts_with("PATH=")));
        assert!(vars.iter().any(|v| v == "HOME=/root"));
        assert!(vars.iter().any(|v| v == "TERM=xterm"));

        // Windows target — no Linux defaults injected
        let win = crate::platform::Target::parse("windows/amd64").unwrap();
        let wvars = build_env_vars(None, &[], &win).unwrap();
        assert!(wvars.is_empty());

        // Darwin target — gets same Unix defaults as Linux
        let darwin = crate::platform::Target::parse("darwin/arm64").unwrap();
        let dvars = build_env_vars(None, &[], &darwin).unwrap();
        assert!(dvars.iter().any(|v| v.starts_with("PATH=")));
        assert!(dvars.iter().any(|v| v == "HOME=/root"));
        assert!(dvars.iter().any(|v| v == "TERM=xterm"));
    }

    #[test]
    fn build_env_vars_preserves_image_env() {
        let cc = crate::image::ContainerConfig {
            env: Some(vec![
                "PATH=/custom/bin".into(),
                "HOME=/app".into(),
                "APP_MODE=production".into(),
            ]),
            ..Default::default()
        };
        let vars = build_env_vars(Some(&cc), &[], &crate::platform::Target::host()).unwrap();
        assert!(vars.iter().any(|v| v == "PATH=/custom/bin"));
        assert!(vars.iter().any(|v| v == "HOME=/app"));
        assert!(vars.iter().any(|v| v == "APP_MODE=production"));
        // TERM should be injected since image didn't set it
        assert!(vars.iter().any(|v| v == "TERM=xterm"));
    }

    #[test]
    fn build_env_vars_user_overrides() {
        let cc = crate::image::ContainerConfig {
            env: Some(vec!["PATH=/usr/bin".into(), "FOO=old".into()]),
            ..Default::default()
        };
        let vars = build_env_vars(
            Some(&cc),
            &["FOO=new".into(), "BAR=added".into()],
            &crate::platform::Target::host(),
        )
        .unwrap();
        assert!(vars.iter().any(|v| v == "FOO=new"));
        assert!(vars.iter().any(|v| v == "BAR=added"));
        assert!(!vars.iter().any(|v| v == "FOO=old"));
    }

    #[test]
    fn build_env_vars_empty_image_env() {
        // Empty vec should trigger default PATH on Linux
        let cc = crate::image::ContainerConfig {
            env: Some(vec![]),
            ..Default::default()
        };
        let vars = build_env_vars(Some(&cc), &[], &crate::platform::Target::host()).unwrap();
        assert!(
            vars.iter()
                .any(|v| v == "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        );

        // Empty vec on Windows — no Linux fallback
        let win = crate::platform::Target::parse("windows/amd64").unwrap();
        let wvars = build_env_vars(Some(&cc), &[], &win).unwrap();
        assert!(!wvars.iter().any(|v| v.starts_with("PATH=")));
        assert!(!wvars.iter().any(|v| v.starts_with("HOME=")));
    }

    #[test]
    fn parse_volume_valid() {
        let v = parse_volume("/tmp:/data").unwrap();
        assert_eq!(v.target, "/data");
        assert!(!v.read_only && v.source.starts_with('/'));
        assert!(parse_volume("/tmp:/data:ro").unwrap().read_only);
        assert!(!parse_volume("/tmp:/data:rw").unwrap().read_only);
        assert_eq!(parse_volume("/tmp/../tmp:/data").unwrap().source, "/tmp");
    }

    #[test]
    fn parse_volume_rejects_invalid() {
        for bad in [
            "",
            ":/data",
            "/tmp:",
            "relative:/data",
            "/tmp:relative",
            "/a:/b:ro:extra",
            "/tmp:/data:xx",
            "/nonexistent/path:/data",
            "/tmp:/../escape",
            "/tmp:/data/../../../etc",
        ] {
            assert!(parse_volume(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn copy_dir_recursive_basic() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (src, dst) = (tmp.path().join("src"), tmp.path().join("dst"));
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), "hello").unwrap();
        std::fs::write(src.join("sub/b.txt"), "world").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a.txt", src.join("link.txt")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        copy_dir_recursive(&src, &dst).unwrap();
        assert_eq!(std::fs::read_to_string(dst.join("a.txt")).unwrap(), "hello");
        assert_eq!(
            std::fs::read_to_string(dst.join("sub/b.txt")).unwrap(),
            "world"
        );
        #[cfg(unix)]
        {
            assert!(dst.join("link.txt").is_symlink());
            assert_eq!(
                std::fs::read_link(dst.join("link.txt"))
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "a.txt"
            );
        }
        // Overwrite: second copy replaces shared file
        std::fs::write(src.join("a.txt"), "new").unwrap();
        copy_dir_recursive(&src, &dst).unwrap();
        assert_eq!(std::fs::read_to_string(dst.join("a.txt")).unwrap(), "new");
    }

    #[test]
    fn gc_simple_removes_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let containers = tmp.path().join("containers");
        std::fs::create_dir_all(containers.join("stale1")).unwrap();
        std::fs::create_dir_all(containers.join("stale2/sub")).unwrap();
        // Files under containers/ are left alone
        std::fs::write(containers.join("not_a_dir"), "x").unwrap();
        gc_simple(tmp.path());
        assert!(!containers.join("stale1").exists());
        assert!(!containers.join("stale2").exists());
        assert!(containers.join("not_a_dir").exists());
    }

    #[test]
    fn gc_simple_missing_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        // No containers/ directory — should not panic
        assert_eq!(gc_simple(tmp.path()), 0);
    }

    #[test]
    fn simple_cleanup_guard_removes_on_drop() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("ctest");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        {
            let _guard = SimpleCleanupGuard(dir.clone());
            assert!(dir.exists());
        }
        assert!(!dir.exists());
    }
}
