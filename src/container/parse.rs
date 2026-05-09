//! CLI argument parsers for `-p` (port mappings), `--network`, and `-v`
//! (volume mounts). Pure validation — no runtime knowledge.

use super::spec::{NetworkMode, PortMapping, VolumeMount};
use anyhow::{Context, Result, bail};
use std::path::Path;

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
    let parts: Vec<&str> = spec.splitn(4, ':').collect();
    let (source, target, read_only) = match parts.as_slice() {
        [s, t] => (*s, *t, false),
        [s, t, "ro"] => (*s, *t, true),
        [s, t, "rw"] => (*s, *t, false),
        [_, _, opt, ..] => bail!("invalid volume option {opt:?}, expected 'ro' or 'rw'"),
        _ => bail!("invalid volume spec {spec:?}, expected SRC:DST[:ro|rw]"),
    };
    if source.is_empty() {
        bail!("invalid volume spec {spec:?}, empty source");
    }
    if !Path::new(source).is_absolute() {
        bail!("volume source must be absolute: {source:?}");
    }
    validate_volume_target(target)?;
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

/// Validate a volume target path. Same checks every code path that constructs a
/// [`VolumeMount`] must run — CLI parsing, OCI image-declared `Volumes`, and
/// (defensively) the mount-time loop in linux/mounts.rs. Rejects empty paths,
/// non-absolute paths, and any path containing a `..` component (which would
/// escape the container rootfs once joined to `merged`).
pub fn validate_volume_target(target: &str) -> Result<()> {
    if target.is_empty() {
        bail!("volume target must not be empty");
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_volume_target_rejects_bad_paths() {
        validate_volume_target("/data").unwrap();
        validate_volume_target("/var/lib/foo").unwrap();
        for bad in [
            "",
            "data",         // not absolute
            "./data",       // not absolute
            "/data/../etc", // contains ..
            "/../etc",      // contains ..
            "/data/sub/..", // contains ..
        ] {
            assert!(
                validate_volume_target(bad).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn parse_volume_valid_and_invalid() {
        #[cfg(unix)]
        {
            let v = parse_volume("/tmp:/data").unwrap();
            assert_eq!(v.target, "/data");
            assert!(!v.read_only && v.source.starts_with('/'));
            assert!(parse_volume("/tmp:/data:ro").unwrap().read_only);
            assert!(!parse_volume("/tmp:/data:rw").unwrap().read_only);
            assert_eq!(parse_volume("/tmp/../tmp:/data").unwrap().source, "/tmp");

            for bad in [
                "/tmp:",
                "/nonexistent/path:/data",
                "/tmp:/../escape",
                "/tmp:/data/../../../etc",
            ] {
                assert!(parse_volume(bad).is_err(), "should reject {bad:?}");
            }
        }
        #[cfg(windows)]
        {
            // parse_volume uses splitn(4, ':') which conflicts with Windows drive
            // letters (C:\path contains ':').  Volume specs use container-oriented
            // paths (Linux-style) and volumes on Windows are copied into the merged
            // dir rather than bind-mounted, so drive-letter source paths are not
            // expected.  The Unix happy-path tests (which use /tmp:/data) can't run
            // here because Path::is_absolute() rejects Unix paths on Windows.

            // Target must start with '/' (container path) — this works everywhere
            assert!(parse_volume("relative:/data").is_err());
        }
        // Platform-independent error cases
        for bad in ["", ":/data", "relative:/data"] {
            assert!(parse_volume(bad).is_err(), "should reject {bad:?}");
        }
        // These error cases use ':' which on Windows would split differently,
        // so they are Unix-only
        #[cfg(unix)]
        for bad in ["/a:/b:ro:extra", "/tmp:/data:xx", "/tmp:relative"] {
            assert!(parse_volume(bad).is_err(), "should reject {bad:?}");
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
}
