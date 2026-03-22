use anyhow::{Context, Result, bail};
use nix::mount::{MsFlags, mount};
use std::fs::{self, File};
use std::path::Path;

use super::VolumeMount;

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
        bail!("invalid volume spec {spec:?}, source and target must not be empty");
    }
    if !source.starts_with('/') {
        bail!("volume source must be an absolute path: {source:?}");
    }
    if !target.starts_with('/') {
        bail!("volume target must be an absolute path: {target:?}");
    }
    if Path::new(target).components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        bail!("volume target must not contain '..': {target:?}");
    }
    let source_path = Path::new(source);
    if !source_path.exists() {
        bail!("volume source does not exist: {source:?}");
    }
    Ok(VolumeMount {
        source: source_path
            .canonicalize()
            .with_context(|| format!("failed to resolve volume source {source:?}"))?
            .to_string_lossy()
            .to_string(),
        target: target.to_string(),
        read_only,
    })
}

pub(super) fn mount_volumes(merged: &Path, volumes: &[VolumeMount]) -> Result<()> {
    for vol in volumes {
        let target = merged.join(vol.target.trim_start_matches('/'));
        if !target.starts_with(merged) {
            bail!("volume target escapes container rootfs: {}", vol.target);
        }

        if vol.source == "tmpfs" {
            fs::create_dir_all(&target)?;
            mount(Some("tmpfs"), &target, Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV, Some("size=67108864"))
                .with_context(|| format!("failed to mount tmpfs volume at {}", target.display()))?;
            continue;
        }

        let source_meta = fs::metadata(&vol.source)
            .with_context(|| format!("volume source inaccessible: {}", vol.source))?;
        if source_meta.is_file() {
            if let Some(parent) = target.parent() { fs::create_dir_all(parent)?; }
            if !target.exists() { File::create(&target)?; }
        } else {
            fs::create_dir_all(&target)?;
        }

        mount(Some(vol.source.as_str()), &target, None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)
            .with_context(|| format!("failed to bind-mount {} at {}", vol.source, target.display()))?;

        let mut remount_flags = MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_REMOUNT
            | MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
        if vol.read_only { remount_flags |= MsFlags::MS_RDONLY; }
        match mount(None::<&str>, &target, None::<&str>, remount_flags, None::<&str>) {
            Ok(()) => {}
            Err(nix::errno::Errno::EPERM) if vol.read_only => {
                eprintln!("warning: read-only remount not supported for {} (rootless limitation)", vol.target);
            }
            Err(e) => return Err(e).with_context(|| format!("failed to remount {} with security flags", target.display())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "", ":/data", "/tmp:", "relative:/data", "/tmp:relative",
            "/tmp:/data:xx", "/nonexistent/path:/data",
            "/tmp:/../escape", "/tmp:/data/../../../etc",
        ] {
            assert!(parse_volume(bad).is_err(), "should reject {bad:?}");
        }
    }
}
