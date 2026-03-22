use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ── Image reference ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRef {
    pub registry: String,
    pub repository: String,
    pub tag: String,
}

impl ImageRef {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() { bail!("empty image reference"); }
        let (name, tag) = match input.rsplit_once(':') {
            Some((n, t)) if !t.contains('/') => (n, t),
            _ => (input, "latest"),
        };
        let (registry, repository) = match name.split_once('/') {
            Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => {
                if rest.is_empty() { bail!("missing repository name in image reference"); }
                let reg = if first == "docker.io" { "registry-1.docker.io" } else { first };
                (reg.to_string(), rest.to_string())
            }
            _ => ("registry-1.docker.io".to_string(), name.to_string()),
        };
        let repository = if registry == "registry-1.docker.io" && !repository.contains('/') {
            format!("library/{repository}")
        } else { repository };
        Ok(Self { registry, repository, tag: tag.to_string() })
    }

    pub fn image_metadata_path(&self, base_dir: &Path) -> PathBuf {
        base_dir.join("images").join(&self.registry).join(&self.repository)
            .join(format!("{}.json", self.tag))
    }
}

// ── OCI manifest / config types ────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: Option<String>,
    pub digest: String,
    pub size: u64,
}

impl Descriptor {
    pub fn hex(&self) -> &str {
        self.digest.strip_prefix("sha256:").unwrap_or(&self.digest)
    }
    pub fn layer_dir(&self, base_dir: &Path) -> PathBuf {
        base_dir.join("layers/sha256").join(self.hex())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ImageConfig {
    pub config: Option<ContainerConfig>,
    pub rootfs: Option<RootFs>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct ContainerConfig {
    pub cmd: Option<Vec<String>>,
    pub entrypoint: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub working_dir: Option<String>,
    pub stop_signal: Option<String>,
    pub user: Option<String>,
    pub volumes: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RootFs {
    #[serde(rename = "type")]
    pub fs_type: String,
    pub diff_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StoredImage {
    pub manifest: Manifest,
    pub config: ImageConfig,
}

// ── Image storage ──────────────────────────────────────────────────

pub fn walk_stored_images(images_dir: &Path) -> Result<Vec<(String, String, PathBuf)>> {
    let mut results = Vec::new();
    if !images_dir.exists() { return Ok(results); }
    let mut stack = vec![images_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { stack.push(path); continue; }
            let Some(tag) = path.file_name().and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".json")) else { continue };
            let repo = path.parent().unwrap_or(&dir)
                .strip_prefix(images_dir).map_or_else(|_| String::new(), |r| r.to_string_lossy().to_string());
            results.push((repo, tag.to_string(), path));
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_image_refs() {
        for (input, reg, repo, tag) in [
            ("nginx", "registry-1.docker.io", "library/nginx", "latest"),
            ("alpine:3.19", "registry-1.docker.io", "library/alpine", "3.19"),
            ("myuser/myimage:v1", "registry-1.docker.io", "myuser/myimage", "v1"),
            ("ghcr.io/owner/repo:sha-abc123", "ghcr.io", "owner/repo", "sha-abc123"),
            ("docker.io/library/ubuntu:22.04", "registry-1.docker.io", "library/ubuntu", "22.04"),
            ("localhost/myimage:dev", "localhost", "myimage", "dev"),
            ("myregistry:5000/repo:tag", "myregistry:5000", "repo", "tag"),
        ] {
            let r = ImageRef::parse(input).unwrap();
            assert_eq!((r.registry.as_str(), r.repository.as_str(), r.tag.as_str()), (reg, repo, tag), "failed for {input}");
        }
    }

    #[test]
    fn parse_image_ref_errors() {
        for bad in ["", "  ", "ghcr.io/"] { assert!(ImageRef::parse(bad).is_err(), "should reject {bad:?}"); }
    }

    #[test]
    fn parse_image_ref_with_nested_repo() {
        let r = ImageRef::parse("ghcr.io/org/sub/repo:v2").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "org/sub/repo");
        assert_eq!(r.tag, "v2");
    }

    #[test]
    fn parse_image_ref_whitespace_trimmed() {
        let r = ImageRef::parse("  nginx:latest  ").unwrap();
        assert_eq!(r.repository, "library/nginx");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_image_ref_docker_io_rewrite() {
        // docker.io should be rewritten to registry-1.docker.io
        let r = ImageRef::parse("docker.io/myuser/myimage:v1").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "myuser/myimage");
    }

    #[test]
    fn image_metadata_path_layout() {
        let r = ImageRef::parse("nginx").unwrap();
        assert_eq!(r.image_metadata_path(Path::new("/tmp/hb")),
            PathBuf::from("/tmp/hb/images/registry-1.docker.io/library/nginx/latest.json"));
    }

    #[test]
    fn descriptor_helpers() {
        let d = Descriptor { media_type: None, digest: "sha256:abc123def456".into(), size: 100 };
        assert_eq!(d.hex(), "abc123def456");
        assert_eq!(d.layer_dir(Path::new("/hb")), Path::new("/hb/layers/sha256/abc123def456"));
        let d = Descriptor { media_type: None, digest: "md5:abcdef".into(), size: 100 };
        assert_eq!(d.hex(), "md5:abcdef");
    }

    #[test]
    fn walk_stored_images_scenarios() {
        assert!(walk_stored_images(Path::new("/nonexistent/path")).unwrap().is_empty());
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(walk_stored_images(tmp.path()).unwrap().is_empty());
        let repo_dir = tmp.path().join("registry/repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::fs::write(repo_dir.join("latest.json"), "{}").unwrap();
        std::fs::write(repo_dir.join("v1.json"), "{}").unwrap();
        std::fs::write(repo_dir.join("notes.txt"), "hi").unwrap();
        let mut results = walk_stored_images(tmp.path()).unwrap();
        results.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(results.len(), 2);
        assert_eq!((results[0].0.as_str(), results[0].1.as_str()), ("registry/repo", "latest"));
        assert_eq!(results[1].1, "v1");
    }
}
