use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::platform::Target;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRef {
    pub registry: String,
    pub repository: String,
    pub tag: String,
}

impl ImageRef {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            bail!("empty image reference");
        }
        let (name, tag) = match input.rsplit_once(':') {
            Some((n, t)) if !t.contains('/') => (n, t),
            _ => (input, "latest"),
        };
        let (registry, repository) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                if rest.is_empty() {
                    bail!("missing repository name in image reference");
                }
                (
                    if first == "docker.io" {
                        "registry-1.docker.io"
                    } else {
                        first
                    }
                    .to_string(),
                    rest.to_string(),
                )
            }
            _ => ("registry-1.docker.io".to_string(), name.to_string()),
        };
        let repository = if registry == "registry-1.docker.io" && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository
        };
        Ok(Self {
            registry,
            repository,
            tag: tag.to_string(),
        })
    }
    pub fn image_metadata_path(&self, base_dir: &Path, target: &Target) -> PathBuf {
        let base = base_dir
            .join("images")
            .join(&self.registry)
            .join(&self.repository);
        let platformed = base.join(target.slug()).join(format!("{}.json", self.tag));
        if platformed.exists() {
            return platformed;
        }
        // Fallback: check the legacy (non-platformed) path for backward compat.
        let legacy = base.join(format!("{}.json", self.tag));
        if legacy.exists() { legacy } else { platformed }
    }
}

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
    #[serde(default)]
    pub target: Target,
}

/// Read a stored image's manifest + config from the local cache.
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

pub fn walk_stored_images(images_dir: &Path) -> Result<Vec<(String, String, PathBuf)>> {
    let mut results = Vec::new();
    if !images_dir.exists() {
        return Ok(results);
    }
    let mut stack = vec![images_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Some(tag) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".json"))
            else {
                continue;
            };
            let repo = path
                .parent()
                .unwrap_or(&dir)
                .strip_prefix(images_dir)
                .map(|r| r.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            results.push((repo, tag.to_string(), path));
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_image_refs_and_descriptors() {
        for (input, reg, repo, tag) in [
            ("nginx", "registry-1.docker.io", "library/nginx", "latest"),
            (
                "alpine:3.19",
                "registry-1.docker.io",
                "library/alpine",
                "3.19",
            ),
            (
                "myuser/myimage:v1",
                "registry-1.docker.io",
                "myuser/myimage",
                "v1",
            ),
            (
                "ghcr.io/owner/repo:sha-abc123",
                "ghcr.io",
                "owner/repo",
                "sha-abc123",
            ),
            (
                "docker.io/library/ubuntu:22.04",
                "registry-1.docker.io",
                "library/ubuntu",
                "22.04",
            ),
            ("localhost/myimage:dev", "localhost", "myimage", "dev"),
            ("myregistry:5000/repo:tag", "myregistry:5000", "repo", "tag"),
            ("ghcr.io/org/sub/repo:v2", "ghcr.io", "org/sub/repo", "v2"),
            (
                "  nginx:latest  ",
                "registry-1.docker.io",
                "library/nginx",
                "latest",
            ),
        ] {
            let r = ImageRef::parse(input).unwrap();
            assert_eq!(
                (r.registry.as_str(), r.repository.as_str(), r.tag.as_str()),
                (reg, repo, tag),
                "failed for {input}"
            );
        }
        for bad in ["", "  ", "ghcr.io/"] {
            assert!(ImageRef::parse(bad).is_err(), "should reject {bad:?}");
        }
        let host = Target::host();
        assert_eq!(
            ImageRef::parse("nginx")
                .unwrap()
                .image_metadata_path(Path::new("/hb"), &host),
            PathBuf::from(format!(
                "/hb/images/registry-1.docker.io/library/nginx/{}/latest.json",
                host.slug()
            ))
        );

        // Descriptor helpers
        let d = Descriptor {
            media_type: None,
            digest: "sha256:abc123".into(),
            size: 100,
        };
        assert_eq!(d.hex(), "abc123");
        assert_eq!(
            d.layer_dir(Path::new("/hb")),
            Path::new("/hb/layers/sha256/abc123")
        );
        assert_eq!(
            Descriptor {
                media_type: None,
                digest: "md5:x".into(),
                size: 0
            }
            .hex(),
            "md5:x"
        );
    }
    #[test]
    fn walk_stored_images_scenarios() {
        assert!(
            walk_stored_images(Path::new("/nonexistent/path"))
                .unwrap()
                .is_empty()
        );
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(walk_stored_images(tmp.path()).unwrap().is_empty());
        let repo_dir = tmp.path().join("registry/repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::fs::write(repo_dir.join("latest.json"), "{}").unwrap();
        std::fs::write(repo_dir.join("v1.json"), "{}").unwrap();
        std::fs::write(repo_dir.join("notes.txt"), "hi").unwrap();
        let mut r = walk_stored_images(tmp.path()).unwrap();
        r.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(r.len(), 2);
        assert_eq!(
            (r[0].0.as_str(), r[0].1.as_str()),
            ("registry/repo", "latest")
        );
        assert_eq!(r[1].1, "v1");
    }

    #[test]
    fn load_image_valid_missing_and_corrupt() {
        fn desc(d: &str, s: u64) -> Descriptor {
            Descriptor {
                media_type: None,
                digest: d.into(),
                size: s,
            }
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let target = Target::host();
        let img = ImageRef::parse("nginx:1.25").unwrap();
        let stored = StoredImage {
            manifest: Manifest {
                config: desc("sha256:cfg", 10),
                layers: vec![desc("sha256:layer1", 100)],
            },
            config: ImageConfig {
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
        let missing = ImageRef::parse("nonexistent:latest").unwrap();
        assert!(
            format!(
                "{:#}",
                load_image(&missing, tmp.path(), &target).unwrap_err()
            )
            .contains("image not found locally")
        );
        let corrupt = ImageRef::parse("nginx:bad").unwrap();
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
}
