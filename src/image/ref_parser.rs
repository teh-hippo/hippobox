use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

/// A parsed container image reference.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ImageRef {
    /// Registry host (e.g. "registry-1.docker.io", "ghcr.io", "myregistry:5000")
    pub registry: String,
    /// Repository path (e.g. "library/nginx", "user/repo")
    pub repository: String,
    /// Tag (e.g. "latest", "v1.0")
    pub tag: String,
}

impl ImageRef {
    /// Parse an image reference string like "docker.io/nginx:latest" or "ghcr.io/user/repo:v1".
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            bail!("empty image reference");
        }

        let (name, tag) = split_tag(input);
        let (registry, repository) = split_registry(name)?;

        let registry = if registry == "docker.io" {
            "registry-1.docker.io".to_string()
        } else {
            registry
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

    pub fn image_metadata_dir(&self, base_dir: &Path) -> PathBuf {
        base_dir.join("images").join(&self.registry).join(&self.repository)
    }

    pub fn image_metadata_path(&self, base_dir: &Path) -> PathBuf {
        self.image_metadata_dir(base_dir)
            .join(format!("{}.json", self.tag))
    }
}

fn split_tag(input: &str) -> (&str, &str) {
    let last_slash = input.rfind('/').unwrap_or(0);
    let after_last_slash = &input[last_slash..];

    if let Some(colon_offset) = after_last_slash.rfind(':') {
        let colon_pos = last_slash + colon_offset;
        (&input[..colon_pos], &input[colon_pos + 1..])
    } else {
        (input, "latest")
    }
}

fn split_registry(name: &str) -> Result<(String, String)> {
    match name.find('/') {
        Some(pos) => {
            let first_component = &name[..pos];
            let rest = &name[pos + 1..];
            if looks_like_registry(first_component) {
                if rest.is_empty() {
                    bail!("missing repository name in image reference");
                }
                Ok((first_component.to_string(), rest.to_string()))
            } else {
                Ok(("docker.io".to_string(), name.to_string()))
            }
        }
        None => Ok(("docker.io".to_string(), name.to_string())),
    }
}

fn looks_like_registry(component: &str) -> bool {
    component.contains('.') || component.contains(':') || component == "localhost"
}

impl std::fmt::Display for ImageRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}:{}", self.registry, self.repository, self.tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_io_with_tag() {
        let r = ImageRef::parse("docker.io/nginx:latest").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/nginx");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn ghcr_with_tag() {
        let r = ImageRef::parse("ghcr.io/user/repo:v1").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "user/repo");
        assert_eq!(r.tag, "v1");
    }

    #[test]
    fn registry_with_port() {
        let r = ImageRef::parse("myregistry:5000/org/image:tag").unwrap();
        assert_eq!(r.registry, "myregistry:5000");
        assert_eq!(r.repository, "org/image");
        assert_eq!(r.tag, "tag");
    }

    #[test]
    fn docker_io_default_tag() {
        let r = ImageRef::parse("docker.io/nginx").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/nginx");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn docker_io_rewrite() {
        let r = ImageRef::parse("docker.io/nginx:latest").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
    }

    #[test]
    fn docker_io_library_prefix() {
        let r = ImageRef::parse("docker.io/nginx:latest").unwrap();
        assert_eq!(r.repository, "library/nginx");
    }

    #[test]
    fn docker_io_no_library_prefix_for_namespaced() {
        let r = ImageRef::parse("docker.io/myuser/myrepo:latest").unwrap();
        assert_eq!(r.repository, "myuser/myrepo");
    }

    #[test]
    fn nested_repo() {
        let r = ImageRef::parse("ghcr.io/user/repo/nested:tag").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "user/repo/nested");
        assert_eq!(r.tag, "tag");
    }

    #[test]
    fn empty_ref_fails() {
        assert!(ImageRef::parse("").is_err());
    }
}
