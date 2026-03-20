use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
            Some((name, tag)) if !tag.contains('/') => (name, tag),
            _ => (input, "latest"),
        };

        let (registry, repository) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                if rest.is_empty() {
                    bail!("missing repository name in image reference");
                }
                let registry = if first == "docker.io" {
                    "registry-1.docker.io"
                } else {
                    first
                };
                (registry.to_string(), rest.to_string())
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

    pub fn image_metadata_path(&self, base_dir: &Path) -> PathBuf {
        let base = base_dir
            .join("images")
            .join(&self.registry)
            .join(&self.repository);
        base.join(format!("{}.json", self.tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_name() {
        let r = ImageRef::parse("nginx").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/nginx");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_bare_name_with_tag() {
        let r = ImageRef::parse("alpine:3.19").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag, "3.19");
    }

    #[test]
    fn parse_user_repo() {
        let r = ImageRef::parse("myuser/myimage:v1").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "myuser/myimage");
        assert_eq!(r.tag, "v1");
    }

    #[test]
    fn parse_custom_registry() {
        let r = ImageRef::parse("ghcr.io/owner/repo:sha-abc123").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "owner/repo");
        assert_eq!(r.tag, "sha-abc123");
    }

    #[test]
    fn parse_docker_io_explicit() {
        let r = ImageRef::parse("docker.io/library/ubuntu:22.04").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/ubuntu");
        assert_eq!(r.tag, "22.04");
    }

    #[test]
    fn parse_localhost_registry() {
        let r = ImageRef::parse("localhost/myimage:dev").unwrap();
        assert_eq!(r.registry, "localhost");
        assert_eq!(r.repository, "myimage");
        assert_eq!(r.tag, "dev");
    }

    #[test]
    fn parse_registry_with_port() {
        let r = ImageRef::parse("myregistry:5000/repo:tag").unwrap();
        assert_eq!(r.registry, "myregistry:5000");
        assert_eq!(r.repository, "repo");
        assert_eq!(r.tag, "tag");
    }

    #[test]
    fn parse_empty_errors() {
        assert!(ImageRef::parse("").is_err());
        assert!(ImageRef::parse("  ").is_err());
    }

    #[test]
    fn parse_missing_repo_errors() {
        assert!(ImageRef::parse("ghcr.io/").is_err());
    }

    #[test]
    fn image_metadata_path_layout() {
        let r = ImageRef::parse("nginx").unwrap();
        let path = r.image_metadata_path(Path::new("/tmp/hb"));
        assert_eq!(
            path,
            PathBuf::from("/tmp/hb/images/registry-1.docker.io/library/nginx/latest.json")
        );
    }
}
