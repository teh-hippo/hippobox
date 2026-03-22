use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

/// Parsed container image reference (registry/repo:tag).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_image_refs() {
        let cases = [
            ("nginx", "registry-1.docker.io", "library/nginx", "latest"),
            ("alpine:3.19", "registry-1.docker.io", "library/alpine", "3.19"),
            ("myuser/myimage:v1", "registry-1.docker.io", "myuser/myimage", "v1"),
            ("ghcr.io/owner/repo:sha-abc123", "ghcr.io", "owner/repo", "sha-abc123"),
            ("docker.io/library/ubuntu:22.04", "registry-1.docker.io", "library/ubuntu", "22.04"),
            ("localhost/myimage:dev", "localhost", "myimage", "dev"),
            ("myregistry:5000/repo:tag", "myregistry:5000", "repo", "tag"),
        ];
        for (input, reg, repo, tag) in cases {
            let r = ImageRef::parse(input).unwrap();
            assert_eq!((r.registry.as_str(), r.repository.as_str(), r.tag.as_str()), (reg, repo, tag), "failed for {input}");
        }
    }

    #[test]
    fn parse_image_ref_errors() {
        assert!(ImageRef::parse("").is_err());
        assert!(ImageRef::parse("  ").is_err());
        assert!(ImageRef::parse("ghcr.io/").is_err());
    }

    #[test]
    fn image_metadata_path_layout() {
        let r = ImageRef::parse("nginx").unwrap();
        assert_eq!(
            r.image_metadata_path(Path::new("/tmp/hb")),
            PathBuf::from("/tmp/hb/images/registry-1.docker.io/library/nginx/latest.json")
        );
    }
}
