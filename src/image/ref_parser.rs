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
            _ => ("docker.io".to_string(), name.to_string()),
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
