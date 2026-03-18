use anyhow::{bail, Result};

/// A parsed container image reference.
#[derive(Debug, Clone, PartialEq)]
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

        // Split off tag from the last component
        // We need to find the registry/repo boundary first, then the tag
        let (name, tag) = split_tag(input);

        // Split name into registry and repository
        let (registry, repository) = split_registry(name)?;

        // Rewrite docker.io to the actual API endpoint
        let registry = if registry == "docker.io" {
            "registry-1.docker.io".to_string()
        } else {
            registry
        };

        // Prepend library/ for Docker Hub bare names (single-component repos)
        let repository = if registry == "registry-1.docker.io" && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository
        };

        Ok(ImageRef {
            registry,
            repository,
            tag: tag.to_string(),
        })
    }

    /// The full reference string for display.
    pub fn display_name(&self) -> String {
        format!("{}/{}:{}", self.registry, self.repository, self.tag)
    }

    /// Path used for local storage under ~/.hippobox/images/
    pub fn storage_path(&self) -> String {
        format!("{}/{}", self.repository, self.tag)
    }
}

/// Split the tag from the reference. Tag defaults to "latest".
fn split_tag(input: &str) -> (&str, &str) {
    // Find the last '/' to isolate the final component
    let last_slash = input.rfind('/').unwrap_or(0);
    let after_last_slash = &input[last_slash..];

    // Look for ':' in the part after the last '/' (this is the tag separator)
    if let Some(colon_offset) = after_last_slash.rfind(':') {
        let colon_pos = last_slash + colon_offset;
        (&input[..colon_pos], &input[colon_pos + 1..])
    } else {
        (input, "latest")
    }
}

/// Split the name into registry and repository.
/// A component is a registry if it contains a '.', ':', or is "localhost".
fn split_registry(name: &str) -> Result<(String, String)> {
    let first_slash = name.find('/');

    match first_slash {
        Some(pos) => {
            let first_component = &name[..pos];
            let rest = &name[pos + 1..];

            if looks_like_registry(first_component) {
                if rest.is_empty() {
                    bail!("missing repository name in image reference");
                }
                Ok((first_component.to_string(), rest.to_string()))
            } else {
                // No registry prefix — treat the whole thing as a repo on docker.io
                Ok(("docker.io".to_string(), name.to_string()))
            }
        }
        None => {
            // Bare name like "nginx" — docker.io default
            Ok(("docker.io".to_string(), name.to_string()))
        }
    }
}

/// Heuristic: a component is a registry hostname if it contains '.', ':', or is "localhost".
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
