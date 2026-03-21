use serde::{Deserialize, Serialize};

/// OCI image manifest listing the config and layer descriptors.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

/// A content-addressable blob reference (config or layer).
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: Option<String>,
    pub digest: String,
    pub size: u64,
}

impl Descriptor {
    /// Return the hex portion of the digest (strips `sha256:` prefix if present).
    pub fn hex(&self) -> &str {
        self.digest.strip_prefix("sha256:").unwrap_or(&self.digest)
    }

    /// Build the on-disk layer directory path for this descriptor.
    pub fn layer_dir(&self, base_dir: &std::path::Path) -> std::path::PathBuf {
        base_dir.join("layers/sha256").join(self.hex())
    }
}

/// Parsed OCI image configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct ImageConfig {
    pub config: Option<ContainerConfig>,
    pub rootfs: Option<RootFs>,
}

/// Container runtime configuration from the image.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerConfig {
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default)]
    pub env: Option<Vec<String>>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub stop_signal: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub volumes: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RootFs {
    #[serde(rename = "type")]
    pub fs_type: String,
    pub diff_ids: Vec<String>,
}

/// A manifest + config pair as stored on disk after pulling.
#[derive(Debug, Deserialize, Serialize)]
pub struct StoredImage {
    pub manifest: Manifest,
    pub config: ImageConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn hex_strips_sha256_prefix() {
        let d = Descriptor { media_type: None, digest: "sha256:abc123def456".to_string(), size: 100 };
        assert_eq!(d.hex(), "abc123def456");
    }

    #[test]
    fn hex_without_prefix_returns_full() {
        let d = Descriptor { media_type: None, digest: "md5:abcdef".to_string(), size: 100 };
        assert_eq!(d.hex(), "md5:abcdef");
    }

    #[test]
    fn layer_dir_builds_correct_path() {
        let d = Descriptor { media_type: None, digest: "sha256:abc123".to_string(), size: 100 };
        assert_eq!(d.layer_dir(Path::new("/home/.hippobox")), Path::new("/home/.hippobox/layers/sha256/abc123"));
    }
}
