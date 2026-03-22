use serde::{Deserialize, Serialize};

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
    pub fn layer_dir(&self, base_dir: &std::path::Path) -> std::path::PathBuf {
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
    fn descriptor_helpers() {
        let d = Descriptor { media_type: None, digest: "sha256:abc123def456".into(), size: 100 };
        assert_eq!(d.hex(), "abc123def456");
        assert_eq!(d.layer_dir(Path::new("/hb")), Path::new("/hb/layers/sha256/abc123def456"));

        let d = Descriptor { media_type: None, digest: "md5:abcdef".into(), size: 100 };
        assert_eq!(d.hex(), "md5:abcdef");
    }
}
