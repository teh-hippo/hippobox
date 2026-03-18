use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ManifestResponse {
    Index(ManifestIndex),
    Direct(Manifest),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestIndex {
    pub manifests: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestEntry {
    pub digest: String,
    pub platform: Option<Platform>,
}

#[derive(Debug, Deserialize)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
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
    pub fn digest_hex(&self) -> &str {
        self.digest.strip_prefix("sha256:").unwrap_or(&self.digest)
    }

    pub fn is_gzip_layer(&self) -> bool {
        match self.media_type.as_deref() {
            None => true,
            Some(media_type) => {
                media_type.contains("tar+gzip") || media_type.ends_with("diff.tar.gzip")
            }
        }
    }

    pub fn is_plain_tar_layer(&self) -> bool {
        matches!(
            self.media_type.as_deref(),
            Some("application/vnd.oci.image.layer.v1.tar")
                | Some("application/vnd.docker.image.rootfs.diff.tar")
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ImageConfig {
    pub config: Option<ContainerConfig>,
    pub rootfs: Option<RootFs>,
}

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
    pub user: Option<String>,
    #[serde(default)]
    pub stop_signal: Option<String>,
    #[serde(default)]
    pub exposed_ports: Option<serde_json::Value>,
    #[serde(default)]
    pub volumes: Option<serde_json::Value>,
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
