use serde::{Deserialize, Serialize};

/// Response that could be either a manifest index (fat manifest) or a direct platform manifest.
/// We distinguish by checking for the "manifests" field (index) vs "layers" field (direct).
#[derive(Debug)]
pub enum ManifestResponse {
    Index(ManifestIndex),
    Direct(Manifest),
}

impl<'de> Deserialize<'de> for ManifestResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: serde_json::Value = Deserialize::deserialize(deserializer)?;

        if value.get("manifests").is_some() {
            let index: ManifestIndex =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            Ok(ManifestResponse::Index(index))
        } else if value.get("layers").is_some() {
            let manifest: Manifest =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            Ok(ManifestResponse::Direct(manifest))
        } else {
            Err(serde::de::Error::custom(
                "response is neither a manifest index nor a manifest",
            ))
        }
    }
}

/// OCI Image Index / Docker Manifest List
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestIndex {
    pub manifests: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestEntry {
    pub media_type: Option<String>,
    pub digest: String,
    pub platform: Option<Platform>,
}

#[derive(Debug, Deserialize)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
}

/// OCI Image Manifest / Docker Distribution Manifest v2
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
    /// Extract the hex portion after "sha256:"
    pub fn digest_hex(&self) -> String {
        self.digest
            .strip_prefix("sha256:")
            .unwrap_or(&self.digest)
            .to_string()
    }
}

/// OCI Image Configuration
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
