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
    pub stop_signal: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
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
