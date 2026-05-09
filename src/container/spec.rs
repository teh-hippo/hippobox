//! Wire types shared between the CLI front end, the per-platform runtimes, and
//! the container-init child process. These are the structs that round-trip
//! through serde when the CLI launches a child runner.

use crate::image::{ImageConfig, ImageRef, Manifest};
use crate::platform::Target;
use std::path::PathBuf;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VolumeMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NetworkMode {
    Host,
    None,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ContainerSpec {
    pub id: String,
    pub image_ref: ImageRef,
    pub manifest: Manifest,
    pub config: ImageConfig,
    pub base_dir: PathBuf,
    pub user_cmd: Vec<String>,
    pub user_env: Vec<String>,
    pub volumes: Vec<VolumeMount>,
    pub network_mode: NetworkMode,
    pub port_mappings: Vec<PortMapping>,
    pub external_netns: bool,
    pub rootless: bool,
    #[serde(default)]
    pub target: Target,
}
