//! Container runtime entry points.
//!
//! Per-platform implementations live in `linux/` and `windows/`. The public
//! surface is a thin set of dispatch functions plus re-exports of the wire
//! types and CLI parsers used by `main.rs`.

mod env;
mod parse;
mod spec;
mod util;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(unix))]
mod windows;

use anyhow::{Result, bail};
use std::path::Path;

use crate::platform::Os;

#[cfg(target_os = "linux")]
pub(crate) use linux::container_init;

pub use parse::{parse_network_mode, parse_port, parse_volume, validate_volume_target};
pub use spec::{ContainerSpec, NetworkMode, PortMapping, VolumeMount};

#[cfg(target_os = "linux")]
pub(crate) use env::env_find_mut;
pub(crate) use env::{build_argv, build_env_vars};
#[cfg(not(unix))]
pub(crate) use util::SimpleCleanupGuard;
#[cfg(not(unix))]
pub(crate) use util::copy_dir_recursive;
#[cfg(target_os = "linux")]
pub(crate) use util::which;

pub fn gc_stale_containers(base_dir: &Path) -> usize {
    #[cfg(target_os = "linux")]
    {
        linux::gc_stale_containers(base_dir)
    }
    #[cfg(not(target_os = "linux"))]
    {
        util::gc_simple(base_dir)
    }
}

pub fn run(spec: ContainerSpec) -> Result<i32> {
    match spec.target.os {
        #[cfg(target_os = "linux")]
        Os::Linux => linux::run(spec),
        #[cfg(not(target_os = "linux"))]
        Os::Linux => bail!("Linux containers require a Linux host"),
        #[cfg(not(unix))]
        Os::Windows => windows::run(spec),
        #[cfg(unix)]
        Os::Windows => bail!("Windows containers require a Windows host"),
        Os::Darwin => bail!("Darwin containers are not yet supported"),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn run_prepared(spec: ContainerSpec) -> Result<i32> {
    match spec.target.os {
        Os::Linux => linux::run_prepared(spec),
        Os::Windows => bail!("Windows containers require a Windows host"),
        Os::Darwin => bail!("Darwin containers are not yet supported"),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn set_pdeathsig() -> std::io::Result<()> {
    linux::set_pdeathsig()
}
