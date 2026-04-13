use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Linux,
    Windows,
}

impl Os {
    pub fn as_oci_str(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Windows => "windows",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "linux" => Ok(Os::Linux),
            "windows" => Ok(Os::Windows),
            _ => bail!("unsupported OS: {s:?} (supported: linux, windows)"),
        }
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_oci_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    Amd64,
    Arm64,
}

impl Arch {
    pub fn as_oci_str(self) -> &'static str {
        match self {
            Arch::Amd64 => "amd64",
            Arch::Arm64 => "arm64",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "amd64" | "x86_64" => Ok(Arch::Amd64),
            "arm64" | "aarch64" => Ok(Arch::Arm64),
            _ => bail!("unsupported architecture: {s:?} (supported: amd64, arm64)"),
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_oci_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub os: Os,
    pub arch: Arch,
}

impl Target {
    /// Returns the target matching the current host.
    /// hippobox only runs on Linux (including WSL2), so OS is always Linux.
    pub fn host() -> Self {
        Self {
            os: Os::Linux,
            arch: host_arch(),
        }
    }

    /// Parse an OCI-style platform string like `"linux/amd64"` or `"windows/arm64"`.
    pub fn parse(s: &str) -> Result<Self> {
        let (os_str, arch_str) = s.split_once('/').with_context(|| {
            format!("invalid platform {s:?}, expected os/arch (e.g. linux/amd64)")
        })?;
        Ok(Self {
            os: Os::parse(os_str)?,
            arch: Arch::parse(arch_str)?,
        })
    }

    /// Short slug for filesystem paths, e.g. `"linux-amd64"`.
    pub fn slug(self) -> String {
        format!("{}-{}", self.os.as_oci_str(), self.arch.as_oci_str())
    }
}

impl Default for Target {
    fn default() -> Self {
        Self::host()
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.arch)
    }
}

fn host_arch() -> Arch {
    #[cfg(target_arch = "aarch64")]
    {
        return Arch::Arm64;
    }
    #[allow(unreachable_code)]
    Arch::Amd64
}

use anyhow::Context;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_targets() {
        for (input, os, arch) in [
            ("linux/amd64", Os::Linux, Arch::Amd64),
            ("linux/arm64", Os::Linux, Arch::Arm64),
            ("windows/amd64", Os::Windows, Arch::Amd64),
            ("windows/arm64", Os::Windows, Arch::Arm64),
            ("linux/x86_64", Os::Linux, Arch::Amd64),
            ("linux/aarch64", Os::Linux, Arch::Arm64),
        ] {
            let t = Target::parse(input).unwrap();
            assert_eq!(t.os, os, "failed for {input}");
            assert_eq!(t.arch, arch, "failed for {input}");
        }
    }

    #[test]
    fn parse_invalid_targets() {
        for bad in [
            "",
            "linux",
            "linux/sparc",
            "darwin/amd64",
            "amd64/linux",
            "foo/bar",
        ] {
            assert!(Target::parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn display_round_trip() {
        for s in [
            "linux/amd64",
            "linux/arm64",
            "windows/amd64",
            "windows/arm64",
        ] {
            let t = Target::parse(s).unwrap();
            assert_eq!(t.to_string(), s);
        }
    }

    #[test]
    fn slug_format() {
        assert_eq!(Target::parse("linux/amd64").unwrap().slug(), "linux-amd64");
        assert_eq!(
            Target::parse("windows/arm64").unwrap().slug(),
            "windows-arm64"
        );
    }

    #[test]
    fn host_default() {
        let t = Target::host();
        assert_eq!(t.os, Os::Linux);
        // Arch depends on host — just verify it parses back
        let s = t.to_string();
        assert_eq!(Target::parse(&s).unwrap(), t);
    }

    #[test]
    fn serialisation_round_trip() {
        for t in [
            Target {
                os: Os::Linux,
                arch: Arch::Amd64,
            },
            Target {
                os: Os::Windows,
                arch: Arch::Arm64,
            },
        ] {
            let json = serde_json::to_string(&t).unwrap();
            let back: Target = serde_json::from_str(&json).unwrap();
            assert_eq!(back, t);
        }
    }

    #[test]
    fn default_is_host() {
        assert_eq!(Target::default(), Target::host());
    }

    #[test]
    fn oci_strings() {
        assert_eq!(Os::Linux.as_oci_str(), "linux");
        assert_eq!(Os::Windows.as_oci_str(), "windows");
        assert_eq!(Arch::Amd64.as_oci_str(), "amd64");
        assert_eq!(Arch::Arm64.as_oci_str(), "arm64");
    }
}
