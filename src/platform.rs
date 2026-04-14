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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub os: Os,
    pub arch: Arch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
}

impl Target {
    /// Returns the target matching the current host.
    /// hippobox only runs on Linux (including WSL2), so OS is always Linux.
    pub fn host() -> Self {
        Self {
            os: Os::Linux,
            arch: host_arch(),
            os_version: None,
        }
    }

    /// Parse an OCI-style platform string like `"linux/amd64"`, `"windows/arm64"`,
    /// or `"windows/amd64/10.0.20348"` (with os.version prefix for Windows).
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, '/').collect();
        match parts.len() {
            2 => Ok(Self {
                os: Os::parse(parts[0])?,
                arch: Arch::parse(parts[1])?,
                os_version: None,
            }),
            3 => Ok(Self {
                os: Os::parse(parts[0])?,
                arch: Arch::parse(parts[1])?,
                os_version: Some(parts[2].into()),
            }),
            _ => bail!("invalid platform {s:?}, expected OS/ARCH or OS/ARCH/VERSION"),
        }
    }

    /// Short slug for filesystem paths, e.g. `"linux-amd64"` or `"windows-amd64-10.0.20348"`.
    pub fn slug(&self) -> String {
        match &self.os_version {
            Some(v) => format!("{}-{}-{v}", self.os.as_oci_str(), self.arch.as_oci_str()),
            None => format!("{}-{}", self.os.as_oci_str(), self.arch.as_oci_str()),
        }
    }
}

impl Default for Target {
    fn default() -> Self {
        Self::host()
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.arch)?;
        if let Some(v) = &self.os_version {
            write!(f, "/{v}")?;
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_targets() {
        for (input, os, arch, ver) in [
            ("linux/amd64", Os::Linux, Arch::Amd64, None),
            ("linux/arm64", Os::Linux, Arch::Arm64, None),
            ("windows/amd64", Os::Windows, Arch::Amd64, None),
            ("windows/arm64", Os::Windows, Arch::Arm64, None),
            ("linux/x86_64", Os::Linux, Arch::Amd64, None),
            ("linux/aarch64", Os::Linux, Arch::Arm64, None),
            (
                "windows/amd64/10.0.20348",
                Os::Windows,
                Arch::Amd64,
                Some("10.0.20348"),
            ),
            (
                "windows/amd64/10.0.26100.32522",
                Os::Windows,
                Arch::Amd64,
                Some("10.0.26100.32522"),
            ),
        ] {
            let t = Target::parse(input).unwrap();
            assert_eq!(t.os, os, "failed for {input}");
            assert_eq!(t.arch, arch, "failed for {input}");
            assert_eq!(t.os_version.as_deref(), ver, "failed for {input}");
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
            "windows/amd64/10.0.20348",
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
        assert_eq!(
            Target::parse("windows/amd64/10.0.20348").unwrap().slug(),
            "windows-amd64-10.0.20348"
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
                os_version: None,
            },
            Target {
                os: Os::Windows,
                arch: Arch::Arm64,
                os_version: None,
            },
            Target {
                os: Os::Windows,
                arch: Arch::Amd64,
                os_version: Some("10.0.20348".into()),
            },
        ] {
            let json = serde_json::to_string(&t).unwrap();
            let back: Target = serde_json::from_str(&json).unwrap();
            assert_eq!(back, t);
        }
        // os_version=None should not appear in JSON
        let t = Target::parse("linux/amd64").unwrap();
        let json = serde_json::to_string(&t).unwrap();
        assert!(!json.contains("os_version"));
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
