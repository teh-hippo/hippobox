use anyhow::{Context, Result, bail};

/// Bring up the loopback network interface via ioctl.
/// Uses raw libc calls — no external tools or extra crates.
pub(super) fn bring_up_loopback() -> Result<()> {
    unsafe {
        let sock = nix::libc::socket(nix::libc::AF_INET, nix::libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to create socket");
        }

        let mut ifr: nix::libc::ifreq = std::mem::zeroed();
        // "lo\0" into ifr_name
        ifr.ifr_name[0] = b'l' as i8;
        ifr.ifr_name[1] = b'o' as i8;

        // Get current flags (cast needed: ioctl request type differs between glibc and musl)
        #[allow(clippy::unnecessary_cast)]
        if nix::libc::ioctl(sock, nix::libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
            let err = std::io::Error::last_os_error();
            nix::libc::close(sock);
            return Err(err).context("failed to get loopback flags");
        }

        // Set IFF_UP
        ifr.ifr_ifru.ifru_flags |= nix::libc::IFF_UP as i16;

        #[allow(clippy::unnecessary_cast)]
        if nix::libc::ioctl(sock, nix::libc::SIOCSIFFLAGS as _, &ifr) < 0 {
            let err = std::io::Error::last_os_error();
            nix::libc::close(sock);
            return Err(err).context("failed to bring up loopback");
        }

        nix::libc::close(sock);
    }
    Ok(())
}

/// A host:container port mapping for network-isolated containers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

/// Container network mode: host networking or isolated (with optional port forwarding).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NetworkMode {
    Host,
    None,
}

/// Parse a port mapping spec like `8080:80` or `5353:53/udp`.
pub fn parse_port(spec: &str) -> Result<PortMapping> {
    let (port_part, protocol) = match spec.rsplit_once('/') {
        Some((p, proto)) => {
            if proto != "tcp" && proto != "udp" {
                bail!("invalid protocol {proto:?}, expected 'tcp' or 'udp'");
            }
            (p, proto.to_string())
        }
        None => (spec, "tcp".to_string()),
    };

    let (host_port, container_port) = port_part
        .split_once(':')
        .context("invalid port mapping, expected HOST_PORT:CONTAINER_PORT")?;

    let host_port: u16 = host_port
        .parse()
        .with_context(|| format!("invalid host port: {host_port:?}"))?;
    let container_port: u16 = container_port
        .parse()
        .with_context(|| format!("invalid container port: {container_port:?}"))?;

    if host_port == 0 || container_port == 0 {
        bail!("port numbers must be non-zero");
    }

    Ok(PortMapping {
        host_port,
        container_port,
        protocol,
    })
}

/// Parse a network mode string (`"host"` or `"none"`).
pub fn parse_network_mode(s: &str) -> Result<NetworkMode> {
    match s {
        "host" => Ok(NetworkMode::Host),
        "none" => Ok(NetworkMode::None),
        _ => bail!("invalid network mode {s:?}, expected 'host' or 'none'"),
    }
}

/// Check that `pasta` is installed. Returns the path if found.
pub(super) fn check_pasta() -> Result<std::path::PathBuf> {
    which("pasta").context(
        "pasta not found; required for port mapping (-p)\n\
         install: apt install passt  (Debian/Ubuntu)\n\
         install: dnf install passt  (Fedora)\n\
         install: pacman -S passt    (Arch)",
    )
}

pub(super) fn which(name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| std::path::PathBuf::from(dir).join(name))
        .find(|p| p.is_file())
}

/// Spawn `pasta` attached to a process's network namespace (by PID).
/// Used from the rootful parent after the child signals netns is ready.
pub(super) fn spawn_pasta_for_pid(pid: u32, ports: &[PortMapping]) -> Result<std::process::Child> {
    let pasta_path = check_pasta()?;
    let mut cmd = std::process::Command::new(pasta_path);
    cmd.args(["--config-net", "--quiet", "--foreground", "--no-map-gw"]);
    add_port_args(&mut cmd, ports);
    cmd.args(["-u", "none", "-T", "none", "-U", "none"]);
    let netns_path = format!("/proc/{pid}/ns/net");
    cmd.args(["--netns", &netns_path]);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::inherit());
    cmd.spawn()
        .context("failed to start pasta for port forwarding")
}

pub(super) fn add_port_args(cmd: &mut std::process::Command, ports: &[PortMapping]) {
    for pm in ports {
        match pm.protocol.as_str() {
            "udp" => {
                cmd.args(["-u", &format!("{}:{}", pm.host_port, pm.container_port)]);
            }
            _ => {
                cmd.args(["-t", &format!("{}:{}", pm.host_port, pm.container_port)]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_basic() {
        let pm = parse_port("8080:80").unwrap();
        assert_eq!(pm.host_port, 8080);
        assert_eq!(pm.container_port, 80);
        assert_eq!(pm.protocol, "tcp");
    }

    #[test]
    fn parse_port_udp() {
        let pm = parse_port("5353:53/udp").unwrap();
        assert_eq!(pm.host_port, 5353);
        assert_eq!(pm.container_port, 53);
        assert_eq!(pm.protocol, "udp");
    }

    #[test]
    fn parse_port_tcp_explicit() {
        let pm = parse_port("3000:3000/tcp").unwrap();
        assert_eq!(pm.protocol, "tcp");
    }

    #[test]
    fn parse_port_rejects_zero() {
        assert!(parse_port("0:80").is_err());
        assert!(parse_port("8080:0").is_err());
    }

    #[test]
    fn parse_port_rejects_bad_format() {
        assert!(parse_port("8080").is_err());
        assert!(parse_port("abc:80").is_err());
        assert!(parse_port("8080:abc").is_err());
        assert!(parse_port("8080:80/sctp").is_err());
    }

    #[test]
    fn parse_network_mode_valid() {
        assert_eq!(parse_network_mode("host").unwrap(), NetworkMode::Host);
        assert_eq!(parse_network_mode("none").unwrap(), NetworkMode::None);
    }

    #[test]
    fn parse_network_mode_invalid() {
        assert!(parse_network_mode("bridge").is_err());
        assert!(parse_network_mode("").is_err());
    }

    #[test]
    fn parse_port_max_valid() {
        let pm = parse_port("65535:65535").unwrap();
        assert_eq!(pm.host_port, 65535);
        assert_eq!(pm.container_port, 65535);
    }

    #[test]
    fn parse_port_overflow() {
        assert!(parse_port("65536:80").is_err());
    }

    #[test]
    fn add_port_args_tcp() {
        let mut cmd = std::process::Command::new("echo");
        let ports = vec![PortMapping { host_port: 8080, container_port: 80, protocol: "tcp".to_string() }];
        add_port_args(&mut cmd, &ports);
        let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap().to_string()).collect();
        assert_eq!(args, vec!["-t", "8080:80"]);
    }

    #[test]
    fn add_port_args_udp() {
        let mut cmd = std::process::Command::new("echo");
        let ports = vec![PortMapping { host_port: 5353, container_port: 53, protocol: "udp".to_string() }];
        add_port_args(&mut cmd, &ports);
        let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap().to_string()).collect();
        assert_eq!(args, vec!["-u", "5353:53"]);
    }

    #[test]
    fn add_port_args_empty() {
        let mut cmd = std::process::Command::new("echo");
        add_port_args(&mut cmd, &[]);
        assert_eq!(cmd.get_args().count(), 0);
    }
}
