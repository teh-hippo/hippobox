use anyhow::{Context, Result, bail};
use std::path::PathBuf;

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

pub fn parse_port(spec: &str) -> Result<PortMapping> {
    let (port_part, protocol) = match spec.rsplit_once('/') {
        Some((p, proto)) if proto == "tcp" || proto == "udp" => (p, proto.to_string()),
        Some((_, proto)) => bail!("invalid protocol {proto:?}, expected 'tcp' or 'udp'"),
        None => (spec, "tcp".to_string()),
    };
    let (host, cont) = port_part.split_once(':')
        .context("invalid port mapping, expected HOST_PORT:CONTAINER_PORT")?;
    let host_port: u16 = host.parse().with_context(|| format!("invalid host port: {host:?}"))?;
    let container_port: u16 = cont.parse().with_context(|| format!("invalid container port: {cont:?}"))?;
    if host_port == 0 || container_port == 0 { bail!("port numbers must be non-zero"); }
    Ok(PortMapping { host_port, container_port, protocol })
}

pub fn parse_network_mode(s: &str) -> Result<NetworkMode> {
    match s {
        "host" => Ok(NetworkMode::Host),
        "none" => Ok(NetworkMode::None),
        _ => bail!("invalid network mode {s:?}, expected 'host' or 'none'"),
    }
}

/// Bring up the loopback network interface via ioctl.
pub(super) fn bring_up_loopback() -> Result<()> {
    unsafe {
        let sock = nix::libc::socket(nix::libc::AF_INET, nix::libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to create socket");
        }
        let mut ifr: nix::libc::ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l' as i8;
        ifr.ifr_name[1] = b'o' as i8;
        #[allow(clippy::unnecessary_cast)]
        if nix::libc::ioctl(sock, nix::libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
            let e = std::io::Error::last_os_error();
            nix::libc::close(sock);
            return Err(e).context("failed to get loopback flags");
        }
        ifr.ifr_ifru.ifru_flags |= nix::libc::IFF_UP as i16;
        #[allow(clippy::unnecessary_cast)]
        if nix::libc::ioctl(sock, nix::libc::SIOCSIFFLAGS as _, &ifr) < 0 {
            let e = std::io::Error::last_os_error();
            nix::libc::close(sock);
            return Err(e).context("failed to bring up loopback");
        }
        nix::libc::close(sock);
    }
    Ok(())
}

pub(super) fn check_pasta() -> Result<PathBuf> {
    which("pasta").context(
        "pasta not found; required for port mapping (-p)\n\
         install: apt install passt  (Debian/Ubuntu)\n\
         install: dnf install passt  (Fedora)\n\
         install: pacman -S passt    (Arch)",
    )
}

pub(super) fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?.to_str()?.split(':')
        .map(|dir| PathBuf::from(dir).join(name))
        .find(|p| p.is_file())
}

pub(super) fn spawn_pasta_for_pid(pid: u32, ports: &[PortMapping]) -> Result<std::process::Child> {
    let mut cmd = std::process::Command::new(check_pasta()?);
    cmd.args(["--config-net", "--quiet", "--foreground", "--no-map-gw"]);
    add_port_args(&mut cmd, ports);
    cmd.args(["-u", "none", "-T", "none", "-U", "none",
        "--netns", &format!("/proc/{pid}/ns/net")]);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    cmd.spawn().context("failed to start pasta for port forwarding")
}

pub(super) fn add_port_args(cmd: &mut std::process::Command, ports: &[PortMapping]) {
    for pm in ports {
        let flag = if pm.protocol == "udp" { "-u" } else { "-t" };
        cmd.args([flag, &format!("{}:{}", pm.host_port, pm.container_port)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_valid() {
        let pm = parse_port("8080:80").unwrap();
        assert_eq!((pm.host_port, pm.container_port, pm.protocol.as_str()), (8080, 80, "tcp"));
        let pm = parse_port("5353:53/udp").unwrap();
        assert_eq!((pm.host_port, pm.container_port, pm.protocol.as_str()), (5353, 53, "udp"));
        assert_eq!(parse_port("3000:3000/tcp").unwrap().protocol, "tcp");
        assert_eq!(parse_port("65535:65535").unwrap().host_port, 65535);
    }

    #[test]
    fn parse_port_rejects_invalid() {
        for bad in ["0:80", "8080:0", "8080", "abc:80", "8080:abc", "8080:80/sctp", "65536:80"] {
            assert!(parse_port(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn parse_network_mode_valid_and_invalid() {
        assert_eq!(parse_network_mode("host").unwrap(), NetworkMode::Host);
        assert_eq!(parse_network_mode("none").unwrap(), NetworkMode::None);
        assert!(parse_network_mode("bridge").is_err());
        assert!(parse_network_mode("").is_err());
    }

    #[test]
    fn add_port_args_builds_flags() {
        let check = |proto: &str, flag: &str| {
            let mut cmd = std::process::Command::new("echo");
            add_port_args(&mut cmd, &[PortMapping {
                host_port: 80, container_port: 8080, protocol: proto.into(),
            }]);
            let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();
            assert_eq!(args, vec![flag, "80:8080"]);
        };
        check("tcp", "-t");
        check("udp", "-u");
        let mut cmd = std::process::Command::new("echo");
        add_port_args(&mut cmd, &[]);
        assert_eq!(cmd.get_args().count(), 0);
    }
}
