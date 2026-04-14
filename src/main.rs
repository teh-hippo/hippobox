mod container;
mod image;
mod platform;
mod registry;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use image::ImageRef;
use registry::RegistryClient;
use std::fs;
use std::path::{Path, PathBuf};

fn hippobox_dir() -> PathBuf {
    #[cfg(windows)]
    {
        // On Windows, use %LOCALAPPDATA%\hippobox (native NTFS path)
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join("hippobox");
        }
        // Fallback: %USERPROFILE%\.hippobox
        return PathBuf::from(
            std::env::var("USERPROFILE")
                .unwrap_or_else(|_| std::env::var("HOME").unwrap_or_else(|_| "C:\\".into())),
        )
        .join(".hippobox");
    }
    #[allow(unreachable_code)]
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".into())).join(".hippobox")
}

fn ensure_storage_dirs() -> Result<()> {
    for sub in ["layers/sha256", "images", "containers"] {
        fs::create_dir_all(hippobox_dir().join(sub))?;
    }
    Ok(())
}

#[derive(Parser)]
#[command(name = "hippobox", about = "Lightweight container manager", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Pull {
        #[arg(long = "platform", value_name = "OS/ARCH")]
        platform: Option<String>,
        image: String,
    },
    Run {
        #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        #[arg(short = 'v', long = "volume", value_name = "SRC:DST[:ro|rw]")]
        volumes: Vec<String>,
        #[arg(short = 'p', long = "publish", value_name = "HOST:CONTAINER[/PROTO]")]
        ports: Vec<String>,
        #[arg(long = "network", default_value = "host")]
        network: String,
        #[arg(long = "platform", value_name = "OS/ARCH")]
        platform: Option<String>,
        image: String,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    Images,
    Clean,
}

fn main() -> Result<()> {
    // Internal commands used by the Linux container runtime (fork/exec protocol)
    #[cfg(target_os = "linux")]
    {
        use anyhow::Context;
        use std::os::fd::FromRawFd;
        let mut args = std::env::args_os();
        let _ = args.next();
        if let Some(arg1) = args.next() {
            let parse_fd = |a: Option<std::ffi::OsString>, label: &str| -> i32 {
                a.unwrap_or_else(|| panic!("missing fd for {label}"))
                    .to_string_lossy()
                    .parse()
                    .unwrap_or_else(|_| panic!("invalid fd for {label}"))
            };
            if arg1 == "--container-init" {
                return container::container_init(parse_fd(args.next(), "container-init"));
            }
            if arg1 == "--rootless-bootstrap" {
                let fd = parse_fd(args.next(), "rootless-bootstrap");
                container::set_pdeathsig().context("failed to set rootless PDEATHSIG")?;
                let spec: container::ContainerSpec =
                    serde_json::from_reader(std::io::BufReader::new(unsafe {
                        std::fs::File::from_raw_fd(fd)
                    }))
                    .context("failed to read rootless bootstrap spec from pipe")?;
                std::process::exit(container::run_prepared(spec)?);
            }
        }
    }

    let cli = Cli::parse();
    ensure_storage_dirs()?;

    match cli.command {
        Commands::Pull { image, platform } => {
            let image_ref = ImageRef::parse(&image)?;
            let target = match platform {
                Some(p) => {
                    let t = platform::Target::parse(&p)?;
                    t.validate_host_os()?;
                    t
                }
                None => platform::Target::host(),
            };
            let base_dir = hippobox_dir();
            container::gc_stale_containers(&base_dir);
            let mut client = RegistryClient::new();
            let _ = client.pull(&image_ref, &base_dir, &target)?;
            eprintln!("pulled {image} ({target})");
        }
        Commands::Run {
            image,
            cmd,
            env,
            volumes,
            ports,
            network,
            platform,
        } => {
            let image_ref = ImageRef::parse(&image)?;
            let target = match platform {
                Some(p) => {
                    let t = platform::Target::parse(&p)?;
                    t.validate_host_os()?;
                    t
                }
                None => platform::Target::host(),
            };
            let base_dir = hippobox_dir();
            #[cfg(target_os = "linux")]
            let rootless = !nix::unistd::geteuid().is_root();
            #[cfg(not(target_os = "linux"))]
            let rootless = false;

            container::gc_stale_containers(&base_dir);

            if !image_ref.image_metadata_path(&base_dir, &target).exists() {
                eprintln!("image not found locally, pulling...");
                let mut client = RegistryClient::new();
                client.pull(&image_ref, &base_dir, &target)?;
            }

            let (manifest, config) = container::load_image(&image_ref, &base_dir, &target)?;

            let volume_mounts = {
                let mut vm: Vec<container::VolumeMount> = volumes
                    .iter()
                    .map(|v| container::parse_volume(v))
                    .collect::<Result<_>>()?;
                if let Some(image_volumes) = config.config.as_ref().and_then(|c| c.volumes.as_ref())
                {
                    for vol_path in image_volumes.keys() {
                        if !vm.iter().any(|v| v.target == *vol_path) {
                            vm.push(container::VolumeMount {
                                source: "tmpfs".into(),
                                target: vol_path.clone(),
                                read_only: false,
                            });
                        }
                    }
                }
                vm
            };

            let port_mappings: Vec<container::PortMapping> = ports
                .iter()
                .map(|p| container::parse_port(p))
                .collect::<Result<_>>()?;

            let network_mode = if !port_mappings.is_empty()
                && network == "host"
                && !std::env::args().any(|a| a.starts_with("--network"))
            {
                container::NetworkMode::None
            } else {
                container::parse_network_mode(&network)?
            };

            if !port_mappings.is_empty() && network_mode == container::NetworkMode::Host {
                anyhow::bail!(
                    "-p requires network isolation; use --network=none (default with -p) \
                     or remove --network=host"
                );
            }

            let id = format!(
                "{:x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::from_secs(0))
                    .as_nanos()
            );
            let spec = container::ContainerSpec {
                id,
                image_ref,
                manifest,
                config,
                base_dir,
                user_cmd: cmd,
                user_env: env,
                volumes: volume_mounts,
                network_mode,
                external_netns: !port_mappings.is_empty(),
                port_mappings,
                rootless,
                target,
            };

            let exit_code = container::run(spec)?;
            std::process::exit(exit_code);
        }
        Commands::Images => list_images(&hippobox_dir())?,
        Commands::Clean => clean_all(&hippobox_dir())?,
    }

    Ok(())
}

fn list_images(base_dir: &Path) -> Result<()> {
    let repos = image::walk_stored_images(&base_dir.join("images"))?;
    if repos.is_empty() {
        println!("no images cached");
        return Ok(());
    }
    println!("{:<60} {:<15}", "REPOSITORY", "TAG");
    for (repo, tag, _) in repos {
        println!("{repo:<60} {tag:<15}");
    }
    Ok(())
}

fn clean_all(base_dir: &Path) -> Result<()> {
    let skipped = container::gc_stale_containers(base_dir);
    let mut had_errors = false;
    for sub in ["layers", "images", "containers"] {
        let dir = base_dir.join(sub);
        if dir.exists()
            && let Err(e) = fs::remove_dir_all(&dir)
        {
            had_errors = true;
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("error: cannot remove {}: permission denied", dir.display());
            } else {
                eprintln!("error: cannot remove {}: {e}", dir.display());
            }
        }
    }
    ensure_storage_dirs()?;
    if had_errors {
        if skipped > 0 {
            eprintln!(
                "hint: {skipped} container(s) are owned by root (created with sudo).\n      \
                 Run `sudo hippobox clean` to remove them."
            );
        } else {
            #[cfg(windows)]
            let suggestion = "Try running as administrator.";
            #[cfg(not(windows))]
            let suggestion = "Try `sudo hippobox clean`.";
            eprintln!("hint: some directories could not be removed. {suggestion}");
        }
        bail!("clean completed with errors");
    }
    println!("removed all cached images and containers");
    Ok(())
}
