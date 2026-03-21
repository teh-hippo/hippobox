mod container;
mod image;
mod registry;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use image::ref_parser::ImageRef;
use registry::RegistryClient;
use std::fs;
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};

fn hippobox_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".into())).join(".hippobox")
}

fn ensure_storage_dirs() -> Result<()> {
    let base = hippobox_dir();
    for sub in ["layers/sha256", "images", "containers"] {
        fs::create_dir_all(base.join(sub))?;
    }
    Ok(())
}

#[derive(Parser)]
#[command(name = "hippobox", about = "Lightweight Linux container manager", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Pull {
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
        image: String,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    Images,
    Clean,
}

fn main() -> Result<()> {
    // Fast-path: check for internal commands before collecting all args.
    // These paths are the child re-exec from fork/unshare so every µs counts.
    let mut args = std::env::args_os();
    let _ = args.next(); // skip argv[0]
    if let Some(arg1) = args.next() {
        if arg1 == "--container-init" {
            let fd: i32 = args
                .next()
                .expect("missing fd for container-init")
                .to_string_lossy()
                .parse()
                .expect("invalid fd for container-init");
            return container::container_init(fd);
        }
        if arg1 == "--rootless-bootstrap" {
            let fd: i32 = args
                .next()
                .expect("missing fd for rootless-bootstrap")
                .to_string_lossy()
                .parse()
                .expect("invalid fd for rootless-bootstrap");
            container::set_pdeathsig()
                .context("failed to set rootless PDEATHSIG")?;
            let pipe_file = unsafe { std::fs::File::from_raw_fd(fd) };
            let spec: container::ContainerSpec =
                serde_json::from_reader(std::io::BufReader::new(pipe_file))
                    .context("failed to read rootless bootstrap spec from pipe")?;
            let exit_code = container::run_prepared(spec)?;

            std::process::exit(exit_code);
        }
    }

    let cli = Cli::parse();
    ensure_storage_dirs()?;

    match cli.command {
        Commands::Pull { image } => {
            let image_ref = ImageRef::parse(&image)?;
            let mut client = RegistryClient::new();
            let _ = client.pull(&image_ref, &hippobox_dir())?;
            eprintln!("pulled {image}");
        }
        Commands::Run {
            image,
            cmd,
            env,
            volumes,
            ports,
            network,
        } => {
            let image_ref = ImageRef::parse(&image)?;
            let base_dir = hippobox_dir();
            let rootless = !nix::unistd::geteuid().is_root();

            container::gc_stale_containers(&base_dir);

            let image_path = image_ref.image_metadata_path(&base_dir);

            if !image_path.exists() {
                eprintln!("image not found locally, pulling...");
                let mut client = RegistryClient::new();
                client.pull(&image_ref, &base_dir)?;
            }

            let (manifest, config) = container::load_image(&image_ref, &base_dir)?;

            let mut volume_mounts: Vec<container::VolumeMount> = volumes
                .iter()
                .map(|v| container::parse_volume(v))
                .collect::<Result<_>>()?;

            // Add tmpfs volumes for image VOLUME directives not covered by user -v.
            if let Some(image_volumes) = config
                .config
                .as_ref()
                .and_then(|c| c.volumes.as_ref())
            {
                for vol_path in image_volumes.keys() {
                    if !volume_mounts.iter().any(|v| v.target == *vol_path) {
                        volume_mounts.push(container::VolumeMount {
                            source: "tmpfs".to_string(),
                            target: vol_path.clone(),
                            read_only: false,
                        });
                    }
                }
            }

            let port_mappings: Vec<container::net::PortMapping> = ports
                .iter()
                .map(|p| container::net::parse_port(p))
                .collect::<Result<_>>()?;

            // -p implies network isolation unless --network=host is explicit.
            let network_mode = if !port_mappings.is_empty()
                && network == "host"
                && !std::env::args().any(|a| a.starts_with("--network"))
            {
                container::net::NetworkMode::None
            } else {
                container::net::parse_network_mode(&network)?
            };

            if !port_mappings.is_empty()
                && network_mode == container::net::NetworkMode::Host
            {
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
    for (repo_name, tag, _) in repos {
        println!("{:<60} {:<15}", repo_name, tag);
    }
    Ok(())
}

fn clean_all(base_dir: &Path) -> Result<()> {
    container::gc_stale_containers(base_dir);

    for sub in ["layers", "images", "containers"] {
        let dir = base_dir.join(sub);
        if dir.exists() && fs::remove_dir_all(&dir).is_err() {
            eprintln!("warning: failed to remove {}", dir.display());
        }
    }
    ensure_storage_dirs()?;
    println!("removed all cached images");
    Ok(())
}
