mod container;
mod image;
mod registry;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use image::ref_parser::ImageRef;
use registry::RegistryClient;
use std::fs;
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
#[command(name = "hippobox", about = "Lightweight Linux container manager")]
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
        image: String,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    Images,
    Clean,
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--container-init" {
        let fd: i32 = args[2].parse().expect("invalid fd for container-init");
        return container::container_init(fd);
    }
    if args.len() >= 2 && args[1] == "--rootless-bootstrap" {
        let prctl_ret = unsafe {
            nix::libc::prctl(
                nix::libc::PR_SET_PDEATHSIG,
                nix::libc::SIGTERM as nix::libc::c_ulong,
                0,
                0,
                0,
            )
        };
        if prctl_ret != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to set rootless PDEATHSIG");
        }
        let spec: container::ContainerSpec = serde_json::from_reader(std::io::stdin())
            .context("failed to read rootless bootstrap spec from stdin")?;
        let exit_code = container::run_prepared(spec)?;
        std::process::exit(exit_code);
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
        Commands::Run { image, cmd, env } => {
            let image_ref = ImageRef::parse(&image)?;
            let base_dir = hippobox_dir();
            let rootless = unsafe { nix::libc::geteuid() } != 0;

            container::gc_stale_containers(&base_dir);

            let image_path = image_ref.image_metadata_path(&base_dir);

            if !image_path.exists() {
                eprintln!("image not found locally, pulling...");
                let mut client = RegistryClient::new();
                client.pull(&image_ref, &base_dir)?;
            }

            let (manifest, config) = container::load_image(&image_ref, &base_dir)?;
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
