mod image;
mod registry;

use anyhow::Result;
use clap::{Parser, Subcommand};
use image::ref_parser::ImageRef;
use registry::RegistryClient;
use std::fs;
use std::path::PathBuf;

fn hippobox_dir() -> PathBuf {
    let dir = dirs::home().join(".hippobox");
    dir
}

mod dirs {
    use std::path::PathBuf;

    pub fn home() -> PathBuf {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".into()))
    }
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
    /// Pull an image from a registry
    Pull {
        /// Image reference (e.g. docker.io/nginx:latest)
        image: String,
    },
    /// Run a container from an image
    Run {
        /// Image reference (e.g. docker.io/nginx:latest)
        image: String,
        /// Command to run (overrides CMD)
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    /// List cached images
    Images,
    /// Remove all cached images and layers
    Clean,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure_storage_dirs()?;

    match cli.command {
        Commands::Pull { image } => {
            let image_ref = ImageRef::parse(&image)?;
            eprintln!("pulling {image_ref}");
            let mut client = RegistryClient::new();
            let config = client.pull(&image_ref, &hippobox_dir())?;
            eprintln!("pulled {} layers", config.rootfs.map(|r| r.diff_ids.len()).unwrap_or(0));
        }
        Commands::Run { image, cmd: _ } => {
            let image_ref = ImageRef::parse(&image)?;
            eprintln!("running {image_ref} (not yet implemented)");
        }
        Commands::Images => {
            println!("no images cached");
        }
        Commands::Clean => {
            println!("nothing to clean");
        }
    }

    Ok(())
}
