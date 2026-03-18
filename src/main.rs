mod container;
mod image;
mod registry;

use anyhow::Result;
use clap::{Parser, Subcommand};
use image::ref_parser::ImageRef;
use registry::manifest::StoredImage;
use registry::RegistryClient;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn hippobox_dir() -> PathBuf {
    dirs::home().join(".hippobox")
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
    Pull { image: String },
    /// Run a container from an image
    Run {
        image: String,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    /// List cached images
    Images,
    /// Remove all cached images and layers
    Clean,
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--container-init" {
        let fd: i32 = args[2].parse().expect("invalid fd for container-init");
        return container::process::container_init(fd);
    }

    let cli = Cli::parse();
    ensure_storage_dirs()?;

    match cli.command {
        Commands::Pull { image } => {
            let image_ref = ImageRef::parse(&image)?;
            eprintln!("pulling {image_ref}");
            let mut client = RegistryClient::new();
            let stored = client.pull(&image_ref, &hippobox_dir())?;
            let layer_count = stored
                .config
                .rootfs
                .as_ref()
                .map(|rootfs| rootfs.diff_ids.len())
                .unwrap_or(stored.manifest.layers.len());
            eprintln!("pulled {layer_count} layers");
        }
        Commands::Run { image, cmd } => {
            let image_ref = ImageRef::parse(&image)?;
            let base_dir = hippobox_dir();

            if !image_ref.image_metadata_path(&base_dir).exists() {
                eprintln!("image not found locally, pulling...");
                let mut client = RegistryClient::new();
                client.pull(&image_ref, &base_dir)?;
            }

            let (manifest, config) = container::load_image(&image_ref, &base_dir)?;
            let spec = container::ContainerSpec {
                id: next_container_id(),
                image_ref,
                manifest,
                config,
                base_dir,
                user_cmd: cmd,
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
    let images_dir = base_dir.join("images");
    let repos = walk_image_repos(&images_dir)?;
    if repos.is_empty() {
        println!("no images cached");
        return Ok(());
    }

    println!("{:<60} {:<15} {:>10}", "REPOSITORY", "TAG", "LAYERS");
    for (repo_name, tag_path, tag) in repos {
        let data = fs::read(tag_path)?;
        let stored: StoredImage = serde_json::from_slice(&data)?;
        println!(
            "{:<60} {:<15} {:>10}",
            repo_name,
            tag,
            stored.manifest.layers.len()
        );
    }
    Ok(())
}

fn walk_image_repos(images_dir: &Path) -> Result<Vec<(String, PathBuf, String)>> {
    let mut results = Vec::new();
    walk_image_repos_inner(images_dir, images_dir, &mut results)?;
    Ok(results)
}

fn walk_image_repos_inner(
    base: &Path,
    dir: &Path,
    results: &mut Vec<(String, PathBuf, String)>,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_image_repos_inner(base, &path, results)?;
        } else if let Some(tag) = path.file_name().and_then(|f| f.to_str()).and_then(|f| f.strip_suffix(".json")) {
            let tag = tag.to_string();
            let repo_name = path
                .parent()
                .unwrap_or(dir)
                .strip_prefix(base)
                .unwrap_or(dir)
                .to_string_lossy()
                .to_string();
            results.push((repo_name, path, tag));
        }
    }
    Ok(())
}

fn clean_all(base_dir: &Path) -> Result<()> {
    let mut freed = 0;
    for sub in ["layers", "images", "containers"] {
        let dir = base_dir.join(sub);
        if dir.exists() {
            freed += dir_size(&dir)?;
            fs::remove_dir_all(&dir)?;
            fs::create_dir_all(&dir)?;
        }
    }
    fs::create_dir_all(base_dir.join("layers/sha256"))?;

    if freed == 0 {
        println!("nothing to clean");
    } else {
        let (size, unit) = human_size(freed);
        println!("removed all images, freed {size:.1} {unit}");
    }
    Ok(())
}

fn dir_size(path: &Path) -> Result<u64> {
    if path.is_file() {
        return Ok(fs::metadata(path)?.len());
    }

    let mut total = 0;
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            total += dir_size(&entry?.path())?;
        }
    }
    Ok(total)
}

fn human_size(bytes: u64) -> (f64, &'static str) {
    if bytes >= 1_073_741_824 {
        (bytes as f64 / 1_073_741_824.0, "GB")
    } else if bytes >= 1_048_576 {
        (bytes as f64 / 1_048_576.0, "MB")
    } else if bytes >= 1024 {
        (bytes as f64 / 1024.0, "KB")
    } else {
        (bytes as f64, "B")
    }
}

fn next_container_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    format!("{:x}", now.as_nanos())
}
