mod image;
mod container;
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
    // Handle re-exec for container init
    let args: Vec<String> = std::env::args().collect();
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
            let config = client.pull(&image_ref, &hippobox_dir())?;
            eprintln!("pulled {} layers", config.rootfs.map(|r| r.diff_ids.len()).unwrap_or(0));
        }
        Commands::Run { image, cmd } => {
            let image_ref = ImageRef::parse(&image)?;
            let base_dir = hippobox_dir();

            // Auto-pull if not cached
            let image_path = base_dir
                .join("images")
                .join(&image_ref.repository)
                .join(format!("{}.json", image_ref.tag));
            if !image_path.exists() {
                eprintln!("image not found locally, pulling...");
                let mut client = RegistryClient::new();
                client.pull(&image_ref, &base_dir)?;
            }

            let (manifest, config) = container::load_image(&image_ref, &base_dir)?;
            let container_id = format!("{:x}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos());

            let spec = container::ContainerSpec {
                id: container_id,
                image_ref,
                manifest,
                config,
                base_dir,
                user_cmd: cmd,
            };

            let exit_code = container::run(spec)?;
            std::process::exit(exit_code);
        }
        Commands::Images => {
            list_images(&hippobox_dir())?;
        }
        Commands::Clean => {
            clean_all(&hippobox_dir())?;
        }
    }

    Ok(())
}

fn list_images(base_dir: &PathBuf) -> Result<()> {
    let images_dir = base_dir.join("images");
    let mut found = false;

    let repos = walk_image_repos(&images_dir)?;
    for (repo_name, tag_path, tag) in &repos {
        if !found {
            println!("{:<40} {:<15} {:>10}", "REPOSITORY", "TAG", "LAYERS");
            found = true;
        }
        let data = fs::read_to_string(tag_path)?;
        let val: serde_json::Value = serde_json::from_str(&data)?;
        let layer_count = val
            .get("manifest")
            .and_then(|m| m.get("layers"))
            .and_then(|l| l.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        println!("{:<40} {:<15} {:>10}", repo_name, tag, layer_count);
    }

    if !found {
        println!("no images cached");
    }
    Ok(())
}

fn walk_image_repos(images_dir: &std::path::Path) -> Result<Vec<(String, PathBuf, String)>> {
    let mut results = Vec::new();
    walk_image_repos_inner(images_dir, images_dir, &mut results)?;
    Ok(results)
}

fn walk_image_repos_inner(
    base: &std::path::Path,
    dir: &std::path::Path,
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
        } else if let Some(fname) = path.file_name().and_then(|f| f.to_str()) {
            if let Some(tag) = fname.strip_suffix(".json") {
                let repo_name = path
                    .parent()
                    .unwrap_or(dir)
                    .strip_prefix(base)
                    .unwrap_or(dir.as_ref())
                    .to_string_lossy()
                    .to_string();
                results.push((repo_name, path.clone(), tag.to_string()));
            }
        }
    }
    Ok(())
}

fn clean_all(base_dir: &PathBuf) -> Result<()> {
    let mut freed: u64 = 0;

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

fn dir_size(path: &std::path::Path) -> Result<u64> {
    let mut total = 0;
    if path.is_file() {
        return Ok(fs::metadata(path)?.len());
    }
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
