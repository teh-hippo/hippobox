pub mod auth;
pub mod manifest;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use crate::image::ref_parser::ImageRef;
use auth::TokenCache;
use manifest::{ImageConfig, Manifest, ManifestResponse};

pub struct RegistryClient {
    agent: ureq::Agent,
    token_cache: TokenCache,
}

impl RegistryClient {
    pub fn new() -> Self {
        let agent = ureq::Agent::new_with_defaults();
        Self {
            agent,
            token_cache: TokenCache::new(),
        }
    }

    /// Pull an image: fetch manifest, config, and all layers.
    pub fn pull(&mut self, image_ref: &ImageRef, base_dir: &Path) -> Result<ImageConfig> {
        let manifest = self.fetch_manifest(image_ref)?;
        let config = self.fetch_config(image_ref, &manifest)?;

        for layer in &manifest.layers {
            let digest_hex = layer.digest_hex();
            let layer_dir = base_dir.join("layers/sha256").join(&digest_hex);
            if layer_dir.exists() {
                eprintln!("  layer {} already exists, skipping", &digest_hex[..12]);
                continue;
            }
            eprintln!("  pulling layer {}...", &digest_hex[..12]);
            self.download_and_extract_layer(image_ref, &layer.digest, &layer_dir)?;
        }

        // Save config to images dir
        let images_dir = base_dir
            .join("images")
            .join(&image_ref.repository);
        fs::create_dir_all(&images_dir)?;
        let config_path = images_dir.join(format!("{}.json", image_ref.tag));
        let save_data = serde_json::json!({
            "manifest": manifest,
            "config": config,
        });
        fs::write(&config_path, serde_json::to_string_pretty(&save_data)?)?;

        Ok(config)
    }

    fn fetch_manifest(&mut self, image_ref: &ImageRef) -> Result<Manifest> {
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            image_ref.registry, image_ref.repository, image_ref.tag
        );

        let accept = [
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ]
        .join(", ");

        let body: String = self.authenticated_get(image_ref, &url, &accept)?;
        let response: ManifestResponse = serde_json::from_str(&body)
            .context("failed to parse manifest response")?;

        match response {
            ManifestResponse::Direct(m) => Ok(m),
            ManifestResponse::Index(index) => {
                // Find linux/amd64 platform
                let entry = index
                    .manifests
                    .iter()
                    .find(|m| {
                        m.platform.as_ref().is_some_and(|p| {
                            p.os == "linux" && p.architecture == "amd64"
                        })
                    })
                    .context("no linux/amd64 platform found in manifest index")?;

                // Fetch the platform-specific manifest
                let url = format!(
                    "https://{}/v2/{}/manifests/{}",
                    image_ref.registry, image_ref.repository, entry.digest
                );
                let accept = [
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                ]
                .join(", ");
                let body: String = self.authenticated_get(image_ref, &url, &accept)?;
                let manifest: Manifest = serde_json::from_str(&body)
                    .context("failed to parse platform manifest")?;
                Ok(manifest)
            }
        }
    }

    fn fetch_config(&mut self, image_ref: &ImageRef, manifest: &Manifest) -> Result<ImageConfig> {
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            image_ref.registry, image_ref.repository, manifest.config.digest
        );
        let body: String = self.authenticated_get(image_ref, &url, "application/json")?;
        let config: ImageConfig =
            serde_json::from_str(&body).context("failed to parse image config")?;
        Ok(config)
    }

    fn download_and_extract_layer(
        &mut self,
        image_ref: &ImageRef,
        digest: &str,
        target_dir: &Path,
    ) -> Result<()> {
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            image_ref.registry, image_ref.repository, digest
        );

        let token = self.token_cache.get_token(&self.agent, image_ref)?;

        // Manual redirect handling: don't send auth to CDN
        let resp = self
            .agent
            .get(&url)
            .header("Authorization", &format!("Bearer {token}"))
            .config()
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|e| anyhow::anyhow!("blob request failed: {e}"))?;

        let resp = if resp.status() == 307 || resp.status() == 302 || resp.status() == 301 {
            let location = resp
                .headers()
                .get("Location")
                .context("redirect without Location header")?
                .to_str()
                .context("invalid Location header")?
                .to_string();
            self.agent
                .get(&location)
                .call()
                .map_err(|e| anyhow::anyhow!("redirect follow failed: {e}"))?
        } else if resp.status() != 200 {
            bail!("unexpected status {} for blob {}", resp.status(), digest);
        } else {
            resp
        };

        // Streaming: reader → sha256 verify → gzip decompress → tar extract
        let reader = resp.into_body().into_reader();
        let hashing_reader = HashingReader::new(reader);
        let hashing_ref = hashing_reader.hasher_ref();

        // We need to get the hash after reading completes
        // Use a shared reference pattern
        let gz = flate2::read::GzDecoder::new(hashing_reader);

        // Extract to temp dir, then rename
        let tmp_dir = target_dir.with_extension("tmp");
        if tmp_dir.exists() {
            fs::remove_dir_all(&tmp_dir)?;
        }
        fs::create_dir_all(&tmp_dir)?;

        let mut archive = tar::Archive::new(gz);
        extract_with_whiteouts(&mut archive, &tmp_dir)?;

        // Verify digest
        let computed = format!("sha256:{}", hex_encode(&hashing_ref.lock().unwrap().clone().finalize()));
        if computed != digest {
            fs::remove_dir_all(&tmp_dir)?;
            bail!(
                "layer digest mismatch: expected {}, got {}",
                digest,
                computed
            );
        }

        // Atomic rename
        fs::rename(&tmp_dir, target_dir)?;
        Ok(())
    }

    fn authenticated_get(
        &mut self,
        image_ref: &ImageRef,
        url: &str,
        accept: &str,
    ) -> Result<String> {
        let token = self.token_cache.get_token(&self.agent, image_ref)?;
        let resp = self
            .agent
            .get(url)
            .header("Authorization", &format!("Bearer {token}"))
            .header("Accept", accept)
            .call()
            .map_err(|e| anyhow::anyhow!("request failed: {e}"))?;

        if resp.status() != 200 {
            bail!("HTTP {} for {}", resp.status(), url);
        }

        resp.into_body()
            .read_to_string()
            .context("failed to read response body")
    }
}

/// Extract tar archive with OCI whiteout conversion for overlayfs.
fn extract_with_whiteouts(archive: &mut tar::Archive<impl Read>, target: &Path) -> Result<()> {
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(true);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();

        // Security: reject paths with ..
        if path.components().any(|c| c.as_os_str() == "..") {
            eprintln!("  skipping dangerous path: {}", path.display());
            continue;
        }

        let file_name = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        if file_name == ".wh..wh..opq" {
            // Opaque whiteout: set xattr on parent directory
            let parent = target.join(path.parent().unwrap_or(Path::new("")));
            fs::create_dir_all(&parent)?;
            set_opaque_xattr(&parent)?;
            continue;
        }

        if let Some(deleted_name) = file_name.strip_prefix(".wh.") {
            // File whiteout: create character device (0, 0)
            let parent = target.join(path.parent().unwrap_or(Path::new("")));
            let whiteout_path = parent.join(deleted_name);
            fs::create_dir_all(&parent)?;
            create_whiteout_device(&whiteout_path)?;
            continue;
        }

        // Normal entry: extract
        // Handle hard links by falling back to copy if link target doesn't exist yet
        let target_path = target.join(&path);
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let link_name = entry.link_name()?.map(|l| l.to_path_buf());
        if entry.header().entry_type() == tar::EntryType::Link {
            if let Some(ref link) = link_name {
                let link_target = target.join(link);
                if link_target.exists() {
                    // Try hard link
                    if fs::hard_link(&link_target, &target_path).is_err() {
                        // Fall back to copy
                        fs::copy(&link_target, &target_path)?;
                    }
                }
                // If link target doesn't exist, skip (it may come in a later entry)
            }
            continue;
        }

        entry.unpack(&target_path)?;
    }
    Ok(())
}

fn set_opaque_xattr(path: &Path) -> Result<()> {
    use std::ffi::CString;
    let c_path = CString::new(path.to_string_lossy().as_bytes())?;
    let c_name = CString::new("trusted.overlay.opaque")?;
    let value = b"y";
    let ret = unsafe {
        nix::libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr() as *const nix::libc::c_void,
            value.len(),
            0,
        )
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        eprintln!("  warning: failed to set opaque xattr on {}: {err}", path.display());
    }
    Ok(())
}

fn create_whiteout_device(path: &Path) -> Result<()> {
    use nix::sys::stat;
    let dev = stat::makedev(0, 0);
    match stat::mknod(path, stat::SFlag::S_IFCHR, stat::Mode::S_IRUSR | stat::Mode::S_IWUSR, dev) {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("  warning: failed to create whiteout at {}: {e}", path.display());
            Ok(())
        }
    }
}

/// Read wrapper that hashes bytes as they pass through.
struct HashingReader<R: Read> {
    inner: R,
    hasher: std::sync::Arc<std::sync::Mutex<Sha256>>,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: std::sync::Arc::new(std::sync::Mutex::new(Sha256::new())),
        }
    }

    fn hasher_ref(&self) -> std::sync::Arc<std::sync::Mutex<Sha256>> {
        self.hasher.clone()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.lock().unwrap().update(&buf[..n]);
        }
        Ok(n)
    }
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
