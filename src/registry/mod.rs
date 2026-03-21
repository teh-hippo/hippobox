pub mod auth;
mod extract;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

use crate::image::manifest::{Descriptor, ImageConfig, Manifest, StoredImage};
use crate::image::ref_parser::ImageRef;
use auth::get_anonymous_token;
use extract::{HashingReader, create_extract_temp_dir, extract_with_whiteouts};

const MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

/// OCI registry HTTP client for pulling container images.
pub struct RegistryClient {
    agent: ureq::Agent,
    token_cache: HashMap<String, String>,
}

impl RegistryClient {
    pub fn new() -> Self {
        Self {
            agent: ureq::Agent::new_with_defaults(),
            token_cache: HashMap::new(),
        }
    }

    /// Pull an image, downloading missing layers and storing metadata to disk.
    pub fn pull(&mut self, image_ref: &ImageRef, base_dir: &Path) -> Result<StoredImage> {
        let config_path = image_ref.image_metadata_path(base_dir);

        // Snapshot old stored image before overwriting (for auto-prune).
        let old_stored: Option<StoredImage> = fs::read(&config_path)
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok());

        let manifest = self.fetch_manifest(image_ref)?;
        let config = self.fetch_config(image_ref, &manifest)?;

        for layer in &manifest.layers {
            let digest_hex = layer.hex();
            let layer_dir = layer.layer_dir(base_dir);
            if layer_dir.exists() {
                eprintln!("  layer {} already exists, skipping", &digest_hex[..12]);
                continue;
            }

            eprintln!("  pulling layer {}...", &digest_hex[..12]);
            self.download_and_extract_layer(image_ref, layer, &layer_dir)?;
        }

        let stored = StoredImage { manifest, config };
        fs::create_dir_all(
            config_path
                .parent()
                .context("invalid image metadata path")?,
        )?;
        fs::write(&config_path, serde_json::to_vec(&stored)?)?;

        // Auto-prune: remove old layers that are no longer referenced by any image.
        if let Some(ref old) = old_stored {
            let new_digests: std::collections::HashSet<&str> =
                stored.manifest.layers.iter().map(|l| l.digest.as_str()).collect();
            let orphaned: Vec<&str> = old.manifest.layers.iter()
                .map(|l| l.digest.as_str())
                .filter(|d| !new_digests.contains(d))
                .collect();

            if !orphaned.is_empty() {
                let all_referenced = collect_all_referenced_layers(base_dir)?;
                for digest in orphaned {
                    if all_referenced.contains(digest) {
                        continue;
                    }
                    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
                    let layer_dir = base_dir.join("layers/sha256").join(hex);
                    if layer_dir.exists() {
                        if layer_dir.join(".in-use").exists() {
                            continue;
                        }
                        fs::remove_dir_all(&layer_dir).with_context(|| {
                            format!("failed to prune old layer {}", &hex[..hex.len().min(12)])
                        })?;
                        eprintln!("  pruned old layer {}", &hex[..hex.len().min(12)]);
                    }
                }
            }
        }

        Ok(stored)
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

        let response: serde_json::Value = serde_json::from_reader(
            self.authenticated_get(image_ref, &url, &accept)?
                .into_body()
                .into_reader()
                .take(MAX_RESPONSE_BYTES),
        )
        .context("failed to parse manifest response")?;

        if let Some(manifests) = response.get("manifests").and_then(|value| value.as_array()) {
            let digest = manifests
                .iter()
                .find_map(|entry| {
                    let platform = entry.get("platform")?;
                    if platform.get("os")?.as_str()? == "linux"
                        && platform.get("architecture")?.as_str()? == "amd64"
                    {
                        entry.get("digest")?.as_str()
                    } else {
                        None
                    }
                })
                .context("no linux/amd64 platform found in manifest index")?;

            let url = format!(
                "https://{}/v2/{}/manifests/{}",
                image_ref.registry, image_ref.repository, digest
            );
            let accept = [
                "application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json",
            ]
            .join(", ");
            return serde_json::from_reader(
                self.authenticated_get(image_ref, &url, &accept)?
                    .into_body()
                    .into_reader()
                    .take(MAX_RESPONSE_BYTES),
            )
            .context("failed to parse platform manifest");
        }

        serde_json::from_value(response).context("failed to parse manifest response")
    }

    fn fetch_config(&mut self, image_ref: &ImageRef, manifest: &Manifest) -> Result<ImageConfig> {
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            image_ref.registry, image_ref.repository, manifest.config.digest
        );
        serde_json::from_reader(
            self.authenticated_get(image_ref, &url, "application/json")?
                .into_body()
                .into_reader()
                .take(MAX_RESPONSE_BYTES),
        )
        .context("failed to parse image config")
    }

    fn download_and_extract_layer(
        &mut self,
        image_ref: &ImageRef,
        layer: &Descriptor,
        target_dir: &Path,
    ) -> Result<()> {
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            image_ref.registry, image_ref.repository, layer.digest
        );
        let token = get_anonymous_token(&mut self.token_cache, &self.agent, image_ref)?;

        let mut request = self.agent.get(&url);
        if !token.is_empty() {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        let resp = request
            .config()
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|e| anyhow::anyhow!("blob request failed: {e}"))?;

        let resp = if matches!(resp.status().as_u16(), 301 | 302 | 307) {
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
            bail!(
                "unexpected status {} for blob {}",
                resp.status(),
                layer.digest
            );
        } else {
            resp
        };

        let tmp_dir = create_extract_temp_dir(target_dir)?;

        let result = (|| -> Result<()> {
            let reader = HashingReader {
                inner: resp.into_body().into_reader(),
                hasher: Sha256::new(),
            };
            let is_gzip = layer.media_type.as_deref().is_none_or(|mt| {
                mt.contains("tar+gzip") || mt.ends_with("diff.tar.gzip")
            });
            let is_tar = matches!(
                layer.media_type.as_deref(),
                Some("application/vnd.oci.image.layer.v1.tar"
                    | "application/vnd.docker.image.rootfs.diff.tar")
            );
            let reader = if is_gzip {
                let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(reader));
                extract_with_whiteouts(&mut archive, &tmp_dir)?;
                archive.into_inner().into_inner()
            } else if is_tar {
                let mut archive = tar::Archive::new(reader);
                extract_with_whiteouts(&mut archive, &tmp_dir)?;
                archive.into_inner()
            } else {
                bail!("unsupported layer media type: {:?}", layer.media_type);
            };

            let computed = format!("sha256:{:x}", reader.hasher.finalize());
            if computed != layer.digest {
                bail!(
                    "layer digest mismatch: expected {}, got {}",
                    layer.digest,
                    computed
                );
            }

            fs::rename(&tmp_dir, target_dir)?;
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_dir_all(&tmp_dir);
        }
        result
    }

    fn authenticated_get(
        &mut self,
        image_ref: &ImageRef,
        url: &str,
        accept: &str,
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let token = get_anonymous_token(&mut self.token_cache, &self.agent, image_ref)?;
        let mut request = self.agent.get(url).header("Accept", accept);
        if !token.is_empty() {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }

        let resp = request
            .call()
            .map_err(|e| anyhow::anyhow!("request failed: {e}"))?;
        if resp.status() != 200 {
            bail!("HTTP {} for {}", resp.status(), url);
        }

        Ok(resp)
    }
}

/// Collect all layer digests referenced by any stored image manifest.
fn collect_all_referenced_layers(base_dir: &Path) -> Result<std::collections::HashSet<String>> {
    let mut referenced = std::collections::HashSet::new();
    for (_, _, path) in crate::image::walk_stored_images(&base_dir.join("images"))? {
        if let Some(stored) = fs::read(&path)
            .ok()
            .and_then(|data| serde_json::from_slice::<StoredImage>(&data).ok())
        {
            for layer in &stored.manifest.layers {
                referenced.insert(layer.digest.clone());
            }
        }
    }
    Ok(referenced)
}


