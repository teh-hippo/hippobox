pub mod auth;
pub mod manifest;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use crate::image::ref_parser::ImageRef;
use auth::get_anonymous_token;
use manifest::{Descriptor, ImageConfig, Manifest, StoredImage};

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

    pub fn pull(&mut self, image_ref: &ImageRef, base_dir: &Path) -> Result<StoredImage> {
        let config_path = image_ref.image_metadata_path(base_dir);

        // Snapshot old layer digests before overwriting (for auto-prune).
        let old_layer_digests: Vec<String> = fs::read(&config_path)
            .ok()
            .and_then(|data| serde_json::from_slice::<StoredImage>(&data).ok())
            .map(|old| {
                old.manifest
                    .layers
                    .iter()
                    .map(|l| l.digest.clone())
                    .collect()
            })
            .unwrap_or_default();

        let manifest = self.fetch_manifest(image_ref)?;
        let config = self.fetch_config(image_ref, &manifest)?;

        for layer in &manifest.layers {
            let digest_hex = layer
                .digest
                .strip_prefix("sha256:")
                .unwrap_or(&layer.digest);
            let layer_dir = base_dir.join("layers/sha256").join(digest_hex);
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
        if !old_layer_digests.is_empty() {
            let new_digests: std::collections::HashSet<&str> =
                stored.manifest.layers.iter().map(|l| l.digest.as_str()).collect();
            let orphaned: Vec<&str> = old_layer_digests
                .iter()
                .filter(|d| !new_digests.contains(d.as_str()))
                .map(|d| d.as_str())
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
                .into_reader(),
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
                    .into_reader(),
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
                .into_reader(),
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

        let reader = HashingReader {
            inner: resp.into_body().into_reader(),
            hasher: Sha256::new(),
        };
        let reader = if layer
            .media_type
            .as_deref()
            .map(|media_type| {
                media_type.contains("tar+gzip") || media_type.ends_with("diff.tar.gzip")
            })
            .unwrap_or(true)
        {
            let decoder = flate2::read::GzDecoder::new(reader);
            let mut archive = tar::Archive::new(decoder);
            extract_with_whiteouts(&mut archive, &tmp_dir)?;
            archive.into_inner().into_inner()
        } else if matches!(
            layer.media_type.as_deref(),
            Some("application/vnd.oci.image.layer.v1.tar")
                | Some("application/vnd.docker.image.rootfs.diff.tar")
        ) {
            let mut archive = tar::Archive::new(reader);
            extract_with_whiteouts(&mut archive, &tmp_dir)?;
            archive.into_inner()
        } else {
            fs::remove_dir_all(&tmp_dir).ok();
            bail!("unsupported layer media type: {:?}", layer.media_type);
        };

        let computed = format!("sha256:{:x}", reader.hasher.finalize());
        if computed != layer.digest {
            let _ = fs::remove_dir_all(&tmp_dir);
            bail!(
                "layer digest mismatch: expected {}, got {}",
                layer.digest,
                computed
            );
        }

        fs::rename(&tmp_dir, target_dir)?;
        Ok(())
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

fn has_unsafe_components(path: &Path) -> bool {
    path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

fn extract_with_whiteouts(archive: &mut tar::Archive<impl Read>, target: &Path) -> Result<()> {
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(false);

    // Resolve a relative path under target, ensuring no symlink traversal.
    let safe_dir = |relative: &Path| -> Result<PathBuf> {
        if has_unsafe_components(relative) {
            bail!("unsafe archive path component in {}", relative.display());
        }
        let mut out = target.to_path_buf();
        for component in relative.components() {
            if let Component::Normal(part) = component {
                out.push(part);
                match fs::symlink_metadata(&out) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        bail!(
                            "refusing to traverse symlink while extracting: {}",
                            out.display()
                        );
                    }
                    Err(err) if err.kind() != io::ErrorKind::NotFound => {
                        return Err(err.into());
                    }
                    _ => {}
                }
            }
        }
        fs::create_dir_all(&out)?;
        Ok(out)
    };

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if has_unsafe_components(&path) {
            bail!("unsafe archive path component in {}", path.display());
        }

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if file_name == ".wh..wh..opq" {
            let parent = safe_dir(path.parent().unwrap_or(Path::new("")))?;
            let c_path = CString::new(parent.to_string_lossy().as_bytes())?;
            let c_name = CString::new("trusted.overlay.opaque")?;
            let ret = unsafe {
                nix::libc::setxattr(
                    c_path.as_ptr(),
                    c_name.as_ptr(),
                    b"y".as_ptr() as *const nix::libc::c_void,
                    1,
                    0,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error()).with_context(|| {
                    format!("failed to set opaque xattr on {}", parent.display())
                });
            }
            continue;
        }

        if let Some(deleted_name) = file_name.strip_prefix(".wh.") {
            if deleted_name.is_empty()
                || Path::new(deleted_name).components().count() != 1
                || deleted_name == "."
                || deleted_name == ".."
                || deleted_name.contains('/')
                || deleted_name.contains('\\')
            {
                bail!("unsafe whiteout name: {deleted_name}");
            }
            let parent = safe_dir(path.parent().unwrap_or(Path::new("")))?;
            let whiteout_path = parent.join(deleted_name);
            if let Ok(metadata) = fs::symlink_metadata(&whiteout_path) {
                if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
                    fs::remove_dir_all(&whiteout_path)?;
                } else {
                    fs::remove_file(&whiteout_path)?;
                }
            }

            nix::sys::stat::mknod(
                &whiteout_path,
                nix::sys::stat::SFlag::S_IFCHR,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                nix::sys::stat::makedev(0, 0),
            )
            .with_context(|| format!("failed to create whiteout at {}", whiteout_path.display()))?;
            continue;
        }

        if !entry.unpack_in(target)? {
            bail!("archive entry escapes target directory: {}", path.display());
        }
    }
    Ok(())
}

fn create_extract_temp_dir(target_dir: &Path) -> Result<PathBuf> {
    let pid = std::process::id();

    for nonce in 0..64 {
        let tmp_dir = target_dir.with_extension(format!("tmp-{pid}-{nonce}"));
        match fs::create_dir(&tmp_dir) {
            Ok(()) => {
                fs::set_permissions(&tmp_dir, fs::Permissions::from_mode(0o700))?;
                return Ok(tmp_dir);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }

    bail!(
        "failed to create a unique extraction temp dir for {}",
        target_dir.display()
    );
}

struct HashingReader<R: Read> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
        }
        Ok(n)
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
