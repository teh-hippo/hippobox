pub mod auth;
pub mod manifest;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use crate::image::ref_parser::ImageRef;
use auth::TokenCache;
use manifest::{Descriptor, ImageConfig, Manifest, ManifestResponse, StoredImage};

pub struct RegistryClient {
    agent: ureq::Agent,
    token_cache: TokenCache,
}

impl RegistryClient {
    pub fn new() -> Self {
        Self {
            agent: ureq::Agent::new_with_defaults(),
            token_cache: TokenCache::new(),
        }
    }

    pub fn pull(&mut self, image_ref: &ImageRef, base_dir: &Path) -> Result<StoredImage> {
        let manifest = self.fetch_manifest(image_ref)?;
        let config = self.fetch_config(image_ref, &manifest)?;

        for layer in &manifest.layers {
            let layer_dir = base_dir.join("layers/sha256").join(layer.digest_hex());
            if layer_dir.exists() {
                eprintln!("  layer {} already exists, skipping", &layer.digest_hex()[..12]);
                continue;
            }

            eprintln!("  pulling layer {}...", &layer.digest_hex()[..12]);
            self.download_and_extract_layer(image_ref, layer, &layer_dir)?;
        }

        let stored = StoredImage { manifest, config };
        let images_dir = image_ref.image_metadata_dir(base_dir);
        fs::create_dir_all(&images_dir)?;
        let config_path = image_ref.image_metadata_path(base_dir);
        fs::write(&config_path, serde_json::to_vec(&stored)?)?;

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

        let response: ManifestResponse = serde_json::from_reader(
            self.authenticated_get(image_ref, &url, &accept)?
                .into_body()
                .into_reader(),
        )
        .context("failed to parse manifest response")?;

        match response {
            ManifestResponse::Direct(manifest) => Ok(manifest),
            ManifestResponse::Index(index) => {
                let entry = index
                    .manifests
                    .iter()
                    .find(|entry| {
                        entry
                            .platform
                            .as_ref()
                            .is_some_and(|p| p.os == "linux" && p.architecture == "amd64")
                    })
                    .context("no linux/amd64 platform found in manifest index")?;

                let url = format!(
                    "https://{}/v2/{}/manifests/{}",
                    image_ref.registry, image_ref.repository, entry.digest
                );
                let accept = [
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                ]
                .join(", ");
                serde_json::from_reader(
                    self.authenticated_get(image_ref, &url, &accept)?
                        .into_body()
                        .into_reader(),
                )
                .context("failed to parse platform manifest")
            }
        }
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
        let token = self.token_cache.get_token(&self.agent, image_ref)?;

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
            bail!("unexpected status {} for blob {}", resp.status(), layer.digest);
        } else {
            resp
        };

        let tmp_dir = target_dir.with_extension("tmp");
        if tmp_dir.exists() {
            fs::remove_dir_all(&tmp_dir)?;
        }
        fs::create_dir_all(&tmp_dir)?;

        let reader = HashingReader::new(resp.into_body().into_reader());
        let reader = if layer.is_gzip_layer() {
            let decoder = flate2::read::GzDecoder::new(reader);
            let mut archive = tar::Archive::new(decoder);
            extract_with_whiteouts(&mut archive, &tmp_dir)?;
            archive.into_inner().into_inner()
        } else if layer.is_plain_tar_layer() {
            let mut archive = tar::Archive::new(reader);
            extract_with_whiteouts(&mut archive, &tmp_dir)?;
            archive.into_inner()
        } else {
            fs::remove_dir_all(&tmp_dir).ok();
            bail!("unsupported layer media type: {:?}", layer.media_type);
        };

        let computed = format!("sha256:{}", reader.finalize_hex());
        if computed != layer.digest {
            let _ = fs::remove_dir_all(&tmp_dir);
            bail!("layer digest mismatch: expected {}, got {}", layer.digest, computed);
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
        let token = self.token_cache.get_token(&self.agent, image_ref)?;
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

fn extract_with_whiteouts(archive: &mut tar::Archive<impl Read>, target: &Path) -> Result<()> {
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(false);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        validate_relative_path(&path)?;

        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
        if file_name == ".wh..wh..opq" {
            let parent_rel = path.parent().unwrap_or(Path::new(""));
            let parent = ensure_safe_dir(target, parent_rel)?;
            set_opaque_xattr(&parent)?;
            continue;
        }

        if let Some(deleted_name) = file_name.strip_prefix(".wh.") {
            let parent_rel = path.parent().unwrap_or(Path::new(""));
            let parent = ensure_safe_dir(target, parent_rel)?;
            let whiteout_path = parent.join(deleted_name);
            if whiteout_path.exists() {
                remove_existing_path(&whiteout_path)?;
            }
            create_whiteout_device(&whiteout_path)?;
            continue;
        }

        if !entry.unpack_in(target)? {
            bail!("archive entry escapes target directory: {}", path.display());
        }
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<()> {
    if path.is_absolute() {
        bail!("absolute archive path is not allowed: {}", path.display());
    }

    for component in path.components() {
        match component {
            Component::CurDir | Component::Normal(_) => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("unsafe archive path component in {}", path.display())
            }
        }
    }
    Ok(())
}

fn ensure_safe_dir(base: &Path, relative: &Path) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    let mut out = base.to_path_buf();
    for component in relative.components() {
        if let Component::Normal(part) = component {
            out.push(part);
            if out.exists() && fs::symlink_metadata(&out)?.file_type().is_symlink() {
                bail!("refusing to traverse symlink while extracting: {}", out.display());
            }
        }
    }
    fs::create_dir_all(&out)?;
    Ok(out)
}

fn remove_existing_path(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
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
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to set opaque xattr on {}", path.display()));
    }
    Ok(())
}

fn create_whiteout_device(path: &Path) -> Result<()> {
    use nix::sys::stat;

    let dev = stat::makedev(0, 0);
    stat::mknod(
        path,
        stat::SFlag::S_IFCHR,
        stat::Mode::S_IRUSR | stat::Mode::S_IWUSR,
        dev,
    )
    .with_context(|| format!("failed to create whiteout at {}", path.display()))
}

struct HashingReader<R: Read> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finalize_hex(self) -> String {
        hex_encode(&self.hasher.finalize())
    }
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
