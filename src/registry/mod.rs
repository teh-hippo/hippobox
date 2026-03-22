mod extract;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use crate::image::{Descriptor, ImageConfig, ImageRef, Manifest, StoredImage};
use extract::{HashingReader, create_extract_temp_dir, extract_with_whiteouts};

const MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;
pub struct RegistryClient {
    agent: ureq::Agent,
    token_cache: HashMap<String, String>,
}
impl RegistryClient {
    pub fn new() -> Self {
        Self { agent: ureq::Agent::new_with_defaults(), token_cache: HashMap::new() }
    }
    pub fn pull(&mut self, image_ref: &ImageRef, base_dir: &Path) -> Result<StoredImage> {
        let config_path = image_ref.image_metadata_path(base_dir);
        let old_stored: Option<StoredImage> = fs::read(&config_path)
            .ok().and_then(|data| serde_json::from_slice(&data).ok());
        let manifest = self.fetch_manifest(image_ref)?;
        let config = self.fetch_config(image_ref, &manifest)?;
        for layer in &manifest.layers {
            let (hex, layer_dir) = (layer.hex(), layer.layer_dir(base_dir));
            if layer_dir.exists() { eprintln!("  layer {} already exists, skipping", &hex[..12]); continue; }
            eprintln!("  pulling layer {}...", &hex[..12]);
            self.download_and_extract_layer(image_ref, layer, &layer_dir)?;
        }
        let stored = StoredImage { manifest, config };
        fs::create_dir_all(config_path.parent().context("invalid image metadata path")?)?;
        fs::write(&config_path, serde_json::to_vec(&stored)?)?;
        if let Some(ref old) = old_stored { auto_prune_layers(old, &stored, base_dir)?; }
        Ok(stored)
    }
    fn api_url(image_ref: &ImageRef, kind: &str, reference: &str) -> String {
        format!("https://{}/v2/{}/{kind}/{reference}", image_ref.registry, image_ref.repository)
    }
    fn fetch_manifest(&mut self, image_ref: &ImageRef) -> Result<Manifest> {
        let url = Self::api_url(image_ref, "manifests", &image_ref.tag);
        let accept = "application/vnd.oci.image.index.v1+json, \
            application/vnd.oci.image.manifest.v1+json, \
            application/vnd.docker.distribution.manifest.list.v2+json, \
            application/vnd.docker.distribution.manifest.v2+json";
        let response: serde_json::Value = serde_json::from_reader(
            self.authenticated_get(image_ref, &url, accept)?.into_body().into_reader().take(MAX_RESPONSE_BYTES),
        ).context("failed to parse manifest response")?;
        if let Some(manifests) = response.get("manifests").and_then(|v| v.as_array()) {
            let digest = manifests.iter().find_map(|entry| {
                let p = entry.get("platform")?;
                (p.get("os")?.as_str()? == "linux" && p.get("architecture")?.as_str()? == "amd64")
                    .then(|| entry.get("digest")?.as_str())?
            }).context("no linux/amd64 platform found in manifest index")?;
            let url = Self::api_url(image_ref, "manifests", digest);
            let accept = "application/vnd.oci.image.manifest.v1+json, \
                application/vnd.docker.distribution.manifest.v2+json";
            return serde_json::from_reader(
                self.authenticated_get(image_ref, &url, accept)?.into_body().into_reader().take(MAX_RESPONSE_BYTES),
            ).context("failed to parse platform manifest");
        }
        serde_json::from_value(response).context("failed to parse manifest response")
    }

    fn fetch_config(&mut self, image_ref: &ImageRef, manifest: &Manifest) -> Result<ImageConfig> {
        let url = Self::api_url(image_ref, "blobs", &manifest.config.digest);
        serde_json::from_reader(
            self.authenticated_get(image_ref, &url, "application/json")?
                .into_body().into_reader().take(MAX_RESPONSE_BYTES),
        ).context("failed to parse image config")
    }
    fn download_and_extract_layer(
        &mut self, image_ref: &ImageRef, layer: &Descriptor, target_dir: &Path,
    ) -> Result<()> {
        let url = Self::api_url(image_ref, "blobs", &layer.digest);
        let token = get_anonymous_token(&mut self.token_cache, &self.agent, image_ref)?;
        let mut req = self.agent.get(&url);
        if !token.is_empty() { req = req.header("Authorization", &format!("Bearer {token}")); }
        let resp = req.config().max_redirects(0).http_status_as_error(false).build()
            .call().map_err(|e| anyhow::anyhow!("blob request failed: {e}"))?;
        let resp = if matches!(resp.status().as_u16(), 301 | 302 | 307) {
            let loc = resp.headers().get("Location").context("redirect without Location")?
                .to_str().context("invalid Location header")?.to_string();
            self.agent.get(&loc).call().map_err(|e| anyhow::anyhow!("redirect failed: {e}"))?
        } else if resp.status() != 200 { bail!("unexpected status {} for blob {}", resp.status(), layer.digest);
        } else { resp };
        let tmp_dir = create_extract_temp_dir(target_dir)?;
        let result = (|| -> Result<()> {
            let reader = HashingReader { inner: resp.into_body().into_reader(), hasher: Sha256::new() };
            let mt = layer.media_type.as_deref();
            let is_gzip = mt.is_none_or(|m| m.contains("tar+gzip") || m.ends_with("diff.tar.gzip"));
            let reader = if is_gzip {
                let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(reader));
                extract_with_whiteouts(&mut ar, &tmp_dir)?;
                ar.into_inner().into_inner()
            } else if matches!(mt, Some("application/vnd.oci.image.layer.v1.tar" | "application/vnd.docker.image.rootfs.diff.tar")) {
                let mut ar = tar::Archive::new(reader);
                extract_with_whiteouts(&mut ar, &tmp_dir)?;
                ar.into_inner()
            } else { bail!("unsupported layer media type: {mt:?}") };
            let computed = format!("sha256:{:x}", reader.hasher.finalize());
            if computed != layer.digest { bail!("layer digest mismatch: expected {}, got {}", layer.digest, computed); }
            fs::rename(&tmp_dir, target_dir)?;
            Ok(())
        })();
        if result.is_err() { let _ = fs::remove_dir_all(&tmp_dir); }
        result
    }
    fn authenticated_get(
        &mut self, image_ref: &ImageRef, url: &str, accept: &str,
    ) -> Result<ureq::http::Response<ureq::Body>> {
        let token = get_anonymous_token(&mut self.token_cache, &self.agent, image_ref)?;
        let mut req = self.agent.get(url).header("Accept", accept);
        if !token.is_empty() { req = req.header("Authorization", &format!("Bearer {token}")); }
        let resp = req.call().map_err(|e| anyhow::anyhow!("request failed: {e}"))?;
        if resp.status() != 200 { bail!("HTTP {} for {}", resp.status(), url); }
        Ok(resp)
    }
}

fn auto_prune_layers(old: &StoredImage, new: &StoredImage, base_dir: &Path) -> Result<()> {
    let new_digests: std::collections::HashSet<&str> =
        new.manifest.layers.iter().map(|l| l.digest.as_str()).collect();
    let orphaned: Vec<&str> = old.manifest.layers.iter()
        .map(|l| l.digest.as_str()).filter(|d| !new_digests.contains(d)).collect();
    if orphaned.is_empty() { return Ok(()); }
    let mut referenced = std::collections::HashSet::new();
    for (_, _, path) in crate::image::walk_stored_images(&base_dir.join("images"))? {
        if let Some(stored) = fs::read(&path).ok()
            .and_then(|data| serde_json::from_slice::<StoredImage>(&data).ok())
        {
            for layer in &stored.manifest.layers { referenced.insert(layer.digest.clone()); }
        }
    }
    for digest in orphaned {
        if referenced.contains(digest) { continue; }
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        let layer_dir = base_dir.join("layers/sha256").join(hex);
        if layer_dir.exists() && !layer_dir.join(".in-use").exists() {
            fs::remove_dir_all(&layer_dir)
                .with_context(|| format!("failed to prune old layer {}", &hex[..hex.len().min(12)]))?;
            eprintln!("  pruned old layer {}", &hex[..hex.len().min(12)]);
        }
    }
    Ok(())
}
fn get_anonymous_token(
    cache: &mut HashMap<String, String>, agent: &ureq::Agent, image_ref: &ImageRef,
) -> Result<String> {
    let key = format!("{}/{}", image_ref.registry, image_ref.repository);
    if let Some(token) = cache.get(&key) { return Ok(token.clone()); }
    let token = fetch_anonymous_token(agent, image_ref)?;
    cache.insert(key, token.clone());
    Ok(token)
}
fn fetch_anonymous_token(agent: &ureq::Agent, image_ref: &ImageRef) -> Result<String> {
    let v2_url = format!("https://{}/v2/", image_ref.registry);
    let resp = agent.get(&v2_url).config().max_redirects(0).http_status_as_error(false).build()
        .call().map_err(|e| anyhow::anyhow!("v2 ping failed: {e}"))?;
    if resp.status() == 200 { return Ok(String::new()); }
    let www_auth = resp.headers().get("Www-Authenticate")
        .context("no Www-Authenticate header in 401 response")?
        .to_str().context("invalid Www-Authenticate header encoding")?.to_string();
    let rest = www_auth.trim().strip_prefix("Bearer ")
        .or_else(|| www_auth.trim().strip_prefix("bearer "))
        .context("Www-Authenticate is not Bearer type")?;
    let params: Vec<(&str, &str)> = rest.split(',').filter_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        Some((k.trim(), v.trim_matches('"')))
    }).collect();
    let realm = params.iter().find(|(k, _)| *k == "realm").map(|(_, v)| *v)
        .context("no realm in Www-Authenticate")?;
    let service = params.iter().find(|(k, _)| *k == "service").map(|(_, v)| *v).unwrap_or("");
    let scope = format!("repository:{}:pull", image_ref.repository);
    let sep = if realm.contains('?') { '&' } else { '?' };
    let token_url = format!("{realm}{sep}service={service}&scope={scope}");
    let token_resp = agent.get(&token_url).call()
        .map_err(|e| anyhow::anyhow!("token request failed: {e}"))?;
    if token_resp.status() != 200 { bail!("token endpoint returned {}", token_resp.status()); }
    let mut body = String::new();
    token_resp.into_body().into_reader().take(1024 * 1024)
        .read_to_string(&mut body).context("failed to read token response")?;
    let t: TokenResponse = serde_json::from_str(&body).context("failed to parse token response")?;
    Ok(t.token.or(t.access_token).unwrap_or_default())
}

#[derive(Deserialize)]
struct TokenResponse { token: Option<String>, access_token: Option<String> }
