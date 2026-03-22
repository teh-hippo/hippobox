use crate::image::{Descriptor, ImageConfig, ImageRef, Manifest, StoredImage};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

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

    let safe_dir = |relative: &Path| -> Result<PathBuf> {
        if has_unsafe_components(relative) {
            bail!("unsafe archive path component in {}", relative.display());
        }
        let mut out = target.to_path_buf();
        for component in relative.components() {
            if let Component::Normal(part) = component {
                out.push(part);
                match fs::symlink_metadata(&out) {
                    Ok(m) if m.file_type().is_symlink() => bail!(
                        "refusing to traverse symlink while extracting: {}",
                        out.display()
                    ),
                    Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
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
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if file_name == ".wh..wh..opq" {
            let parent = safe_dir(path.parent().unwrap_or(Path::new("")))?;
            let c_path = CString::new(parent.to_string_lossy().as_bytes())?;
            let ret = unsafe {
                nix::libc::setxattr(
                    c_path.as_ptr(),
                    c"trusted.overlay.opaque".as_ptr(),
                    b"y".as_ptr().cast(),
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
                || deleted_name == "."
                || deleted_name == ".."
                || deleted_name.contains('/')
                || deleted_name.contains('\\')
                || Path::new(deleted_name).components().count() != 1
            {
                bail!("unsafe whiteout name: {deleted_name}");
            }
            let parent = safe_dir(path.parent().unwrap_or(Path::new("")))?;
            let wp = parent.join(deleted_name);
            if let Ok(m) = fs::symlink_metadata(&wp) {
                if m.file_type().is_dir() && !m.file_type().is_symlink() {
                    fs::remove_dir_all(&wp)?;
                } else {
                    fs::remove_file(&wp)?;
                }
            }
            nix::sys::stat::mknod(
                &wp,
                nix::sys::stat::SFlag::S_IFCHR,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                nix::sys::stat::makedev(0, 0),
            )
            .with_context(|| format!("failed to create whiteout at {}", wp.display()))?;
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
        let tmp = target_dir.with_extension(format!("tmp-{pid}-{nonce}"));
        match fs::create_dir(&tmp) {
            Ok(()) => {
                fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700))?;
                return Ok(tmp);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!(
        "failed to create a unique extraction temp dir for {}",
        target_dir.display()
    )
}

struct HashingReader<R: Read> {
    inner: R,
    ctx: ring::digest::Context,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.ctx.update(&buf[..n]);
        }
        Ok(n)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;
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
        let old_stored: Option<StoredImage> = fs::read(&config_path)
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok());
        let manifest = self.fetch_manifest(image_ref)?;
        let config = self.fetch_config(image_ref, &manifest)?;
        for layer in &manifest.layers {
            let (hex, layer_dir) = (layer.hex(), layer.layer_dir(base_dir));
            if layer_dir.exists() {
                eprintln!("  layer {} already exists, skipping", &hex[..12]);
                continue;
            }
            eprintln!("  pulling layer {}...", &hex[..12]);
            self.download_and_extract_layer(image_ref, layer, &layer_dir)?;
        }
        let stored = StoredImage { manifest, config };
        fs::create_dir_all(
            config_path
                .parent()
                .context("invalid image metadata path")?,
        )?;
        fs::write(&config_path, serde_json::to_vec(&stored)?)?;
        if let Some(ref old) = old_stored {
            auto_prune_layers(old, &stored, base_dir)?;
        }
        Ok(stored)
    }
    fn api_url(image_ref: &ImageRef, kind: &str, reference: &str) -> String {
        format!(
            "https://{}/v2/{}/{kind}/{reference}",
            image_ref.registry, image_ref.repository
        )
    }
    fn fetch_manifest(&mut self, image_ref: &ImageRef) -> Result<Manifest> {
        let url = Self::api_url(image_ref, "manifests", &image_ref.tag);
        let accept = "application/vnd.oci.image.index.v1+json, \
            application/vnd.oci.image.manifest.v1+json, \
            application/vnd.docker.distribution.manifest.list.v2+json, \
            application/vnd.docker.distribution.manifest.v2+json";
        let response: serde_json::Value = serde_json::from_reader(
            self.authenticated_get(image_ref, &url, accept)?
                .into_body()
                .into_reader()
                .take(MAX_RESPONSE_BYTES),
        )
        .context("failed to parse manifest response")?;
        if let Some(manifests) = response.get("manifests").and_then(|v| v.as_array()) {
            let digest = manifests
                .iter()
                .find_map(|entry| {
                    let p = entry.get("platform")?;
                    (p.get("os")?.as_str()? == "linux"
                        && p.get("architecture")?.as_str()? == "amd64")
                        .then(|| entry.get("digest")?.as_str())?
                })
                .context("no linux/amd64 platform found in manifest index")?;
            let url = Self::api_url(image_ref, "manifests", digest);
            let accept = "application/vnd.oci.image.manifest.v1+json, \
                application/vnd.docker.distribution.manifest.v2+json";
            return serde_json::from_reader(
                self.authenticated_get(image_ref, &url, accept)?
                    .into_body()
                    .into_reader()
                    .take(MAX_RESPONSE_BYTES),
            )
            .context("failed to parse platform manifest");
        }
        serde_json::from_value(response).context("failed to parse manifest response")
    }

    fn fetch_config(&mut self, image_ref: &ImageRef, manifest: &Manifest) -> Result<ImageConfig> {
        let url = Self::api_url(image_ref, "blobs", &manifest.config.digest);
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
        let url = Self::api_url(image_ref, "blobs", &layer.digest);
        let token = get_anonymous_token(&mut self.token_cache, &self.agent, image_ref)?;
        let mut req = self.agent.get(&url);
        if !token.is_empty() {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        let resp = req
            .config()
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|e| anyhow::anyhow!("blob request failed: {e}"))?;
        let resp = if matches!(resp.status().as_u16(), 301 | 302 | 307) {
            let loc = resp
                .headers()
                .get("Location")
                .context("redirect without Location")?
                .to_str()
                .context("invalid Location header")?
                .to_string();
            self.agent
                .get(&loc)
                .call()
                .map_err(|e| anyhow::anyhow!("redirect failed: {e}"))?
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
                ctx: ring::digest::Context::new(&ring::digest::SHA256),
            };
            let mt = layer.media_type.as_deref();
            let is_gzip = mt.is_none_or(|m| m.contains("tar+gzip") || m.ends_with("diff.tar.gzip"));
            let reader = if is_gzip {
                let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(reader));
                extract_with_whiteouts(&mut ar, &tmp_dir)?;
                ar.into_inner().into_inner()
            } else if matches!(
                mt,
                Some(
                    "application/vnd.oci.image.layer.v1.tar"
                        | "application/vnd.docker.image.rootfs.diff.tar"
                )
            ) {
                let mut ar = tar::Archive::new(reader);
                extract_with_whiteouts(&mut ar, &tmp_dir)?;
                ar.into_inner()
            } else {
                bail!("unsupported layer media type: {mt:?}")
            };
            let digest = reader.ctx.finish();
            let computed = format!("sha256:{}", hex(digest.as_ref()));
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
        let mut req = self.agent.get(url).header("Accept", accept);
        if !token.is_empty() {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        let resp = req
            .call()
            .map_err(|e| anyhow::anyhow!("request failed: {e}"))?;
        if resp.status() != 200 {
            bail!("HTTP {} for {}", resp.status(), url);
        }
        Ok(resp)
    }
}

fn auto_prune_layers(old: &StoredImage, new: &StoredImage, base_dir: &Path) -> Result<()> {
    let new_digests: std::collections::HashSet<&str> = new
        .manifest
        .layers
        .iter()
        .map(|l| l.digest.as_str())
        .collect();
    let orphaned: Vec<&str> = old
        .manifest
        .layers
        .iter()
        .map(|l| l.digest.as_str())
        .filter(|d| !new_digests.contains(d))
        .collect();
    if orphaned.is_empty() {
        return Ok(());
    }
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
    for digest in orphaned {
        if referenced.contains(digest) {
            continue;
        }
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        let layer_dir = base_dir.join("layers/sha256").join(hex);
        if layer_dir.exists() && !layer_dir.join(".in-use").exists() {
            fs::remove_dir_all(&layer_dir).with_context(|| {
                format!("failed to prune old layer {}", &hex[..hex.len().min(12)])
            })?;
            eprintln!("  pruned old layer {}", &hex[..hex.len().min(12)]);
        }
    }
    Ok(())
}
fn get_anonymous_token(
    cache: &mut HashMap<String, String>,
    agent: &ureq::Agent,
    image_ref: &ImageRef,
) -> Result<String> {
    let key = format!("{}/{}", image_ref.registry, image_ref.repository);
    if let Some(token) = cache.get(&key) {
        return Ok(token.clone());
    }
    let token = fetch_anonymous_token(agent, image_ref)?;
    cache.insert(key, token.clone());
    Ok(token)
}
fn fetch_anonymous_token(agent: &ureq::Agent, image_ref: &ImageRef) -> Result<String> {
    let v2_url = format!("https://{}/v2/", image_ref.registry);
    let resp = agent
        .get(&v2_url)
        .config()
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .call()
        .map_err(|e| anyhow::anyhow!("v2 ping failed: {e}"))?;
    if resp.status() == 200 {
        return Ok(String::new());
    }
    let www_auth = resp
        .headers()
        .get("Www-Authenticate")
        .context("no Www-Authenticate header in 401 response")?
        .to_str()
        .context("invalid Www-Authenticate header encoding")?
        .to_string();
    let rest = www_auth
        .trim()
        .strip_prefix("Bearer ")
        .or_else(|| www_auth.trim().strip_prefix("bearer "))
        .context("Www-Authenticate is not Bearer type")?;
    let params: Vec<(&str, &str)> = rest
        .split(',')
        .filter_map(|part| {
            let (k, v) = part.trim().split_once('=')?;
            Some((k.trim(), v.trim_matches('"')))
        })
        .collect();
    let realm = params
        .iter()
        .find(|(k, _)| *k == "realm")
        .map(|(_, v)| *v)
        .context("no realm in Www-Authenticate")?;
    let service = params
        .iter()
        .find(|(k, _)| *k == "service")
        .map(|(_, v)| *v)
        .unwrap_or("");
    let scope = format!("repository:{}:pull", image_ref.repository);
    let sep = if realm.contains('?') { '&' } else { '?' };
    let token_url = format!("{realm}{sep}service={service}&scope={scope}");
    let token_resp = agent
        .get(&token_url)
        .call()
        .map_err(|e| anyhow::anyhow!("token request failed: {e}"))?;
    if token_resp.status() != 200 {
        bail!("token endpoint returned {}", token_resp.status());
    }
    let mut body = String::new();
    token_resp
        .into_body()
        .into_reader()
        .take(1024 * 1024)
        .read_to_string(&mut body)
        .context("failed to read token response")?;
    let t: TokenResponse = serde_json::from_str(&body).context("failed to parse token response")?;
    Ok(t.token.or(t.access_token).unwrap_or_default())
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{Descriptor, ImageConfig, ImageRef, Manifest, StoredImage};
    use tempfile::TempDir;

    fn tar_entry(path: &str, content: &[u8], mode: u32, etype: tar::EntryType) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_path(path).unwrap();
        h.set_size(content.len() as u64);
        h.set_mode(mode);
        h.set_entry_type(etype);
        h.set_cksum();
        b.append(&h, content).unwrap();
        b.into_inner().unwrap()
    }
    fn tar_raw_path(path_bytes: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.as_gnu_mut().unwrap().name[..path_bytes.len()].copy_from_slice(path_bytes);
        h.as_gnu_mut().unwrap().name[path_bytes.len()] = 0;
        h.set_size(4);
        h.set_mode(0o644);
        h.set_cksum();
        b.append(&h, b"evil" as &[u8]).unwrap();
        b.into_inner().unwrap()
    }
    fn untar(data: &[u8], dir: &Path) -> Result<()> {
        extract_with_whiteouts(&mut tar::Archive::new(std::io::Cursor::new(data)), dir)
    }
    fn desc(d: &str) -> Descriptor {
        Descriptor {
            media_type: None,
            digest: d.into(),
            size: 100,
        }
    }
    fn stored(digests: &[&str]) -> StoredImage {
        StoredImage {
            manifest: Manifest {
                config: desc("sha256:cfg"),
                layers: digests.iter().map(|d| desc(d)).collect(),
            },
            config: ImageConfig {
                config: None,
                rootfs: None,
            },
        }
    }
    fn mk_layer(b: &Path, d: &str) {
        std::fs::create_dir_all(
            b.join("layers/sha256")
                .join(d.strip_prefix("sha256:").unwrap_or(d)),
        )
        .unwrap();
    }
    fn has_layer(b: &Path, d: &str) -> bool {
        b.join("layers/sha256")
            .join(d.strip_prefix("sha256:").unwrap_or(d))
            .exists()
    }

    #[test]
    fn path_safety() {
        for (p, expect) in [
            ("usr/bin/bash", false),
            ("./foo/bar", false),
            ("", false),
            ("/etc/passwd", true),
            ("foo/../etc", true),
            ("..", true),
        ] {
            assert_eq!(has_unsafe_components(Path::new(p)), expect, "path={p:?}");
        }
    }
    #[test]
    fn hashing_reader() {
        for data in [
            b"hello world" as &[u8],
            b"",
            b"The quick brown fox jumps over the lazy dog",
        ] {
            let expected = hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref());
            let mut r = HashingReader {
                inner: std::io::Cursor::new(data),
                ctx: ring::digest::Context::new(&ring::digest::SHA256),
            };
            let mut buf = [0u8; 5];
            let mut total = Vec::new();
            loop {
                let n = r.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                total.extend_from_slice(&buf[..n]);
            }
            assert_eq!(total, data);
            assert_eq!(hex(r.ctx.finish().as_ref()), expected);
        }
    }
    #[test]
    fn extract_valid_and_nested() {
        let t = TempDir::new().unwrap();
        untar(
            &tar_entry("hello.txt", b"hello", 0o644, tar::EntryType::Regular),
            t.path(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(t.path().join("hello.txt")).unwrap(),
            "hello"
        );
        let t2 = TempDir::new().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut dh = tar::Header::new_gnu();
        dh.set_path("usr/local/bin/").unwrap();
        dh.set_size(0);
        dh.set_mode(0o755);
        dh.set_entry_type(tar::EntryType::Directory);
        dh.set_cksum();
        b.append(&dh, &[][..]).unwrap();
        let mut fh = tar::Header::new_gnu();
        fh.set_path("usr/local/bin/tool").unwrap();
        fh.set_size(4);
        fh.set_mode(0o755);
        fh.set_cksum();
        b.append(&fh, b"test" as &[u8]).unwrap();
        untar(&b.into_inner().unwrap(), t2.path()).unwrap();
        assert_eq!(
            fs::read_to_string(t2.path().join("usr/local/bin/tool")).unwrap(),
            "test"
        );
    }
    #[test]
    fn extract_security() {
        for p in [b"/etc/shadow" as &[u8], b"../../etc/passwd"] {
            assert!(untar(&tar_raw_path(p), &TempDir::new().unwrap().path()).is_err());
        }
        let t = TempDir::new().unwrap();
        std::os::unix::fs::symlink("/tmp", t.path().join("evil")).unwrap();
        assert!(
            untar(
                &tar_entry(
                    "evil/payload.txt",
                    b"attack",
                    0o644,
                    tar::EntryType::Regular
                ),
                t.path()
            )
            .is_err()
        );
        let t2 = TempDir::new().unwrap();
        fs::write(t2.path().join("existing.txt"), "data").unwrap();
        let _ = untar(
            &tar_entry(".wh.existing.txt", b"", 0o644, tar::EntryType::Regular),
            t2.path(),
        );
        for name in [".wh.", ".wh..", ".wh...", r".wh.foo\bar"] {
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            if h.set_path(name).is_err() {
                continue;
            }
            h.set_size(0);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append(&h, &[][..]).unwrap();
            assert!(
                untar(&b.into_inner().unwrap(), &TempDir::new().unwrap().path()).is_err(),
                "should reject {name:?}"
            );
        }
    }
    #[test]
    fn temp_dir_unique() {
        let t = TempDir::new().unwrap();
        let target = t.path().join("layers/sha256/abc123");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let (d1, d2) = (
            create_extract_temp_dir(&target).unwrap(),
            create_extract_temp_dir(&target).unwrap(),
        );
        assert_ne!(d1, d2);
        for d in [&d1, &d2] {
            assert_eq!(fs::metadata(d).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }
    #[test]
    fn auto_prune() {
        let t = TempDir::new().unwrap();
        let b = t.path();
        std::fs::create_dir_all(b.join("images")).unwrap();
        for d in ["sha256:aaa", "sha256:bbb", "sha256:ccc"] {
            mk_layer(b, d);
        }
        auto_prune_layers(
            &stored(&["sha256:aaa", "sha256:bbb"]),
            &stored(&["sha256:bbb", "sha256:ccc"]),
            b,
        )
        .unwrap();
        assert!(
            !has_layer(b, "sha256:aaa") && has_layer(b, "sha256:bbb") && has_layer(b, "sha256:ccc")
        );
        // Referenced by other image
        for d in ["sha256:shared", "sha256:orphan"] {
            mk_layer(b, d);
        }
        let other = stored(&["sha256:shared", "sha256:other"]);
        let dir = b.join("images/reg/other/img");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("latest.json"), serde_json::to_vec(&other).unwrap()).unwrap();
        auto_prune_layers(
            &stored(&["sha256:shared", "sha256:orphan"]),
            &stored(&["sha256:new"]),
            b,
        )
        .unwrap();
        assert!(has_layer(b, "sha256:shared") && !has_layer(b, "sha256:orphan"));
        // In-use marker
        mk_layer(b, "sha256:busy");
        std::fs::write(b.join("layers/sha256/busy/.in-use"), "cid").unwrap();
        auto_prune_layers(&stored(&["sha256:busy"]), &stored(&["sha256:x"]), b).unwrap();
        assert!(has_layer(b, "sha256:busy"));
        // Noop
        mk_layer(b, "sha256:a2");
        mk_layer(b, "sha256:b3");
        auto_prune_layers(
            &stored(&["sha256:a2", "sha256:b3"]),
            &stored(&["sha256:a2", "sha256:b3"]),
            b,
        )
        .unwrap();
        assert!(has_layer(b, "sha256:a2") && has_layer(b, "sha256:b3"));
    }
    #[test]
    fn api_url_format() {
        let ghcr = ImageRef::parse("ghcr.io/owner/repo:v1").unwrap();
        assert_eq!(
            RegistryClient::api_url(&ghcr, "manifests", "v1"),
            "https://ghcr.io/v2/owner/repo/manifests/v1"
        );
        assert_eq!(
            RegistryClient::api_url(&ghcr, "blobs", "sha256:abc"),
            "https://ghcr.io/v2/owner/repo/blobs/sha256:abc"
        );
        let hub = ImageRef::parse("nginx").unwrap();
        assert_eq!(
            RegistryClient::api_url(&hub, "manifests", "latest"),
            "https://registry-1.docker.io/v2/library/nginx/manifests/latest"
        );
    }
    #[test]
    fn token_cache_and_parsing() {
        let img = ImageRef::parse("ghcr.io/owner/repo:v1").unwrap();
        let mut cache = HashMap::new();
        cache.insert("ghcr.io/owner/repo".to_string(), "cached-123".to_string());
        assert_eq!(
            get_anonymous_token(&mut cache, &ureq::Agent::new_with_defaults(), &img).unwrap(),
            "cached-123"
        );
        for (json, tok, at) in [
            (r#"{"token":"t1"}"#, Some("t1"), None),
            (r#"{"access_token":"a1"}"#, None, Some("a1")),
            (r#"{"token":"t","access_token":"a"}"#, Some("t"), Some("a")),
            (r#"{}"#, None, None),
        ] {
            let t: TokenResponse = serde_json::from_str(json).unwrap();
            assert_eq!(t.token.as_deref(), tok);
            assert_eq!(t.access_token.as_deref(), at);
        }
    }
}
