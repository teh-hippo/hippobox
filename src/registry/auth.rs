use anyhow::{bail, Context, Result};
use serde::Deserialize;
use crate::image::ref_parser::ImageRef;

/// Cached bearer tokens, keyed by registry+repo.
pub struct TokenCache {
    entries: Vec<(String, String)>, // (key, token)
}

impl TokenCache {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn get_token(&mut self, agent: &ureq::Agent, image_ref: &ImageRef) -> Result<String> {
        let key = format!("{}/{}", image_ref.registry, image_ref.repository);
        if let Some((_k, token)) = self.entries.iter().find(|(k, _)| k == &key) {
            return Ok(token.clone());
        }

        let token = fetch_anonymous_token(agent, image_ref)?;
        self.entries.push((key, token.clone()));
        Ok(token)
    }
}

fn fetch_anonymous_token(agent: &ureq::Agent, image_ref: &ImageRef) -> Result<String> {
    // Step 1: Hit /v2/ to get the Www-Authenticate challenge
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
        // No auth needed (rare, but some registries allow it)
        return Ok(String::new());
    }

    let www_auth = resp
        .headers()
        .get("Www-Authenticate")
        .or_else(|| resp.headers().get("www-authenticate"))
        .context("no Www-Authenticate header in 401 response")?
        .to_str()
        .context("invalid Www-Authenticate header encoding")?
        .to_string();

    // Step 2: Parse Bearer realm="...",service="...",scope="..."
    let params = parse_www_authenticate(&www_auth)?;
    let realm = params
        .iter()
        .find(|(k, _)| k == "realm")
        .map(|(_, v)| v.as_str())
        .context("no realm in Www-Authenticate")?;

    let service = params
        .iter()
        .find(|(k, _)| k == "service")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    // Step 3: Fetch token
    let scope = format!("repository:{}:pull", image_ref.repository);
    let token_url = if realm.contains('?') {
        format!("{realm}&service={service}&scope={scope}")
    } else {
        format!("{realm}?service={service}&scope={scope}")
    };

    let token_resp = agent
        .get(&token_url)
        .call()
        .map_err(|e| anyhow::anyhow!("token request failed: {e}"))?;

    if token_resp.status() != 200 {
        bail!("token endpoint returned {}", token_resp.status());
    }

    let body = token_resp
        .into_body()
        .read_to_string()
        .context("failed to read token response")?;

    let token_data: TokenResponse =
        serde_json::from_str(&body).context("failed to parse token response")?;

    Ok(token_data.token())
}

/// Parse a Www-Authenticate header like: Bearer realm="...",service="...",scope="..."
fn parse_www_authenticate(header: &str) -> Result<Vec<(String, String)>> {
    let header = header.trim();
    let rest = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .context("Www-Authenticate is not Bearer type")?;

    let mut params = Vec::new();
    for part in rest.split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let value = value.trim_matches('"');
            params.push((key.trim().to_string(), value.to_string()));
        }
    }
    Ok(params)
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

impl TokenResponse {
    fn token(&self) -> String {
        self.token
            .clone()
            .or_else(|| self.access_token.clone())
            .unwrap_or_default()
    }
}
