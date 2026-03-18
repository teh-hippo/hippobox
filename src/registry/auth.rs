use crate::image::ref_parser::ImageRef;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashMap;

pub fn get_anonymous_token(
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
        .or_else(|| resp.headers().get("www-authenticate"))
        .context("no Www-Authenticate header in 401 response")?
        .to_str()
        .context("invalid Www-Authenticate header encoding")?
        .to_string();

    let mut params = Vec::new();
    let rest = www_auth
        .trim()
        .strip_prefix("Bearer ")
        .or_else(|| www_auth.trim().strip_prefix("bearer "))
        .context("Www-Authenticate is not Bearer type")?;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            params.push((key.trim().to_string(), value.trim_matches('"').to_string()));
        }
    }
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

    Ok(token_data
        .token
        .or(token_data.access_token)
        .unwrap_or_default())
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}
