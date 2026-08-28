//! Structural verification for Veilweave subscription responses.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use reqwest::header::{HeaderMap, CONTENT_TYPE};
use reqwest::StatusCode;
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

const MAX_SUBSCRIPTION_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionFormat {
    Raw,
    Base64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSubscription {
    pub format: SubscriptionFormat,
    pub node_count: usize,
    pub raw: String,
}

pub fn verify_response(
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<VerifiedSubscription> {
    if status != StatusCode::OK {
        bail!("subscription endpoint returned HTTP {status}; expected HTTP 200");
    }
    if body.is_empty() {
        bail!("subscription endpoint returned HTTP 200 but the body was empty");
    }
    if body.len() > MAX_SUBSCRIPTION_BYTES {
        bail!(
            "subscription response exceeded the {} byte verification limit",
            MAX_SUBSCRIPTION_BYTES
        );
    }
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .context("subscription response is missing a valid Content-Type header")?;
    if !content_type.to_ascii_lowercase().starts_with("text/plain") {
        bail!("subscription Content-Type must be text/plain, got {content_type:?}");
    }

    let format = match header_text(headers, "X-Veilweave-Format")? {
        "raw" => SubscriptionFormat::Raw,
        "base64" => SubscriptionFormat::Base64,
        value => bail!("subscription declared unsupported format {value:?}"),
    };
    let declared_count = header_text(headers, "X-Node-Count")?
        .parse::<usize>()
        .context("X-Node-Count is not a valid integer")?;
    if declared_count == 0 {
        bail!("subscription declared zero nodes");
    }

    let encoded = std::str::from_utf8(body).context("subscription body is not UTF-8 text")?;
    let raw_bytes = match format {
        SubscriptionFormat::Raw => encoded.as_bytes().to_vec(),
        SubscriptionFormat::Base64 => general_purpose::STANDARD
            .decode(encoded.trim())
            .context("subscription body is not valid standard Base64")?,
    };
    let raw = String::from_utf8(raw_bytes).context("decoded subscription is not UTF-8")?;
    let nodes: Vec<&str> = raw.lines().filter(|line| !line.trim().is_empty()).collect();
    if nodes.is_empty() {
        bail!("subscription endpoint returned HTTP 200 but contained zero VLESS nodes");
    }
    if nodes.len() != declared_count {
        bail!(
            "X-Node-Count declared {declared_count} nodes but {} were present",
            nodes.len()
        );
    }
    for (index, node) in nodes.iter().enumerate() {
        verify_vless_uri(node).with_context(|| format!("invalid VLESS node at index {index}"))?;
    }

    Ok(VerifiedSubscription {
        format,
        node_count: nodes.len(),
        raw,
    })
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    headers
        .get(name)
        .with_context(|| format!("subscription response is missing {name}"))?
        .to_str()
        .with_context(|| format!("subscription response has invalid {name}"))
}

fn verify_vless_uri(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).context("URI parse failed")?;
    if url.scheme() != "vless" {
        bail!("URI scheme is not vless");
    }
    let uuid = Uuid::parse_str(url.username()).context("VLESS user is not a valid UUID")?;
    if uuid.is_nil() {
        bail!("VLESS UUID is the forbidden zero UUID");
    }
    let entry_host = url.host_str().context("VLESS entry host is missing")?;
    validate_host(entry_host).context("VLESS entry host is invalid")?;
    let port = url.port().context("VLESS entry port is missing")?;
    if port == 0 {
        bail!("VLESS entry port is zero");
    }

    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    if query.get("type").map(String::as_str) != Some("ws") {
        bail!("VLESS transport is not WebSocket");
    }
    let relay_host = query
        .get("host")
        .context("VLESS WebSocket host is missing")?;
    validate_hostname(relay_host).context("VLESS relay hostname is invalid")?;
    let path = query
        .get("path")
        .context("VLESS WebSocket path is missing")?;
    if !path.starts_with('/') {
        bail!("VLESS WebSocket path is not absolute");
    }
    let encryption = query
        .get("encryption")
        .context("VLESS encryption parameter is missing")?;
    if encryption.trim().is_empty() {
        bail!("VLESS encryption parameter is empty");
    }

    match query.get("security").map(String::as_str) {
        Some("tls") => {
            let sni = query.get("sni").context("TLS VLESS node is missing SNI")?;
            validate_hostname(sni).context("VLESS SNI is invalid")?;
            if !sni.eq_ignore_ascii_case(relay_host) {
                bail!("VLESS SNI does not match the relay hostname");
            }
            if query.get("insecure").map(String::as_str) != Some("0")
                || query.get("allowInsecure").map(String::as_str) != Some("0")
            {
                bail!("TLS VLESS node does not explicitly reject invalid certificates");
            }
        }
        Some("none") => {}
        _ => bail!("VLESS security must be tls or none"),
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    validate_hostname(host)
}

fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty() || hostname.len() > 253 || !hostname.contains('.') {
        bail!("hostname length or shape is invalid");
    }
    if !hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        bail!("hostname contains an invalid label");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    const NODE: &str = "vless://11111111-1111-4111-8111-111111111111@8.8.8.8:443?encryption=none&security=tls&type=ws&host=relay.example.com&path=%2Fws&sni=relay.example.com&fp=chrome&insecure=0&allowInsecure=0#US-01";

    fn headers(format: &str, count: usize) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        headers.insert("X-Veilweave-Format", HeaderValue::from_str(format).unwrap());
        headers.insert(
            "X-Node-Count",
            HeaderValue::from_str(&count.to_string()).unwrap(),
        );
        headers
    }

    #[test]
    fn accepts_valid_raw_and_base64_subscriptions() {
        let raw = verify_response(StatusCode::OK, &headers("raw", 1), NODE.as_bytes()).unwrap();
        assert_eq!(raw.node_count, 1);
        let body = general_purpose::STANDARD.encode(NODE);
        let encoded =
            verify_response(StatusCode::OK, &headers("base64", 1), body.as_bytes()).unwrap();
        assert_eq!(encoded.raw, NODE);
    }

    #[test]
    fn rejects_http_and_body_false_positives() {
        assert!(
            verify_response(StatusCode::NOT_FOUND, &headers("raw", 1), NODE.as_bytes()).is_err()
        );
        assert!(
            verify_response(StatusCode::FORBIDDEN, &headers("raw", 1), NODE.as_bytes()).is_err()
        );
        assert!(verify_response(StatusCode::OK, &headers("raw", 1), b"").is_err());
        assert!(verify_response(
            StatusCode::OK,
            &headers("raw", 1),
            b"<html>camouflage</html>"
        )
        .is_err());
        assert!(verify_response(StatusCode::OK, &headers("base64", 1), b"not-base64").is_err());
    }

    #[test]
    fn rejects_zero_uuid_malformed_transport_and_count_mismatch() {
        let zero = NODE.replace(
            "11111111-1111-4111-8111-111111111111",
            "00000000-0000-0000-0000-000000000000",
        );
        assert!(verify_response(StatusCode::OK, &headers("raw", 1), zero.as_bytes()).is_err());
        let tcp = NODE.replace("type=ws", "type=tcp");
        assert!(verify_response(StatusCode::OK, &headers("raw", 1), tcp.as_bytes()).is_err());
        assert!(verify_response(StatusCode::OK, &headers("raw", 2), NODE.as_bytes()).is_err());
    }
}
