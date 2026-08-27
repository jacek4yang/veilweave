use base64::{engine::general_purpose, Engine as _};
use futures_util::future::{select, Either};
use futures_util::{FutureExt, StreamExt};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write as FmtWrite};
use std::time::Duration;
use worker::*;

mod apache_mock;
mod codec;
mod egress;
mod encoding;
mod geo;
mod hmac;
mod optimized_ip;
mod path;
mod proxyip;
mod refresher;
mod rng;
mod secret;
mod sha256;

use codec::{UuidCodec, TYPE_PROXYIP};
use egress::EgressEntry;
use encoding::{format_uuid, percent_encode};
use proxyip::{
    parse_cached, parse_country_code, validate_promotion, ProxyIpDataset, ProxyIpError,
    ProxyIpErrorCode, RefreshFailure, ACTIVE_KEY, FAILURE_KEY, FETCH_TIMEOUT_SECS,
    MAX_SOURCE_BYTES, PREVIOUS_KEY, SOURCE_URL,
};

use crate::apache_mock::apache_default_page;

const DEFAULT_MAX_NODES: usize = 100;
const MAX_NODES_LIMIT: usize = 200;
const PROFILE_UPDATE_INTERVAL_HOURS: &str = "6";

thread_local! {
    // This PRNG is only for path variety and equivalent-candidate ordering.
    // Signed UUID nonces come exclusively from WebCrypto in `rng`.
    static PRNG: RefCell<Xorshift64> = RefCell::new(Xorshift64::new(0xdeadbeefc0febabe));
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    match url.path() {
        "/sub" => handle_sub_request(&req, &env).await,
        "/_veilweave/proxyip/status" => handle_proxyip_status(&req, &env).await,
        "/_veilweave/proxyip/refresh" => handle_proxyip_refresh(&req, &env).await,
        _ => apache_default_page(req),
    }
}

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    // The top-level Free-plan Worker has a 10 ms CPU ceiling. Delegate the
    // multi-megabyte source parse to one named Durable Object invocation, which
    // has a 30-second CPU allowance and also serializes refreshes to prevent a
    // scheduled/manual stampede.
    match invoke_proxyip_refresher(&env).await {
        Ok(response) if response.status_code() == 200 => {
            console_log!("event=proxyip_refresh_dispatch status=ok")
        }
        Ok(response) => console_error!(
            "event=proxyip_refresh_dispatch status=failed http_status={}",
            response.status_code()
        ),
        Err(error) => console_error!(
            "event=proxyip_refresh_dispatch status=failed code=DurableObjectUnavailable detail={error}"
        ),
    }
}

async fn handle_sub_request(req: &Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Get || !query_token_is_valid(req, env) {
        return not_found();
    }

    let options = match SubscriptionOptions::from_request(req) {
        Ok(options) => options,
        Err(message) => return client_error(&message),
    };
    let max_nodes = match configured_max_nodes(env) {
        Ok(value) => value,
        Err(message) => return unavailable(&message),
    };
    let Some(kv) = resolve_kv(env) else {
        return unavailable("ProxyIP cache binding is unavailable.");
    };

    let dataset = match load_known_good(&kv).await {
        Ok(dataset) => dataset,
        Err(error) => return unavailable(error.public_message()),
    };
    let now_ms = now_ms();
    let stale = dataset.is_stale(now_ms);

    let user_country =
        extract_cf_header(req, "CF-IPCountry").and_then(|value| parse_country_code(&value).ok());
    let user_asn = extract_cf_header(req, "CF-ASN").and_then(|value| value.parse::<u32>().ok());
    let user_geo = geo::detect_user_geo(user_country.as_deref().unwrap_or("XX"), user_asn);

    let requested = options.requested_countries();
    let rotation_seed = selection_seed(
        &dataset.revision,
        user_country.as_deref(),
        user_asn,
        requested,
    );
    let entries = dataset.select(requested, user_country.as_deref(), max_nodes, rotation_seed);
    if entries.is_empty() {
        return unavailable("No usable proxyIP entries match the requested country selection.");
    }

    let relay_nodes = load_veilweave_nodes(env);
    if relay_nodes.is_empty() {
        return unavailable("Relay topology is unavailable.");
    }
    let render_config = match RenderConfig::from_env(env, options.secure) {
        Ok(config) => config,
        Err(message) => return unavailable(&message),
    };

    let optimized_ips = optimized_ip::load_cached_optimized_ips(Some(&kv))
        .await
        .unwrap_or_default();
    let optimized_ip_list = get_optimized_ip_list(user_geo.carrier, &optimized_ips);

    // One WebCrypto call supplies a path-randomization seed followed by four
    // independent nonce bytes per node.
    let random = match rng::random_bytes(8 + entries.len() * 4) {
        Ok(random) => random,
        Err(error) => {
            console_error!("event=subscription_render status=failed code=CsprngUnavailable");
            return unavailable(&error);
        }
    };
    let mut seed_bytes = [0u8; 8];
    seed_bytes.copy_from_slice(&random[..8]);
    init_prng(u64::from_le_bytes(seed_bytes));
    let raw = match build_subscription(
        &relay_nodes,
        &render_config,
        &entries,
        &optimized_ip_list,
        &random[8..],
    ) {
        Ok(body) => body,
        Err(error) => {
            console_error!(
                "event=subscription_render status=failed code=SubscriptionRenderFailed detail={error}"
            );
            return unavailable("Subscription rendering failed.");
        }
    };

    console_log!(
        "event=subscription_render status=ok nodes={} revision={} stale={} format={}",
        entries.len(),
        dataset.revision,
        stale,
        options.format.as_str()
    );
    build_subscription_response(
        &raw,
        options.format,
        entries.len(),
        &dataset.revision,
        stale,
    )
}

async fn handle_proxyip_status(req: &Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Get || !bearer_token_is_valid(req, env) {
        return not_found();
    }
    let Some(kv) = resolve_kv(env) else {
        return unavailable("ProxyIP cache binding is unavailable.");
    };

    let dataset = load_known_good(&kv).await.ok();
    let last_failure = match kv.get(FAILURE_KEY).text().await {
        Ok(Some(value)) => serde_json::from_str::<RefreshFailure>(&value).ok(),
        _ => None,
    };
    let now = now_ms();
    let status = ProxyIpStatus {
        source: SOURCE_URL,
        validation: if dataset.is_some() {
            "valid"
        } else {
            "unavailable"
        },
        revision: dataset.as_ref().map(|value| value.revision.as_str()),
        last_success_ms: dataset.as_ref().map(|value| value.refreshed_at_ms),
        age_ms: dataset
            .as_ref()
            .map(|value| now.saturating_sub(value.refreshed_at_ms)),
        stale: dataset.as_ref().is_some_and(|value| value.is_stale(now)),
        accepted_count: dataset.as_ref().map(|value| value.accepted_count),
        rejected_count: dataset.as_ref().map(|value| value.rejected_count),
        stored_count: dataset.as_ref().map(|value| value.stored_count),
        country_count: dataset.as_ref().map(|value| value.countries.len()),
        last_failure,
    };
    json_response(&status, 200)
}

async fn handle_proxyip_refresh(req: &Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post || !bearer_token_is_valid(req, env) {
        return not_found();
    }
    match invoke_proxyip_refresher(env).await {
        Ok(response) => Ok(response),
        Err(error) => {
            console_error!(
                "event=proxyip_refresh_dispatch status=failed code=DurableObjectUnavailable detail={error}"
            );
            unavailable("ProxyIP refresh service is unavailable.")
        }
    }
}

async fn invoke_proxyip_refresher(env: &Env) -> Result<Response> {
    let namespace = env.durable_object("PROXYIP_REFRESHER")?;
    let stub = namespace
        .id_from_name("authoritative-all-json")?
        .get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    let request = Request::new_with_init("https://veilweave.internal/refresh", &init)?;
    stub.fetch_with_request(request).await
}

async fn load_known_good(kv: &KvStore) -> Result<ProxyIpDataset, ProxyIpError> {
    for key in [ACTIVE_KEY, PREVIOUS_KEY] {
        if let Ok(Some(value)) = kv.get(key).text().await {
            match parse_cached(&value) {
                Ok(dataset) => {
                    if key == PREVIOUS_KEY {
                        console_warn!(
                            "event=proxyip_cache status=fallback reason=active_missing_or_invalid"
                        );
                    }
                    return Ok(dataset);
                }
                Err(error) => console_error!(
                    "event=proxyip_cache status=invalid key={} code={}",
                    key,
                    error.code.as_str()
                ),
            }
        }
    }
    Err(ProxyIpError::new(
        ProxyIpErrorCode::DatasetUnavailable,
        "no known-good proxyIP generation exists",
    ))
}

async fn refresh_and_record(kv: &KvStore) -> Result<ProxyIpDataset, ProxyIpError> {
    match refresh_proxyip(kv).await {
        Ok(dataset) => {
            let _ = kv.delete(FAILURE_KEY).await;
            Ok(dataset)
        }
        Err(error) => {
            let failure = RefreshFailure {
                at_ms: now_ms(),
                code: error.code.as_str().to_string(),
                message: truncate_diagnostic(&error.detail),
            };
            if let Ok(value) = serde_json::to_string(&failure) {
                if let Ok(put) = kv.put(FAILURE_KEY, value) {
                    let _ = put.execute().await;
                }
            }
            Err(error)
        }
    }
}

async fn refresh_proxyip(kv: &KvStore) -> Result<ProxyIpDataset, ProxyIpError> {
    let active_raw = kv.get(ACTIVE_KEY).text().await.ok().flatten();
    let active = active_raw
        .as_deref()
        .and_then(|value| parse_cached(value).ok());
    let previous_raw = if active.is_none() {
        kv.get(PREVIOUS_KEY).text().await.ok().flatten()
    } else {
        None
    };
    let previous = active.clone().or_else(|| {
        previous_raw
            .as_deref()
            .and_then(|value| parse_cached(value).ok())
    });

    let fetched = fetch_proxyip_source(
        previous
            .as_ref()
            .and_then(|dataset| dataset.source_etag.as_deref()),
    )
    .await?;
    let candidate = match fetched {
        SourceFetch::NotModified => {
            let mut dataset = previous.clone().ok_or_else(|| {
                ProxyIpError::new(
                    ProxyIpErrorCode::DatasetUnavailable,
                    "source returned 304 but no known-good cache exists",
                )
            })?;
            dataset.refreshed_at_ms = now_ms();
            dataset
        }
        SourceFetch::Modified { bytes, etag } => {
            ProxyIpDataset::from_source(&bytes, now_ms(), etag)?
        }
    };
    validate_promotion(previous.as_ref(), &candidate)?;

    let candidate_raw = serde_json::to_string(&candidate).map_err(|error| {
        ProxyIpError::new(
            ProxyIpErrorCode::DatasetInvalid,
            format!("compact dataset serialization failed: {error}"),
        )
    })?;
    let known_good_raw = active_raw.as_deref().or(previous_raw.as_deref());
    if let Some(value) = known_good_raw {
        kv.put(PREVIOUS_KEY, value)
            .map_err(|error| cache_write_error("prepare previous generation", error))?
            .execute()
            .await
            .map_err(|error| cache_write_error("prepare previous generation", error))?;
    }
    kv.put(ACTIVE_KEY, candidate_raw)
        .map_err(|error| cache_write_error("promote active generation", error))?
        .execute()
        .await
        .map_err(|error| cache_write_error("promote active generation", error))?;
    Ok(candidate)
}

enum SourceFetch {
    NotModified,
    Modified {
        bytes: Vec<u8>,
        etag: Option<String>,
    },
}

async fn fetch_proxyip_source(etag: Option<&str>) -> Result<SourceFetch, ProxyIpError> {
    let controller = AbortController::default();
    let signal = controller.signal();
    let fetch = fetch_proxyip_source_inner(etag, &signal).boxed_local();
    let timeout = Delay::from(Duration::from_secs(FETCH_TIMEOUT_SECS)).boxed_local();

    let result = match select(fetch, timeout).await {
        Either::Left((result, _)) => result,
        Either::Right(((), _)) => {
            controller.abort();
            Err(ProxyIpError::new(
                ProxyIpErrorCode::Timeout,
                format!("source fetch exceeded {FETCH_TIMEOUT_SECS} seconds"),
            ))
        }
    };
    result
}

async fn fetch_proxyip_source_inner(
    etag: Option<&str>,
    signal: &AbortSignal,
) -> Result<SourceFetch, ProxyIpError> {
    let headers = Headers::new();
    headers
        .set("Accept", "application/json, text/plain;q=0.8")
        .map_err(fetch_error)?;
    headers
        .set("User-Agent", "Veilweave-Sub/2 proxyip-refresh")
        .map_err(fetch_error)?;
    if let Some(etag) = etag {
        headers.set("If-None-Match", etag).map_err(fetch_error)?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Get)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Error)
        .with_cache(CacheMode::NoStore);
    let request = Request::new_with_init(SOURCE_URL, &init).map_err(fetch_error)?;
    let mut response = Fetch::Request(request)
        .send_with_signal(signal)
        .await
        .map_err(fetch_error)?;

    if response.status_code() == 304 {
        return Ok(SourceFetch::NotModified);
    }
    if response.status_code() != 200 {
        return Err(ProxyIpError::new(
            ProxyIpErrorCode::HttpStatus,
            format!("source returned HTTP {}", response.status_code()),
        ));
    }

    if let Ok(Some(length)) = response.headers().get("Content-Length") {
        if length
            .parse::<usize>()
            .ok()
            .is_some_and(|length| length > MAX_SOURCE_BYTES)
        {
            return Err(ProxyIpError::new(
                ProxyIpErrorCode::Oversized,
                format!("source Content-Length exceeds {MAX_SOURCE_BYTES} bytes"),
            ));
        }
    }
    let response_etag = response.headers().get("ETag").ok().flatten();
    let mut bytes = Vec::new();
    let mut stream = response.stream().map_err(fetch_error)?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(fetch_error)?;
        if bytes.len().saturating_add(chunk.len()) > MAX_SOURCE_BYTES {
            return Err(ProxyIpError::new(
                ProxyIpErrorCode::Oversized,
                format!("source body exceeds {MAX_SOURCE_BYTES} bytes"),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(SourceFetch::Modified {
        bytes,
        etag: response_etag,
    })
}

fn fetch_error(error: impl fmt::Display) -> ProxyIpError {
    ProxyIpError::new(ProxyIpErrorCode::FetchFailed, error.to_string())
}

fn cache_write_error(operation: &str, error: impl fmt::Display) -> ProxyIpError {
    ProxyIpError::new(
        ProxyIpErrorCode::CacheWriteFailed,
        format!("{operation}: {error}"),
    )
}

fn resolve_kv(env: &Env) -> Option<KvStore> {
    env.var("KV_BINDING")
        .ok()
        .map(|value| value.to_string())
        .filter(|value| !value.trim().is_empty())
        .and_then(|binding| env.kv(&binding).ok())
        .or_else(|| env.kv("VEILWEAVE_KV").ok())
        .or_else(|| env.kv("KV").ok())
}

fn query_token_is_valid(req: &Request, env: &Env) -> bool {
    let Some(expected) = subscription_token(env) else {
        return false;
    };
    let Ok(url) = req.url() else {
        return false;
    };
    url.query_pairs()
        .find(|(key, _)| key == "token" || key == "t")
        .is_some_and(|(_, value)| constant_time_eq(value.as_bytes(), expected.as_bytes()))
}

fn bearer_token_is_valid(req: &Request, env: &Env) -> bool {
    let Some(expected) = subscription_token(env) else {
        return false;
    };
    let Ok(Some(header)) = req.headers().get("Authorization") else {
        return false;
    };
    let Some(value) = header.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(value.as_bytes(), expected.as_bytes())
}

fn subscription_token(env: &Env) -> Option<String> {
    env.var("SUBSCRIPTION_TOKEN")
        .ok()
        .map(|value| value.to_string())
        .filter(|value| !value.trim().is_empty())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let max = left.len().max(right.len());
    for index in 0..max {
        difference |= left.get(index).copied().unwrap_or(0) as usize
            ^ right.get(index).copied().unwrap_or(0) as usize;
    }
    difference == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Raw,
    Base64,
}

impl OutputFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Base64 => "base64",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SubscriptionOptions {
    country: Option<String>,
    filter: Vec<String>,
    secure: bool,
    format: OutputFormat,
}

impl SubscriptionOptions {
    fn from_request(req: &Request) -> Result<Self, String> {
        let url = req
            .url()
            .map_err(|_| "Invalid subscription URL.".to_string())?;
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        Self::from_pairs(&pairs)
    }

    fn from_pairs(pairs: &[(String, String)]) -> Result<Self, String> {
        let value = |names: &[&str]| {
            pairs
                .iter()
                .find(|(key, _)| names.contains(&key.as_str()))
                .map(|(_, value)| value.as_str())
        };
        let country = value(&["country", "cc"])
            .map(parse_country_code)
            .transpose()?;
        let filter = match value(&["filter", "c"]) {
            Some(raw) => parse_filter(raw)?,
            None => Vec::new(),
        };
        if country.is_some() && !filter.is_empty() {
            return Err("country and filter cannot be combined.".to_string());
        }
        let secure = match value(&["secure"]) {
            None | Some("1") | Some("true") => true,
            Some("0") | Some("false") => false,
            Some(_) => return Err("secure must be true, false, 1, or 0.".to_string()),
        };
        let format = match value(&["format"]) {
            None | Some("raw") | Some("vless") => OutputFormat::Raw,
            Some("base64") => OutputFormat::Base64,
            Some(_) => return Err("format must be raw or base64.".to_string()),
        };
        Ok(Self {
            country,
            filter,
            secure,
            format,
        })
    }

    fn requested_countries(&self) -> Option<&[String]> {
        if let Some(country) = self.country.as_ref() {
            Some(std::slice::from_ref(country))
        } else if self.filter.is_empty() {
            None
        } else {
            Some(&self.filter)
        }
    }
}

fn parse_filter(raw: &str) -> Result<Vec<String>, String> {
    let mut countries = Vec::new();
    let mut seen = HashSet::new();
    for part in raw
        .split(|character: char| character == ',' || character == '+' || character.is_whitespace())
    {
        if part.is_empty() {
            continue;
        }
        let country = parse_country_code(part)?;
        if seen.insert(country.clone()) {
            countries.push(country);
        }
    }
    if countries.is_empty() {
        return Err("filter must contain at least one ISO country code.".to_string());
    }
    Ok(countries)
}

fn configured_max_nodes(env: &Env) -> Result<usize, String> {
    let raw = env
        .var("MAX_NODES")
        .ok()
        .map(|value| value.to_string())
        .unwrap_or_else(|| DEFAULT_MAX_NODES.to_string());
    let value = raw
        .parse::<usize>()
        .map_err(|_| "MAX_NODES is not a valid integer.".to_string())?;
    if !(1..=MAX_NODES_LIMIT).contains(&value) {
        return Err(format!(
            "MAX_NODES must be between 1 and {MAX_NODES_LIMIT}."
        ));
    }
    Ok(value)
}

struct RenderConfig {
    secure: bool,
    fingerprint: String,
    alpn: String,
    ech: Option<String>,
}

impl RenderConfig {
    fn from_env(env: &Env, secure: bool) -> Result<Self, String> {
        let fingerprint = env
            .var("FP")
            .ok()
            .map(|value| value.to_string())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "chrome".to_string());
        if !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err("FP contains unsupported characters.".to_string());
        }
        let alpn = env
            .var("ALPN")
            .ok()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "http/1.1".to_string());
        let ech = env
            .var("ECH")
            .ok()
            .map(|value| value.to_string())
            .filter(|value| !value.trim().is_empty());
        if let Some(ech) = &ech {
            if ech.len() > 512 || ech.chars().any(char::is_control) {
                return Err("ECH configuration is invalid.".to_string());
            }
        }
        Ok(Self {
            secure,
            fingerprint,
            alpn,
            ech,
        })
    }
}

fn build_subscription(
    relay_nodes: &[RelayNode],
    config: &RenderConfig,
    entries: &[EgressEntry],
    optimized_ip_list: &[String],
    nonce_bytes: &[u8],
) -> Result<String, String> {
    if relay_nodes.is_empty() || entries.is_empty() {
        return Err("no relay or proxyIP entries are available".to_string());
    }
    if nonce_bytes.len() != entries.len() * 4 {
        return Err("nonce byte count does not match node count".to_string());
    }

    let security = if config.secure { "tls" } else { "none" };
    let entry_port = if config.secure { 443 } else { 80 };
    let mut output = String::with_capacity(entries.len() * 256);
    let mut country_counters = HashMap::<String, usize>::new();

    for (index, proxy_entry) in entries.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        let relay = &relay_nodes[index % relay_nodes.len()];
        let octets = parse_ipv4_octets(&proxy_entry.host)
            .ok_or_else(|| "prepared proxyIP entry is not IPv4".to_string())?;
        let mut nonce = [0u8; 4];
        nonce.copy_from_slice(&nonce_bytes[index * 4..index * 4 + 4]);
        let uuid = format_uuid(
            &relay
                .codec
                .encode(TYPE_PROXYIP, octets, proxy_entry.port, &nonce),
        );

        let entry_host = if optimized_ip_list.is_empty() {
            relay.domain.as_str()
        } else {
            optimized_ip_list[index % optimized_ip_list.len()].as_str()
        };
        let path = PRNG.with(|state| path::realistic_ws_path(&mut state.borrow_mut()));
        let country = if proxy_entry.country.is_empty() {
            "XX"
        } else {
            &proxy_entry.country
        };
        let counter = country_counters.entry(country.to_string()).or_insert(0);
        *counter += 1;
        let label = format!("{}-{:02}", country, counter);

        write!(
            output,
            "vless://{}@{}:{}?encryption={}&security={}&type=ws&host={}&path={}",
            uuid,
            entry_host,
            entry_port,
            relay.enc_param,
            security,
            percent_encode(&relay.domain),
            percent_encode(&path)
        )
        .map_err(|_| "formatting subscription URI failed".to_string())?;

        if config.secure {
            write!(
                output,
                "&sni={}&fp={}",
                percent_encode(&relay.domain),
                percent_encode(&config.fingerprint)
            )
            .map_err(|_| "formatting TLS parameters failed".to_string())?;
            if !config.alpn.trim().is_empty() {
                write!(output, "&alpn={}", percent_encode(&config.alpn))
                    .map_err(|_| "formatting ALPN failed".to_string())?;
            }
            if let Some(ech) = &config.ech {
                write!(output, "&ech={}", percent_encode(ech))
                    .map_err(|_| "formatting ECH failed".to_string())?;
            }
            output.push_str("&insecure=0&allowInsecure=0");
        }
        write!(output, "#{}", percent_encode(&label))
            .map_err(|_| "formatting node label failed".to_string())?;
    }
    Ok(output)
}

fn build_subscription_response(
    raw: &str,
    format: OutputFormat,
    node_count: usize,
    revision: &str,
    stale: bool,
) -> Result<Response> {
    let body = match format {
        OutputFormat::Raw => raw.to_string(),
        OutputFormat::Base64 => general_purpose::STANDARD.encode(raw.as_bytes()),
    };
    let headers = Headers::new();
    headers.set("Content-Type", "text/plain; charset=utf-8")?;
    headers.set("Cache-Control", "private, no-store")?;
    headers.set("Profile-Update-Interval", PROFILE_UPDATE_INTERVAL_HOURS)?;
    headers.set("X-Veilweave-Format", format.as_str())?;
    headers.set("X-Node-Count", &node_count.to_string())?;
    headers.set("X-ProxyIP-Revision", revision)?;
    headers.set("X-ProxyIP-Stale", if stale { "true" } else { "false" })?;
    Ok(Response::ok(body)?.with_headers(headers))
}

fn not_found() -> Result<Response> {
    Response::error("404 Not Found", 404)
}

fn client_error(message: &str) -> Result<Response> {
    let headers = Headers::new();
    headers.set("Content-Type", "text/plain; charset=utf-8")?;
    headers.set("Cache-Control", "no-store")?;
    Ok(Response::error(message, 400)?.with_headers(headers))
}

fn unavailable(message: &str) -> Result<Response> {
    let headers = Headers::new();
    headers.set("Content-Type", "text/plain; charset=utf-8")?;
    headers.set("Cache-Control", "no-store")?;
    headers.set("Retry-After", "60")?;
    Ok(Response::error(message, 503)?.with_headers(headers))
}

fn json_response<T: Serialize>(value: &T, status: u16) -> Result<Response> {
    let body = serde_json::to_string(value)?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json; charset=utf-8")?;
    headers.set("Cache-Control", "no-store")?;
    Ok(Response::from_body(ResponseBody::Body(body.into_bytes()))?
        .with_status(status)
        .with_headers(headers))
}

fn extract_cf_header(req: &Request, header: &str) -> Option<String> {
    req.headers().get(header).ok().flatten()
}

fn now_ms() -> u64 {
    js_sys::Date::now().max(0.0) as u64
}

fn init_prng(seed: u64) {
    PRNG.with(|state| *state.borrow_mut() = Xorshift64::new(seed));
}

struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xdeadbeefc0febabe } else { seed },
        }
    }

    fn next(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn next_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            0
        } else {
            self.next() % max
        }
    }
}

fn selection_seed(
    revision: &str,
    country: Option<&str>,
    asn: Option<u32>,
    requested: Option<&[String]>,
) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in revision
        .bytes()
        .chain(country.unwrap_or("").bytes())
        .chain(asn.unwrap_or(0).to_be_bytes())
        .chain(
            requested
                .into_iter()
                .flatten()
                .flat_map(|value| value.bytes()),
        )
    {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn parse_ipv4_octets(value: &str) -> Option<[u8; 4]> {
    Some(value.parse::<std::net::Ipv4Addr>().ok()?.octets())
}

fn truncate_diagnostic(detail: &str) -> String {
    detail.chars().take(256).collect()
}

#[derive(Serialize)]
struct ProxyIpStatus<'a> {
    source: &'static str,
    validation: &'static str,
    revision: Option<&'a str>,
    last_success_ms: Option<u64>,
    age_ms: Option<u64>,
    stale: bool,
    accepted_count: Option<usize>,
    rejected_count: Option<usize>,
    stored_count: Option<usize>,
    country_count: Option<usize>,
    last_failure: Option<RefreshFailure>,
}

#[derive(Serialize)]
struct RefreshResult<'a> {
    source: &'static str,
    revision: &'a str,
    accepted_count: usize,
    rejected_count: usize,
    stored_count: usize,
    country_count: usize,
}

fn enc_param_from_pubkey(pubkey: [u8; 32]) -> String {
    format!(
        "mlkem768x25519plus.native.1rtt.{}",
        general_purpose::URL_SAFE_NO_PAD.encode(pubkey)
    )
}

struct RelayNode {
    domain: String,
    codec: UuidCodec,
    enc_param: String,
}

fn load_veilweave_nodes(env: &Env) -> Vec<RelayNode> {
    let nodes_value = env
        .var("VEILWEAVE_NODES")
        .ok()
        .map(|value| value.to_string())
        .unwrap_or_default();
    let shared_key = env
        .var("SECRET_KEY")
        .ok()
        .map(|value| value.to_string())
        .filter(|value| !value.trim().is_empty());

    nodes_value
        .split(',')
        .filter_map(|node_spec| {
            let spec = node_spec.trim();
            if spec.is_empty() {
                return None;
            }
            let (domain, key) = match spec.split_once('|') {
                Some((domain, key)) => (domain.trim(), Some(key.trim().to_string())),
                None => (spec, shared_key.clone()),
            };
            if !is_valid_hostname(domain) {
                return None;
            }
            let key = key.filter(|value| !value.is_empty())?;
            let parsed = secret::parse(&key);
            let enc_param = parsed
                .sub_public()
                .map(enc_param_from_pubkey)
                .unwrap_or_else(|| "none".to_string());
            Some(RelayNode {
                domain: domain.to_ascii_lowercase(),
                codec: UuidCodec::new(&parsed.uuid_key),
                enc_param,
            })
        })
        .collect()
}

fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 || !hostname.contains('.') {
        return false;
    }
    hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn get_optimized_ip_list(carrier: geo::Carrier, ips: &optimized_ip::OptimizedIPs) -> Vec<String> {
    use geo::Carrier::*;
    let mut list = match carrier {
        CT => ips.ct.clone(),
        CU => ips.cu.clone(),
        CMCC => ips.cmcc.clone(),
        Other => ips
            .ct
            .iter()
            .chain(&ips.cu)
            .chain(&ips.cmcc)
            .cloned()
            .collect(),
    };
    let mut seen = HashSet::new();
    list.retain(|value| seen.insert(value.clone()));
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn query_formats_filters_and_country_are_explicit() {
        let options = SubscriptionOptions::from_pairs(&pairs(&[
            ("format", "base64"),
            ("filter", "jp,US jp"),
            ("secure", "false"),
        ]))
        .unwrap();
        assert_eq!(options.format, OutputFormat::Base64);
        assert_eq!(options.filter, vec!["JP", "US"]);
        assert!(!options.secure);

        let plus = SubscriptionOptions::from_pairs(&pairs(&[("filter", "jp+US+JP")])).unwrap();
        assert_eq!(plus.filter, vec!["JP", "US"]);

        assert!(
            SubscriptionOptions::from_pairs(&pairs(&[("country", "JP"), ("filter", "US"),]))
                .is_err()
        );
        assert!(SubscriptionOptions::from_pairs(&pairs(&[("filter", "USA")])).is_err());
        assert!(SubscriptionOptions::from_pairs(&pairs(&[("format", "yaml")])).is_err());
    }

    #[test]
    fn signed_uuid_render_uses_matching_relay_and_has_no_fake_node() {
        let relays = vec![
            RelayNode {
                domain: "relay-a.example.com".into(),
                codec: UuidCodec::new(b"relay-a-secret"),
                enc_param: "none".into(),
            },
            RelayNode {
                domain: "relay-b.example.com".into(),
                codec: UuidCodec::new(b"relay-b-secret"),
                enc_param: "none".into(),
            },
        ];
        let entries = vec![
            EgressEntry {
                host: "8.8.8.8".into(),
                port: 443,
                country: "US".into(),
            },
            EgressEntry {
                host: "9.9.9.9".into(),
                port: 8443,
                country: "JP".into(),
            },
        ];
        init_prng(1);
        let raw = build_subscription(
            &relays,
            &RenderConfig {
                secure: true,
                fingerprint: "chrome".into(),
                alpn: "http/1.1".into(),
                ech: None,
            },
            &entries,
            &[],
            &[1, 2, 3, 4, 5, 6, 7, 8],
        )
        .unwrap();
        let nodes: Vec<&str> = raw.lines().collect();
        assert_eq!(nodes.len(), 2);
        assert!(nodes[0].contains("@relay-a.example.com:443"));
        assert!(nodes[1].contains("@relay-b.example.com:443"));
        assert!(!raw.contains("00000000-0000-0000-0000-000000000000"));
        assert!(!raw.contains("&ech="));
    }

    #[test]
    fn tls_ech_is_explicit_and_plain_ws_has_no_tls_parameters() {
        let relays = vec![RelayNode {
            domain: "relay.example.com".into(),
            codec: UuidCodec::new(b"relay-secret"),
            enc_param: "none".into(),
        }];
        let entries = vec![EgressEntry {
            host: "8.8.8.8".into(),
            port: 443,
            country: "US".into(),
        }];

        init_prng(1);
        let tls = build_subscription(
            &relays,
            &RenderConfig {
                secure: true,
                fingerprint: "chrome".into(),
                alpn: "http/1.1".into(),
                ech: Some("config+https://dns.example/dns-query".into()),
            },
            &entries,
            &[],
            &[1, 2, 3, 4],
        )
        .unwrap();
        assert!(tls.contains("security=tls"));
        assert!(tls.contains("&ech=config%2Bhttps%3A%2F%2Fdns.example%2Fdns-query"));

        init_prng(1);
        let plain = build_subscription(
            &relays,
            &RenderConfig {
                secure: false,
                fingerprint: "chrome".into(),
                alpn: "http/1.1".into(),
                ech: Some("ignored-in-plaintext".into()),
            },
            &entries,
            &[],
            &[1, 2, 3, 4],
        )
        .unwrap();
        assert!(plain.contains("@relay.example.com:80"));
        assert!(plain.contains("security=none"));
        assert!(!plain.contains("&sni="));
        assert!(!plain.contains("&ech="));
        assert!(!plain.contains("allowInsecure"));
    }

    #[test]
    fn base64_contract_encodes_the_complete_raw_list() {
        let raw = "vless://one\nvless://two";
        let encoded = general_purpose::STANDARD.encode(raw.as_bytes());
        assert_eq!(
            general_purpose::STANDARD.decode(encoded).unwrap(),
            raw.as_bytes()
        );
    }

    #[test]
    fn constant_time_comparison_and_hostname_validation_are_strict() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"different"));
        assert!(is_valid_hostname("relay.example.com"));
        assert!(!is_valid_hostname("https://relay.example.com"));
        assert!(!is_valid_hostname("localhost"));
    }
}
