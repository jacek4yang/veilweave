use serde::Deserialize;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use worker::*;

mod apache_mock;
mod codec;
mod egress;
mod encoding;
mod geo;
mod hmac;
mod ip_selector;
mod optimized_ip;
mod path;
mod secret;
mod sha256;

use codec::{UuidCodec, TYPE_PROXYIP};
use egress::{parse_egress_list, EgressEntry};
use encoding::{format_uuid, percent_encode};
use optimized_ip::fetch_optimized_ips;

use crate::apache_mock::apache_default_page;

const MAX_NODES: usize = 100;
const PROXYIP_API_URL: &str = "https://zip.cm.edu.kg/all.json";
const PROXYIP_CACHE_KEY: &str = "proxyip_cache_v1";
const PROXYIP_CACHE_DATE_KEY: &str = "proxyip_cache_date_v1";
const CACHE_TTL_SECONDS: u64 = 86400; // 24 hours for IP data
const SUB_CACHE_TTL_SECONDS: u64 = 3600; // 1 hour for rendered subscription

// Per-request PRNG: nonce bytes, path variety, and shuffling.
thread_local! {
    static PRNG: RefCell<Xorshift64> = RefCell::new(Xorshift64::new(0xdeadbeefc0febabe));
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let path = url.path();

    match path {
        "/sub" => handle_sub_request(&req, &env).await,
        _ => apache_default_page(req),
    }
}

async fn handle_sub_request(req: &Request, env: &Env) -> Result<Response> {
    // Only GET requests
    if req.method() != Method::Get {
        return not_found();
    }

    let url = req.url()?;
    let query = url.query().unwrap_or("");

    // Validate token from query params
    let token = extract_param(query, "token").or_else(|| extract_param(query, "t"));
    let expected_token = env.var("SUBSCRIPTION_TOKEN").ok().map(|v| v.to_string());

    if let Some(expected) = &expected_token {
        if !expected.trim().is_empty() {
            match token {
                Some(t) if t == *expected => {}
                _ => return not_found(),
            }
        }
    }

    // Extract optional filters
    let filter = extract_param(query, "filter").or_else(|| extract_param(query, "c"));
    let req_country = extract_param(query, "country").or_else(|| extract_param(query, "cc"));

    // Initialize PRNG for this request
    init_prng();

    // Get KV for caching
    let kv = env.kv("VEILWEAVE_KV").or_else(|_| env.kv("KV")).ok();

    // Detect user geography (Cloudflare native)
    let user_country = extract_cf_header(req, "CF-IPCountry").unwrap_or_else(|| "XX".to_string());
    let user_asn = extract_cf_header(req, "CF-ASN").and_then(|asn| asn.parse::<u32>().ok());
    let user_geo = geo::detect_user_geo(&user_country, user_asn);

    // ISP-aware cache: users on the same country+carrier share a rendered body.
    let cache_key = build_geo_cache_key(
        &user_country,
        user_asn,
        filter.as_deref(),
        req_country.as_deref(),
    );
    if let Some(kv_ref) = kv.as_ref() {
        if let Ok(Some(cached)) = kv_ref.get(&cache_key).text().await {
            return build_response(&cached, true).await;
        }
    }

    // Fetch IP list
    let mut entries = match fetch_proxyip_list(kv.as_ref(), env).await {
        Ok(e) => e,
        Err(_) => return server_error(),
    };

    // Apply country filter (only controls proxyip exit country)
    if let Some(ref f) = filter {
        let countries: Vec<String> = f
            .split([',', ' ', '+'])
            .map(|s| s.trim().to_uppercase())
            .filter(|s| !s.is_empty())
            .collect();
        entries.retain(|e| countries.contains(&e.country));
    }

    // Dedup by host:port
    let mut seen: HashSet<u64> = HashSet::with_capacity(entries.len());
    entries.retain(|e| seen.insert(dedup_key(&e.host, e.port)));

    // Pre-validate entries
    entries.retain(|e| is_valid_egress(&e.host, e.port));

    // ISP-aware IP selection for domestic users
    let max_nodes = env
        .var("MAX_NODES")
        .ok()
        .and_then(|v| v.to_string().parse::<usize>().ok())
        .unwrap_or(MAX_NODES);
    entries = ip_selector::select_best_ips(&user_geo, &entries, max_nodes);

    // Shuffle within country groups for distribution
    if !entries.is_empty() {
        shuffle_within_groups(&mut entries);
    }

    // Load veilweave relay nodes (for load balancing & HA)
    let veilweave_nodes = load_veilweave_nodes(env);
    if veilweave_nodes.is_empty() {
        return server_error();
    }

    let secure = extract_param(query, "secure")
        .map(|s| s == "1" || s == "true")
        .unwrap_or(true);

    // Fetch carrier-optimized entry IPs (优选IP); empty on failure → domain fallback.
    let optimized_ips = fetch_optimized_ips(kv.as_ref()).await.unwrap_or_default();

    let body = build_subscription(
        env,
        &veilweave_nodes,
        secure,
        filter.as_deref(),
        req_country.as_deref(),
        &entries,
        &user_geo,
        &optimized_ips,
    )
    .await;

    // Cache the result
    if let Some(kv_ref) = kv.as_ref() {
        if let Ok(put) = kv_ref.put(&cache_key, &body) {
            let _ = put.expiration_ttl(SUB_CACHE_TTL_SECONDS).execute().await;
        }
    }

    build_response(&body, false).await
}

async fn fetch_proxyip_list(kv: Option<&KvStore>, env: &Env) -> Result<Vec<EgressEntry>> {
    // Check cache first
    if let Some(kv_ref) = kv {
        if let Ok(Some(cached)) = kv_ref.get(PROXYIP_CACHE_KEY).text().await {
            if let Ok(Some(date_str)) = kv_ref.get(PROXYIP_CACHE_DATE_KEY).text().await {
                let today = today_ymd();
                if date_str == today {
                    return Ok(parse_cached_proxyip(&cached));
                }
            }
        }
    }

    // Cache miss or expired: fetch from API
    let builtin_disabled = env
        .var("DISABLE_BUILTIN_PROXYIP")
        .map(|v| v.to_string() == "true")
        .unwrap_or(false);

    let mut entries = Vec::new();

    if !builtin_disabled {
        let mut resp = Fetch::Request(Request::new(PROXYIP_API_URL, Method::Get)?)
            .send()
            .await?;

        if resp.status_code() == 200 {
            let json_text = resp.text().await?;
            if let Ok(parsed) = serde_json::from_str::<ProxyipApiResponse>(&json_text) {
                for item in parsed.data {
                    let port = item.port.first().copied().unwrap_or(item.meta.port);
                    let country = normalize_country(&item.meta.country);
                    entries.push(EgressEntry {
                        host: item.ip,
                        port,
                        country,
                    });
                }
            }
        }
    }

    // Also load from inline env vars if present
    if let Ok(list) = env.var("PROXYIP_LIST") {
        entries.extend(parse_egress_list(&list.to_string()));
    }

    // Cache the result
    if let Some(kv_ref) = kv {
        let cache_text = serialize_proxyip_cache(&entries);
        let today = today_ymd();
        if let Ok(put) = kv_ref.put(PROXYIP_CACHE_KEY, &cache_text) {
            let _ = put.expiration_ttl(CACHE_TTL_SECONDS).execute().await;
        }
        if let Ok(put) = kv_ref.put(PROXYIP_CACHE_DATE_KEY, &today) {
            let _ = put.expiration_ttl(CACHE_TTL_SECONDS).execute().await;
        }
    }

    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
async fn build_subscription(
    env: &Env,
    relay_nodes: &[RelayNode],
    secure: bool,
    filter: Option<&str>,
    _req_country: Option<&str>,
    entries: &[EgressEntry],
    user_geo: &geo::UserGeo,
    optimized_ips: &optimized_ip::OptimizedIPs,
) -> String {
    let security = if secure { "tls" } else { "none" };

    // VLESS Encryption (`mlkem768x25519plus`) is carried per node in the combined
    // VEILWEAVE_NODES secret: when a node's blob holds an X25519 public key, its
    // links advertise post-quantum, forward-secret in-stream encryption end-to-end
    // (client ⇄ worker), so even Cloudflare — which terminates the outer TLS —
    // cannot read the tunnelled traffic. Nodes without a key emit `encryption=none`.

    let fp = env
        .var("FP")
        .map(|v| v.to_string())
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "chrome".to_string());

    // ALPN suffix — default to http/1.1 (matches veilweave-tools). Empty disables.
    let alpn = env
        .var("ALPN")
        .map(|v| v.to_string())
        .ok()
        .unwrap_or_else(|| "http/1.1".to_string());
    let mut alpn_suffix = String::new();
    if secure && !alpn.trim().is_empty() {
        let _ = write!(alpn_suffix, "&alpn={}", percent_encode(&alpn));
    }

    // ECH suffix — default matches veilweave-tools. Set ECH="" to disable.
    let ech = env
        .var("ECH")
        .map(|v| v.to_string())
        .ok()
        .unwrap_or_else(|| "cloudflare-ech.com+https://dns.alidns.com/dns-query".to_string());
    let mut ech_suffix = String::new();
    if secure && !ech.trim().is_empty() {
        let _ = write!(ech_suffix, "&ech={}", percent_encode(&ech));
    }

    // Optimized entry IPs for this carrier (rotated across nodes for availability).
    let optimized_ip_list = get_optimized_ip_list(user_geo.carrier, optimized_ips);

    let cap = entries.len().min(MAX_NODES);
    if cap == 0 || relay_nodes.is_empty() {
        let fallback_host = relay_nodes
            .first()
            .map(|n| n.domain.as_str())
            .unwrap_or("veilweave.example.com");
        let fallback_enc = relay_nodes
            .first()
            .map(|n| n.enc_param.as_str())
            .unwrap_or("none");
        return format!(
            "vless://00000000-0000-0000-0000-000000000000@{}:443?encryption={}&security={}&type=ws&host={}#{}",
            percent_encode(fallback_host),
            fallback_enc,
            security,
            percent_encode(fallback_host),
            percent_encode(&format!(
                "No nodes available{}",
                filter.map(|f| format!(" (filter: {})", f)).unwrap_or_default()
            ))
        );
    }

    let entry_port: u16 = if secure { 443 } else { 80 };

    let mut out = String::with_capacity(cap * 256);
    let mut country_counters: HashMap<String, usize> = HashMap::new();

    for (idx, proxy_entry) in entries[..cap].iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }

        // Round-robin the relay node; its codec signs this node's UUID.
        let relay = &relay_nodes[idx % relay_nodes.len()];

        // Egress baked into the UUID: an IPv4 proxyip if parseable, else direct.
        let (type_byte, octets, egress_port) = match try_parse_ipv4_octets(&proxy_entry.host) {
            Some(o) => (TYPE_PROXYIP, o, proxy_entry.port),
            None => (codec::TYPE_DIRECT, [0u8, 0, 0, 0], 0u16),
        };
        let nonce = next_nonce();
        let uuid_bytes = relay.codec.encode(type_byte, octets, egress_port, &nonce);
        let uuid = format_uuid(&uuid_bytes);

        // Entry connection address: a carrier-optimized CF IP, else the relay
        // domain itself (always routable). host/SNI are always the relay domain so
        // Cloudflare routes to the right worker.
        let entry_host = if optimized_ip_list.is_empty() {
            relay.domain.as_str()
        } else {
            optimized_ip_list[idx % optimized_ip_list.len()].as_str()
        };

        let path = PRNG.with(|p| path::realistic_ws_path(&mut p.borrow_mut()));
        // Name reflects the proxyip's location — that is what `filter` selects on,
        // so the user sees the egress country of each node.
        let cc = if proxy_entry.country.is_empty() {
            "XX"
        } else {
            &proxy_entry.country
        };
        let counter = country_counters.entry(cc.to_string()).or_insert(0);
        *counter += 1;
        let label = format!("{}-{:02}", cc, counter);

        let _ = write!(
            out,
            "vless://{}@{}:{}?encryption={}&security={}&type=ws&host={}&path={}",
            uuid,
            entry_host,
            entry_port,
            relay.enc_param,
            security,
            percent_encode(&relay.domain),
            percent_encode(&path)
        );

        if secure {
            let _ = write!(out, "&sni={}&fp={}", percent_encode(&relay.domain), fp);
            out.push_str(&alpn_suffix);
            out.push_str(&ech_suffix);
            out.push_str("&insecure=0&allowInsecure=0");
        }

        let _ = write!(out, "#{}", percent_encode(&label));
    }

    out
}

async fn build_response(body: &str, cached: bool) -> Result<Response> {
    let headers = Headers::new();
    headers.set("Content-Type", "text/plain; charset=utf-8")?;
    headers.set("Profile-Update-Interval", "6")?;
    let node_count = body.lines().filter(|l| !l.is_empty()).count();
    headers.set("X-Node-Count", &node_count.to_string())?;
    headers.set("X-Cache", if cached { "HIT" } else { "MISS" })?;

    Ok(Response::ok(body)?.with_headers(headers))
}

fn not_found() -> Result<Response> {
    Response::error("404 Not Found", 404)
}

fn server_error() -> Result<Response> {
    Response::error("500 Server Error", 500)
}

fn extract_param(query: &str, key: &str) -> Option<String> {
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return url_decode(v);
            }
        }
    }
    None
}

fn extract_cf_header(req: &Request, header: &str) -> Option<String> {
    req.headers()
        .get(header)
        .ok()
        .flatten()
        .map(|v| v.to_string())
}

fn url_decode(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(hex) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(hex as char);
                    i += 3;
                    continue;
                }
                return None;
            }
            b'+' => {
                out.push(' ');
                i += 1;
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    Some(out)
}

fn build_geo_cache_key(
    user_country: &str,
    user_asn: Option<u32>,
    filter: Option<&str>,
    req_country: Option<&str>,
) -> String {
    let mut h = 0u64;

    // Include user country in cache key
    for b in user_country.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as u64);
    }

    // Include user ASN (ISP) in cache key for better locality
    if let Some(asn) = user_asn {
        h ^= 0x9e3779b97f4a7c17;
        h = h.wrapping_mul(31).wrapping_add(asn as u64);
    }

    // Include filters
    if let Some(f) = filter {
        h ^= 0x9e3779b97f4a7c18;
        for b in f.bytes() {
            h = h.wrapping_mul(31).wrapping_add(b as u64);
        }
    }

    if let Some(c) = req_country {
        h ^= 0x9e3779b97f4a7c19;
        for b in c.bytes() {
            h = h.wrapping_mul(31).wrapping_add(b as u64);
        }
    }

    format!("sub_geo2:{:016x}:{}", h, today_ymd())
}

fn today_ymd() -> String {
    let now = js_sys::Date::new_0();
    format!(
        "{:04}-{:02}-{:02}",
        now.get_utc_full_year(),
        now.get_utc_month() + 1,
        now.get_utc_date()
    )
}

fn init_prng() {
    let seed = js_sys::Date::now() as u64;
    PRNG.with(|p| *p.borrow_mut() = Xorshift64::new(seed));
}

#[allow(dead_code)]
fn fast_random(max: u32) -> u32 {
    if max == 0 {
        return 0;
    }
    PRNG.with(|p| p.borrow_mut().next_range(max as u64) as u32)
}

/// Four fresh nonce bytes for UUID encoding, drawn from the per-request PRNG.
fn next_nonce() -> [u8; 4] {
    let r = PRNG.with(|p| p.borrow_mut().next());
    [(r >> 24) as u8, (r >> 16) as u8, (r >> 8) as u8, r as u8]
}

struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        let mut s = seed;
        if s == 0 {
            s = 0xdeadbeefc0febabe;
        }
        Self { state: s }
    }
    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
    fn next_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        self.next() % max
    }
}

fn dedup_key(host: &str, port: u16) -> u64 {
    if let Some(ip) = try_parse_ipv4_u32(host) {
        return ((ip as u64) << 16) | (port as u64);
    }
    fnv1a_hash(host, port)
}

fn try_parse_ipv4_u32(s: &str) -> Option<u32> {
    try_parse_ipv4_octets(s).map(u32::from_be_bytes)
}

fn try_parse_ipv4_octets(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut idx = 0usize;
    let mut current = 0u16;
    for b in s.bytes() {
        match b {
            b'0'..=b'9' => {
                current = current.checked_mul(10)?.checked_add((b - b'0') as u16)?;
                if current > 255 {
                    return None;
                }
            }
            b'.' => {
                if idx >= 3 {
                    return None;
                }
                octets[idx] = current as u8;
                idx += 1;
                current = 0;
            }
            _ => return None,
        }
    }
    if idx != 3 || current > 255 {
        return None;
    }
    octets[3] = current as u8;
    Some(octets)
}

fn fnv1a_hash(host: &str, port: u16) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in host.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= (port >> 8) as u64;
    h = h.wrapping_mul(0x100000001b3);
    h ^= (port & 0xff) as u64;
    h = h.wrapping_mul(0x100000001b3);
    h
}

fn is_valid_egress(host: &str, port: u16) -> bool {
    // Only CF TLS ports
    if !matches!(port, 443 | 2053 | 2083 | 2087 | 2096 | 8443) {
        return false;
    }

    // IPv6: accept anything except loopback
    if host.starts_with('[') {
        return true;
    }

    // IPv4: reject private/reserved ranges
    match try_parse_ipv4_octets(host) {
        Some([a, b, c, _]) => {
            // Reserved/private ranges
            !(a == 0
                || a == 10
                || a == 127
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || (a == 198 && (b == 18 || b == 19))
                || a >= 224)
        }
        None => true, // Treat as domain name
    }
}

fn shuffle_within_groups(entries: &mut [EgressEntry]) {
    if entries.is_empty() {
        return;
    }
    let mut rng = Xorshift64::new(PRNG.with(|p| p.borrow_mut().next()));

    let mut start = 0;
    for i in 1..=entries.len() {
        if i == entries.len() || entries[i].country != entries[start].country {
            for j in (start + 1..i).rev() {
                let k = rng.next_range((j - start + 1) as u64) as usize + start;
                entries.swap(j, k);
            }
            start = i;
        }
    }
}

fn split_host_port(host_port: &str, default_port: u16) -> (String, u16) {
    if host_port.starts_with('[') {
        if let Some(bracket) = host_port.rfind(']') {
            let host = host_port[..=bracket].to_string();
            let rest = &host_port[bracket + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return (host, port);
                }
            }
            return (host, default_port);
        }
    }

    if let Some(colon) = host_port.rfind(':') {
        let (host, port_str) = host_port.split_at(colon);
        if let Ok(port) = port_str[1..].parse::<u16>() {
            return (host.to_string(), port);
        }
    }

    (host_port.to_string(), default_port)
}

fn parse_cached_proxyip(text: &str) -> Vec<EgressEntry> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let mut parts = line.splitn(2, '#');
            let hostport = parts.next()?;
            let country = parts.next().unwrap_or("").to_uppercase();
            let (host, port) = split_host_port(hostport, 443);
            Some(EgressEntry {
                host,
                port,
                country,
            })
        })
        .collect()
}

fn serialize_proxyip_cache(entries: &[EgressEntry]) -> String {
    let mut out = String::with_capacity(entries.len() * 40);
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let _ = write!(out, "{}:{}#{}", e.host, e.port, e.country);
    }
    out
}

#[derive(Deserialize)]
struct ProxyipApiResponse {
    #[serde(rename = "data")]
    data: Vec<ProxyipEntry>,
}

#[derive(Deserialize)]
struct ProxyipEntry {
    #[serde(rename = "ip")]
    ip: String,
    #[serde(rename = "port")]
    port: Vec<u16>,
    #[serde(rename = "meta")]
    meta: ProxyipMeta,
}

#[derive(Deserialize)]
struct ProxyipMeta {
    #[serde(rename = "country")]
    country: String,
    #[serde(rename = "_port")]
    port: u16,
}

fn normalize_country(raw: &str) -> String {
    let raw = raw.trim().to_uppercase();
    match raw.as_str() {
        "UK" | "UNITED KINGDOM" => "GB".to_string(),
        "UNITED STATES" | "USA" => "US".to_string(),
        "GERMANY" => "DE".to_string(),
        "JAPAN" => "JP".to_string(),
        "HONG KONG" => "HK".to_string(),
        "SINGAPORE" => "SG".to_string(),
        "NETHERLANDS" => "NL".to_string(),
        "FRANCE" => "FR".to_string(),
        "SOUTH KOREA" => "KR".to_string(),
        "TAIWAN" => "TW".to_string(),
        "AUSTRALIA" => "AU".to_string(),
        "CANADA" => "CA".to_string(),
        "BRAZIL" => "BR".to_string(),
        "INDIA" => "IN".to_string(),
        _ => {
            if raw.len() == 2 && raw.chars().all(|c| c.is_ascii_alphabetic()) {
                raw
            } else {
                "XX".to_string()
            }
        }
    }
}

/// Entry IPs for this carrier (deduped, order preserved). Unknown/foreign carriers
/// get the union of all lists so they still receive working entry IPs.
fn get_optimized_ip_list(carrier: geo::Carrier, ips: &optimized_ip::OptimizedIPs) -> Vec<String> {
    use geo::Carrier::*;
    let mut list = match carrier {
        CT => ips.ct.clone(),
        CU => ips.cu.clone(),
        CMCC => ips.cmcc.clone(),
        Other => {
            let mut all = Vec::with_capacity(ips.ct.len() + ips.cu.len() + ips.cmcc.len());
            all.extend(ips.ct.iter().cloned());
            all.extend(ips.cu.iter().cloned());
            all.extend(ips.cmcc.iter().cloned());
            all
        }
    };

    let mut seen = HashSet::new();
    list.retain(|ip| seen.insert(ip.clone()));
    list
}

/// The VLESS `encryption` value for a node's X25519 public key: the single best
/// profile (native + 1rtt + hybrid ML-KEM-768/X25519). Matches `veilweave-tools`.
fn enc_param_from_pubkey(pubkey: [u8; 32]) -> String {
    use base64::{engine::general_purpose, Engine as _};
    format!(
        "mlkem768x25519plus.native.1rtt.{}",
        general_purpose::URL_SAFE_NO_PAD.encode(pubkey)
    )
}

/// A veilweave relay node: the domain Cloudflare routes on (host/SNI), the per-node
/// UUID codec built from that node's secret, and the VLESS `encryption` value to
/// advertise (derived from the same secret's X25519 public key, or `none`).
struct RelayNode {
    domain: String,
    codec: UuidCodec,
    enc_param: String,
}

/// Parse `VEILWEAVE_NODES` into relay nodes. Format per node:
///   `domain|secret`  (preferred — explicit per-node combined secret)
///   `domain`         (falls back to the shared `SECRET_KEY` env var)
/// The secret is a `veilweave-tools gen-secret` sub blob (UUID secret + X25519
/// public key) or a legacy raw secret (encryption off). Nodes are comma-separated;
/// nodes without any resolvable secret are skipped.
fn load_veilweave_nodes(env: &Env) -> Vec<RelayNode> {
    let nodes_str = env
        .var("VEILWEAVE_NODES")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default();

    let shared_key = env
        .var("SECRET_KEY")
        .ok()
        .map(|v| v.to_string())
        .filter(|s| !s.trim().is_empty());

    let mut nodes = Vec::new();
    for node_spec in nodes_str.split(',') {
        let spec = node_spec.trim();
        if spec.is_empty() {
            continue;
        }

        // Split off an optional per-node secret after '|'. The domain never
        // contains '|', so this is unambiguous.
        let (domain, key) = match spec.split_once('|') {
            Some((d, k)) => (d.trim().to_string(), Some(k.trim().to_string())),
            None => (spec.to_string(), shared_key.clone()),
        };

        let key = match key {
            Some(k) if !k.is_empty() => k,
            _ => continue, // no key for this node → cannot sign UUIDs → skip
        };

        // The combined blob yields the UUID codec key and (for sub blobs) the
        // X25519 public key to publish; a legacy raw secret keeps encryption off.
        let parsed = secret::parse(&key);
        let enc_param = parsed
            .sub_public()
            .map(enc_param_from_pubkey)
            .unwrap_or_else(|| "none".to_string());

        nodes.push(RelayNode {
            domain,
            codec: UuidCodec::new(&parsed.uuid_key),
            enc_param,
        });
    }

    nodes
}
