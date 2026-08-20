// Carrier-optimized entry IPs (优选IP). These are the CF edge addresses the client
// dials; they are chosen per the user's carrier so the first hop is fast inside
// China. Two sources are merged (deduped, quality-sorted source first):
//   1. api.uouin.com/cloudflare.html — server-rendered table, ~10 IPs/carrier,
//      sorted by latency/speed; scraped by carrier label → next IPv4.
//   2. cf.090227.xyz/{ct,cu,cmcc}    — one `IP#label` per line, ~4 IPs/carrier.
//
// A Cloudflare Worker `fetch()` reaches CF-hosted endpoints fine (it goes through
// the HTTP stack, not a raw socket), so no proxyip indirection is needed here.

use serde::{Deserialize, Serialize};
use worker::*;

const OPTIMIZED_IP_CACHE_KEY: &str = "optimized_ips_v4";
const OPTIMIZED_IP_CACHE_TTL: u64 = 86400; // 24 hours
const UOUIN_URL: &str = "https://api.uouin.com/cloudflare.html";
const ENDPOINTS: [(&str, &str); 3] = [
    ("ct", "https://cf.090227.xyz/ct"),
    ("cu", "https://cf.090227.xyz/cu"),
    ("cmcc", "https://cf.090227.xyz/cmcc"),
];
// Carrier labels as they appear in the uouin table (电信 / 联通 / 移动).
const UOUIN_MARKERS: [(&str, &str); 3] = [("ct", "电信"), ("cu", "联通"), ("cmcc", "移动")];
const MAX_PER_CARRIER: usize = 30;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OptimizedIPs {
    pub ct: Vec<String>,
    pub cu: Vec<String>,
    pub cmcc: Vec<String>,
}

impl OptimizedIPs {
    fn is_empty(&self) -> bool {
        self.ct.is_empty() && self.cu.is_empty() && self.cmcc.is_empty()
    }
}

/// Fetch the carrier entry-IP lists, cached 24h in KV.
pub async fn fetch_optimized_ips(kv: Option<&KvStore>) -> Result<OptimizedIPs, String> {
    if let Some(kv_ref) = kv {
        if let Ok(Some(cached)) = kv_ref.get(OPTIMIZED_IP_CACHE_KEY).text().await {
            if let Ok(parsed) = serde_json::from_str::<OptimizedIPs>(&cached) {
                if !parsed.is_empty() {
                    return Ok(parsed);
                }
            }
        }
    }

    let mut result = OptimizedIPs::default();

    // Source 1 (richer, latency-sorted): uouin HTML table.
    if let Ok(body) = fetch_text(UOUIN_URL).await {
        for (carrier, marker) in UOUIN_MARKERS {
            let ips = scrape_uouin(&body, marker);
            list_for(&mut result, carrier).extend(ips);
        }
    }

    // Source 2: cf.090227.xyz plaintext lists, appended after.
    for (carrier, url) in ENDPOINTS {
        if let Ok(body) = fetch_text(url).await {
            let ips = parse_ip_list(&body);
            list_for(&mut result, carrier).extend(ips);
        }
    }

    for list in [&mut result.ct, &mut result.cu, &mut result.cmcc] {
        dedup_keep_order(list);
        list.truncate(MAX_PER_CARRIER);
    }

    if result.is_empty() {
        return Err("optimized IP fetch returned nothing".to_string());
    }

    if let Some(kv_ref) = kv {
        if let Ok(serialized) = serde_json::to_string(&result) {
            if let Ok(put) = kv_ref.put(OPTIMIZED_IP_CACHE_KEY, &serialized) {
                let _ = put.expiration_ttl(OPTIMIZED_IP_CACHE_TTL).execute().await;
            }
        }
    }
    Ok(result)
}

fn list_for<'a>(ips: &'a mut OptimizedIPs, carrier: &str) -> &'a mut Vec<String> {
    match carrier {
        "ct" => &mut ips.ct,
        "cu" => &mut ips.cu,
        _ => &mut ips.cmcc,
    }
}

fn dedup_keep_order(list: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    list.retain(|ip| seen.insert(ip.clone()));
}

async fn fetch_text(url: &str) -> Result<String, String> {
    let mut resp =
        Fetch::Request(Request::new(url, Method::Get).map_err(|_| "bad request".to_string())?)
            .send()
            .await
            .map_err(|_| "fetch failed".to_string())?;
    if resp.status_code() != 200 {
        return Err(format!("status {}", resp.status_code()));
    }
    resp.text().await.map_err(|_| "read failed".to_string())
}

/// Scrape the uouin table: for each carrier label occurrence, take the first IPv4
/// that appears shortly after it (the adjacent `优选IP` cell). Text mentions of the
/// label (title/promo) have no IP nearby and are skipped.
fn scrape_uouin(html: &str, marker: &str) -> Vec<String> {
    const WINDOW: usize = 200;
    let bytes = html.as_bytes();
    let mark = marker.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + mark.len() <= bytes.len() {
        if &bytes[i..i + mark.len()] == mark {
            let start = i + mark.len();
            let end = (start + WINDOW).min(bytes.len());
            if let Some(ip) = first_ipv4(&html[start..end]) {
                out.push(ip);
            }
            i = start;
        } else {
            i += 1;
        }
    }
    out
}

/// Find the first IPv4 substring in `s`.
fn first_ipv4(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let mut j = i;
            while j < b.len() && (b[j].is_ascii_digit() || b[j] == b'.') && j - i < 16 {
                j += 1;
            }
            let cand = &s[i..j];
            if is_ipv4(cand) {
                return Some(cand.to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

/// Parse `IP#label` (or `IP:port#label`, or bare `IP`) lines into bare IPv4 strings.
/// The label after `#` and any `:port` are dropped — the entry port is fixed at 443.
fn parse_ip_list(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let token = line.trim().split('#').next().unwrap_or("").trim();
        if token.is_empty() {
            continue;
        }
        // Strip an optional :port (these IPs are dialed on 443).
        let ip = token.split(':').next().unwrap_or("").trim();
        if is_ipv4(ip) {
            out.push(ip.to_string());
        }
    }
    out
}

fn is_ipv4(s: &str) -> bool {
    let mut parts = 0;
    for p in s.split('.') {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if p.parse::<u8>().is_err() {
            return false;
        }
        parts += 1;
    }
    parts == 4
}
