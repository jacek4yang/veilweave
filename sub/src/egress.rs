// A proxyip egress candidate: the IPv4 (or host) + port the relay will dial, plus
// its country for ISP-aware ranking. This subscription deals only in proxyips
// (the egress baked into each signed UUID), so the model is deliberately minimal.

#[derive(Clone, Debug)]
pub struct EgressEntry {
    pub host: String,
    pub port: u16,
    pub country: String,
}

/// Parse a comma-separated inline list. Each item is `host:port#country` (any
/// trailing `#remark` is ignored). Missing port defaults to 443 (Cloudflare TLS).
pub fn parse_egress_list(list_str: &str) -> Vec<EgressEntry> {
    let mut entries = Vec::new();
    for raw in list_str.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let mut parts = raw.splitn(3, '#');
        let hostport = parts.next().unwrap_or("").trim();
        let country = parts.next().map(|s| s.trim().to_uppercase()).unwrap_or_default();
        if hostport.is_empty() {
            continue;
        }

        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
            None => (hostport.to_string(), 443),
        };

        entries.push(EgressEntry { host, port, country });
    }
    entries
}
