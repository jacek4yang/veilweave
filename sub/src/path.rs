// Realistic WebSocket path generator. Produces paths that look like genuine
// application traffic (chat/live/market/collab/socket.io/graphql/signalr/mqtt…)
// with varied shapes and query params. No `ed=2048`: that is an xray early-data
// marker, not a WebSocket requirement, and the relay reads the VLESS header from
// the first frame when it's absent — so omitting it removes a fingerprint at the
// cost of one handshake RTT (zero steady-state impact).
//
// Uses the per-request Xorshift PRNG only — no extra dependencies. The returned
// path is the raw value (with `/ ? & =`); the caller percent-encodes it.

use crate::Xorshift64;
use std::fmt::Write;

#[inline]
fn between(rng: &mut Xorshift64, lo: u64, hi: u64) -> u64 {
    lo + rng.next_range(hi - lo + 1)
}

#[inline]
fn pick<'a>(rng: &mut Xorshift64, items: &[&'a str]) -> &'a str {
    items[rng.next_range(items.len() as u64) as usize]
}

fn ident(rng: &mut Xorshift64, charset: &[u8], len: usize) -> String {
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let i = rng.next_range(charset.len() as u64) as usize;
        s.push(charset[i] as char);
    }
    s
}

#[inline]
fn hex(rng: &mut Xorshift64, len: usize) -> String {
    ident(rng, b"0123456789abcdef", len)
}

#[inline]
fn alnum(rng: &mut Xorshift64, len: usize) -> String {
    ident(rng, b"abcdefghijklmnopqrstuvwxyz0123456789", len)
}

const RESOURCES: &[&str] = &[
    "chat",
    "messages",
    "notifications",
    "presence",
    "inbox",
    "threads",
    "market",
    "trades",
    "tickers",
    "orders",
    "candles",
    "positions",
    "video",
    "audio",
    "stream",
    "broadcast",
    "media",
    "playback",
    "game",
    "match",
    "lobby",
    "room",
    "session",
    "leaderboard",
    "device",
    "sensor",
    "telemetry",
    "tracker",
    "monitor",
    "document",
    "editor",
    "whiteboard",
    "cursor",
    "comment",
    "user",
    "status",
    "activity",
    "feed",
    "events",
    "data",
    "metrics",
    "location",
    "delivery",
    "fleet",
    "channel",
    "topic",
    "queue",
];

const ACTIONS: &[&str] = &[
    "stream",
    "live",
    "realtime",
    "feed",
    "events",
    "sync",
    "push",
    "subscribe",
    "broadcast",
    "connect",
    "channel",
    "updates",
    "delta",
];

/// Build one realistic WS path. Variety is chosen per call from the PRNG.
pub fn realistic_ws_path(rng: &mut Xorshift64) -> String {
    let resource = pick(rng, RESOURCES);

    // Pick a path shape. Some shapes carry their own canonical query params.
    let (mut path, mut params): (String, Vec<String>) = match rng.next_range(10) {
        0 => {
            // socket.io
            let mut q = vec![
                format!("EIO={}", between(rng, 3, 4)),
                "transport=websocket".to_string(),
            ];
            if rng.next_range(10) < 7 {
                q.push(format!("sid={}", hex(rng, 20)));
            }
            ("/socket.io/".to_string(), q)
        }
        1 => {
            // signalr
            (
                format!("/hubs/{}", resource),
                vec![format!("id={}", hex(rng, 32))],
            )
        }
        2 => ("/graphql".to_string(), Vec::new()),
        3 => ("/subscriptions".to_string(), Vec::new()),
        4 => ("/mqtt".to_string(), Vec::new()),
        5 => {
            let action = pick(rng, ACTIONS);
            (format!("/ws/{}/{}", resource, action), Vec::new())
        }
        6 => (
            format!(
                "/api/v{}/{}/{}",
                between(rng, 1, 4),
                resource,
                pick(rng, ACTIONS)
            ),
            Vec::new(),
        ),
        7 => {
            let action = pick(rng, ACTIONS);
            let id_len = between(rng, 8, 14) as usize;
            (
                format!("/{}/{}/{}", resource, action, alnum(rng, id_len)),
                Vec::new(),
            )
        }
        8 => (format!("/realtime/{}", resource), Vec::new()),
        _ => (format!("/{}/{}", pick(rng, ACTIONS), resource), Vec::new()),
    };

    // Add a few generic, realistic query params (skip for protocols that already
    // carry their own canonical set: socket.io / signalr).
    if params.is_empty() || (path != "/socket.io/" && !path.starts_with("/hubs/")) {
        let extra = between(rng, 0, 3);
        for _ in 0..extra {
            params.push(match rng.next_range(8) {
                0 => {
                    let n = between(rng, 24, 40) as usize;
                    format!("token={}", hex(rng, n))
                }
                1 => format!("session={}", hex(rng, 32)),
                2 => format!("client_id={}", hex(rng, 16)),
                3 => format!("v={}", between(rng, 1, 5)),
                4 => format!("format={}", pick(rng, &["json", "msgpack", "protobuf"])),
                5 => format!("compress={}", pick(rng, &["zstd", "gzip", "none"])),
                6 => format!("heartbeat={}", pick(rng, &["30", "60", "120"])),
                _ => format!("ts={}", between(rng, 1_700_000_000, 1_799_999_999)),
            });
        }
    }

    if !params.is_empty() {
        path.push('?');
        for (i, p) in params.iter().enumerate() {
            if i > 0 {
                path.push('&');
            }
            let _ = path.write_str(p);
        }
    }

    path
}
