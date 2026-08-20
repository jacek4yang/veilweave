// vless.rs
// VLESS wire-format parsing for the decrypted inner stream. After the VLESS
// Encryption handshake (`enc.rs`) the `VeilweaveSession` DO hands the decrypted
// header bytes here; this module authenticates the signed UUID (which also carries
// the egress) and decodes the request (command + target). It holds no I/O — the DO
// owns the sockets and the record framing.

use std::cell::{OnceCell, RefCell};

use worker::*;

use crate::codec::{Payload, Uuid, UuidCodec};
use crate::egress::{Egress, ProxyAuth};

const VLESS_VERSION: u8 = 0;
pub(crate) const VLESS_RESPONSE: [u8; 2] = [VLESS_VERSION, 0x00];

#[inline(always)]
fn fb() -> Error {
    Error::RustError(String::new())
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum AddrType {
    IPv4 = 0x01,
    Domain = 0x02,
    IPv6 = 0x03,
}

impl TryFrom<u8> for AddrType {
    type Error = Error;
    #[inline(always)]
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(AddrType::IPv4),
            0x02 => Ok(AddrType::Domain),
            0x03 => Ok(AddrType::IPv6),
            _ => Err(fb()),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Command {
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = Error;
    #[inline(always)]
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Command::Tcp),
            0x02 => Ok(Command::Udp),
            0x03 => Ok(Command::Mux),
            _ => Err(fb()),
        }
    }
}

pub(crate) struct VlessRequest {
    pub(crate) command: Command,
    pub(crate) host: String,
    pub(crate) port: u16,
}

#[inline(always)]
fn push_u8_dec(s: &mut String, mut n: u8) {
    let mut buf = [0u8; 3];
    let mut i = 0;
    if n >= 100 {
        buf[i] = b'0' + n / 100;
        i += 1;
        n %= 100;
    }
    if n >= 10 || i > 0 {
        buf[i] = b'0' + n / 10;
        i += 1;
        n %= 10;
    }
    buf[i] = b'0' + n;
    i += 1;
    s.push_str(unsafe { core::str::from_utf8_unchecked(&buf[..i]) });
}

#[inline(always)]
fn push_hex_byte(s: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    s.push(HEX[(b >> 4) as usize] as char);
    s.push(HEX[(b & 0xf) as usize] as char);
}

fn load_codec(env: &Env) -> Result<UuidCodec> {
    let secret = env
        .var("SECRET_KEY")
        .ok()
        .map(|v| v.to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(fb)?;
    // SECRET_KEY is a combined blob (UUID secret + encryption key); the UUID codec
    // is seeded from the UUID-secret part.
    Ok(UuidCodec::new(&crate::secret::parse(&secret).uuid_key))
}

// ─── Per-isolate UUID caching ────────────────────────────────────────────────
//
// The UUID is the signed token (egress baked in), validated by the SECRET_KEY-
// derived codec — not a fixed credential. Several distinct UUIDs may be live at
// once (per user / interface) but the set is small and rarely changes, and only
// correctly-signed UUIDs ever decode. Two complementary caches make the steady
// state nearly free while staying robust and secure:
//
//   Layer A: the codec (HKDF key derivation) — depends only on SECRET_KEY, so
//            derive once per isolate. A key change means a redeploy → fresh
//            isolate → fresh cell, so there is never a stale codec.
//   Layer B: decoded Payloads keyed by the full 16-byte UUID, in a small bounded
//            LRU. A hit skips MAC verify + keystream entirely. Only successfully
//            verified UUIDs are inserted, so the cache holds exclusively
//            legitimate tokens — an attacker cannot grow it (forging a cacheable
//            UUID needs the secret) and forged/random UUIDs always take the full
//            constant-time verify path (no validity timing oracle is added).

const DECODE_CACHE_CAP: usize = 16;

struct DecodeCache {
    // Most-recently-used at the front; capacity is tiny so a linear scan wins.
    entries: Vec<([u8; 16], Payload)>,
}

impl DecodeCache {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn get(&mut self, key: &[u8; 16]) -> Option<Payload> {
        let pos = self.entries.iter().position(|(k, _)| k == key)?;
        let entry = self.entries.remove(pos);
        let payload = entry.1;
        self.entries.insert(0, entry);
        Some(payload)
    }

    fn insert(&mut self, key: [u8; 16], payload: Payload) {
        if self.entries.iter().any(|(k, _)| *k == key) {
            return;
        }
        if self.entries.len() >= DECODE_CACHE_CAP {
            self.entries.pop();
        }
        self.entries.insert(0, (key, payload));
    }
}

thread_local! {
    static CODEC: OnceCell<UuidCodec> = const { OnceCell::new() };
    static DECODE_CACHE: RefCell<DecodeCache> = const { RefCell::new(DecodeCache::new()) };
}

/// Decode (and authenticate) a UUID's payload, served from the per-isolate
/// caches when possible. Errors on a missing `SECRET_KEY` or a bad MAC.
fn decode_payload(env: &Env, uuid_bytes: &[u8; 16]) -> Result<Payload> {
    // Layer B: a previously verified UUID short-circuits all crypto.
    if let Some(p) = DECODE_CACHE.with(|c| c.borrow_mut().get(uuid_bytes)) {
        return Ok(p);
    }

    // Layer A: derive (or reuse) the codec, then verify + decrypt this UUID.
    let payload = CODEC.with(|cell| -> Result<Payload> {
        if cell.get().is_none() {
            let _ = cell.set(load_codec(env)?);
        }
        let codec = cell.get().ok_or_else(fb)?;
        codec
            .decode(&Uuid::from_bytes(*uuid_bytes))
            .map_err(|_| fb())
    })?;

    // Only verified payloads enter the cache.
    DECODE_CACHE.with(|c| c.borrow_mut().insert(*uuid_bytes, payload));
    Ok(payload)
}

/// Map the decoded UUID payload to an egress. The type byte mirrors the
/// `veilweave-tools` encoder: 0=direct, 1=proxyip, 2=socks5, 3=http. For
/// non-direct types the embedded IPv4 + port are the proxy's address.
fn build_egress(payload: &Payload) -> Egress {
    let ip = || {
        format!(
            "{}.{}.{}.{}",
            payload.ipv4[0], payload.ipv4[1], payload.ipv4[2], payload.ipv4[3]
        )
    };
    match payload.type_byte {
        0x01 => Egress::ProxyIp {
            host: ip(),
            port: payload.port,
        },
        0x02 => Egress::Socks5(ProxyAuth {
            host: ip(),
            port: payload.port,
            user: None,
            pass: None,
        }),
        0x03 => Egress::Http(ProxyAuth {
            host: ip(),
            port: payload.port,
            user: None,
            pass: None,
        }),
        // 0x00 (direct) and any unknown byte fall back to direct.
        _ => Egress::Direct,
    }
}

pub(crate) fn parse_vless_header(buf: &[u8], env: &Env) -> Result<(VlessRequest, usize, Egress)> {
    let mut pos = 0usize;
    if buf.is_empty() || buf[pos] != VLESS_VERSION {
        return Err(fb());
    }
    pos += 1;

    if buf.len() < pos + 16 {
        return Err(fb());
    }
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&buf[pos..pos + 16]);
    pos += 16;

    let payload = decode_payload(env, &uuid_bytes)?;
    let egress = build_egress(&payload);

    if buf.len() < pos + 1 {
        return Err(fb());
    }
    let addon_len = buf[pos] as usize;
    pos += 1;
    if buf.len() < pos + addon_len {
        return Err(fb());
    }
    pos += addon_len;

    if buf.len() < pos + 1 {
        return Err(fb());
    }
    let command = Command::try_from(buf[pos])?;
    pos += 1;
    if command == Command::Mux {
        return Err(fb());
    }

    if buf.len() < pos + 2 {
        return Err(fb());
    }
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;

    if buf.len() < pos + 1 {
        return Err(fb());
    }
    let addr_type = AddrType::try_from(buf[pos])?;
    pos += 1;

    let host = match addr_type {
        AddrType::IPv4 => {
            if buf.len() < pos + 4 {
                return Err(fb());
            }
            let mut ip = String::with_capacity(15);
            for i in 0..4 {
                if i > 0 {
                    ip.push('.');
                }
                push_u8_dec(&mut ip, buf[pos + i]);
            }
            pos += 4;
            ip
        }
        AddrType::IPv6 => {
            if buf.len() < pos + 16 {
                return Err(fb());
            }
            let mut ip = String::with_capacity(46);
            ip.push('[');
            for i in 0..8 {
                if i > 0 {
                    ip.push(':');
                }
                push_hex_byte(&mut ip, buf[pos + i * 2]);
                push_hex_byte(&mut ip, buf[pos + i * 2 + 1]);
            }
            ip.push(']');
            pos += 16;
            ip
        }
        AddrType::Domain => {
            if buf.len() < pos + 1 {
                return Err(fb());
            }
            let dlen = buf[pos] as usize;
            pos += 1;
            if buf.len() < pos + dlen {
                return Err(fb());
            }
            let domain = core::str::from_utf8(&buf[pos..pos + dlen])
                .map_err(|_| fb())?
                .to_string();
            pos += dlen;
            domain
        }
    };

    Ok((
        VlessRequest {
            command,
            host,
            port,
        },
        pos,
        egress,
    ))
}
