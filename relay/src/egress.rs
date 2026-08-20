// egress.rs
// How the worker reaches the requested target. The egress is chosen entirely
// from the type byte encoded in the (signed) VLESS UUID — there is no per-request
// path/query parsing here, that is the job of `veilweave-tools` which bakes the
// egress into the UUID it hands out.
//
//   Direct          : connect straight to the target.
//   ProxyIp{host}   : try direct first, fall back to a non-CF relay IP for
//                     Cloudflare-hosted targets that `connect()` can't reach.
//   Socks5 / Http   : tunnel through a SOCKS5 / HTTP-CONNECT proxy.

use crate::conn::Conn;
use base64::{engine::general_purpose, Engine as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{Error, Result};

#[derive(Clone)]
pub struct ProxyAuth {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
}

#[derive(Clone)]
pub enum Egress {
    Direct,
    ProxyIp { host: String, port: u16 },
    Socks5(ProxyAuth),
    Http(ProxyAuth),
}

#[inline(always)]
fn fb() -> Error {
    Error::RustError(String::new())
}

/// Connect to `host:port` via the chosen egress. Returns the connection, any
/// bytes the proxy handshake already buffered *downstream* (target→client) — the
/// caller must forward these to the WebSocket before starting the relay — and a
/// static label of the path actually taken (for `perf-log` connect accounting).
pub async fn connect_target(
    host: &str,
    port: u16,
    egress: &Egress,
) -> Result<(Conn, Vec<u8>, &'static str)> {
    match egress {
        Egress::Socks5(p) => {
            let mut c = socks5_connect(host, port, p).await?;
            let leftover = c.take_buffered();
            Ok((c, leftover, "socks5"))
        }
        Egress::Http(p) => {
            let (c, leftover) = http_connect(host, port, p).await?;
            Ok((c, leftover, "http"))
        }
        Egress::ProxyIp { host: pip_host, port: pip_port } => {
            // Direct first: ordinary (non-CF) sites connect straight through on the
            // fast path. Targets that live in Cloudflare's own ranges fail the direct
            // dial (Workers can't reach CF IPs) and fall back to the proxyip — so
            // CF-hosted targets are still served, without forcing non-CF traffic
            // (and client latency-test endpoints) through the proxyip.
            match try_connect(host, port).await {
                Ok(c) => Ok((c, Vec::new(), "direct")),
                Err(_) => {
                    let c = try_connect(pip_host, *pip_port).await?;
                    Ok((c, Vec::new(), "proxyip"))
                }
            }
        }
        Egress::Direct => {
            let c = try_connect(host, port).await?;
            Ok((c, Vec::new(), "direct"))
        }
    }
}

#[inline]
async fn try_connect(host: &str, port: u16) -> Result<Conn> {
    let c = Conn::connect(host, port)?;
    c.opened().await?;
    Ok(c)
}

// ─── SOCKS5 egress (RFC 1928) — stack-buffer handshake ──────────────────────────

async fn socks5_connect(target_host: &str, target_port: u16, p: &ProxyAuth) -> Result<Conn> {
    let mut s = try_connect(&p.host, p.port).await?;

    let authed = p.user.is_some();
    let greeting: &[u8] = if authed { &[0x05, 0x02, 0x00, 0x02] } else { &[0x05, 0x01, 0x00] };
    s.write_all(greeting).await?;

    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    if sel[0] != 0x05 {
        return Err(fb());
    }
    match sel[1] {
        0x00 => {}
        0x02 => {
            let user = p.user.as_deref().unwrap_or("");
            let pass = p.pass.as_deref().unwrap_or("");
            let mut pkt = [0u8; 513];
            pkt[0] = 0x01;
            pkt[1] = user.len() as u8;
            pkt[2..2 + user.len()].copy_from_slice(user.as_bytes());
            let pass_off = 2 + user.len();
            pkt[pass_off] = pass.len() as u8;
            pkt[pass_off + 1..pass_off + 1 + pass.len()].copy_from_slice(pass.as_bytes());
            s.write_all(&pkt[..pass_off + 1 + pass.len()]).await?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await?;
            if ar[1] != 0x00 {
                return Err(fb());
            }
        }
        _ => return Err(fb()),
    }

    let hb = target_host.as_bytes();
    if hb.len() > 255 {
        return Err(fb());
    }
    let mut req = [0u8; 262];
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x03;
    req[4] = hb.len() as u8;
    req[5..5 + hb.len()].copy_from_slice(hb);
    let port_off = 5 + hb.len();
    req[port_off..port_off + 2].copy_from_slice(&target_port.to_be_bytes());
    s.write_all(&req[..port_off + 2]).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(fb());
    }
    let bnd_addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        _ => return Err(fb()),
    };
    let mut skip = [0u8; 18];
    s.read_exact(&mut skip[..bnd_addr_len + 2]).await?;
    Ok(s)
}

// ─── HTTP CONNECT egress ─────────────────────────────────────────────────────────

async fn http_connect(target_host: &str, target_port: u16, p: &ProxyAuth) -> Result<(Conn, Vec<u8>)> {
    let mut s = try_connect(&p.host, p.port).await?;

    let mut req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let (Some(u), Some(pw)) = (&p.user, &p.pass) {
        let cred = general_purpose::STANDARD.encode(format!("{u}:{pw}"));
        req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
    }
    req.push_str("User-Agent: Mozilla/5.0\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n");
    s.write_all(req.as_bytes()).await?;

    let mut buf = [0u8; 8192];
    let mut buf_len = 0;
    let header_end = loop {
        if buf_len >= buf.len() {
            return Err(fb());
        }
        let n = s.read(&mut buf[buf_len..]).await?;
        if n == 0 {
            return Err(fb());
        }
        buf_len += n;
        if let Some(pos) = find_crlfcrlf(&buf[..buf_len]) {
            break pos + 4;
        }
    };

    let status_line = unsafe { core::str::from_utf8_unchecked(&buf[..header_end.min(256)]) };
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&code) {
        return Err(fb());
    }

    // Downstream leftover = bytes after the CONNECT response in our buffer, plus
    // anything AsyncRead pulled past it.
    let mut leftover = buf[header_end..buf_len].to_vec();
    leftover.extend_from_slice(&s.take_buffered());
    Ok((s, leftover))
}

#[inline(always)]
fn find_crlfcrlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}
