use core::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use worker::*;

// ========== 配置常量：模拟 Debian 12 + Apache 2.4.62 ==========
const SERVER_SIGNATURE: &str = "Apache/2.4.62 (Debian)";
const KEEP_ALIVE: &str = "timeout=5, max=100";

static ICON_ICO: &[u8] = include_bytes!("../static/favicon.ico");
static ICON_PNG: &[u8] = include_bytes!("../static/icons/openlogo-75.png");
static DEFAULT_HTML: &str = include_str!("../static/apache_default.html");
static NOT_FOUND_TEMPLATE: &str = include_str!("../static/apache_404.html");

pub fn apache_default_page(req: Request) -> Result<Response> {
    match req.path().as_str() {
        "/favicon.ico" => serve_static(ICON_ICO, "image/x-icon"),
        "/icons/openlogo-75.png" => serve_static(ICON_PNG, "image/png"),
        "/" | "/index.html" => serve_html(DEFAULT_HTML, 200),
        _ => serve_not_found(&req),
    }
}

fn serve_not_found(req: &Request) -> Result<Response> {
    let host = req
        .headers()
        .get("Host")
        .ok()
        .flatten()
        .unwrap_or_else(|| "localhost".to_string());
    not_found(&host)
}

/// Render the Apache-style 404 page for a given `Host` header value. Used for
/// every 404 the worker emits so probes see an ordinary Apache server instead
/// of a revealing API error.
pub fn not_found(host: &str) -> Result<Response> {
    let (server_name, port) = parse_host(host);

    let body = NOT_FOUND_TEMPLATE
        .replace("{{SERVER_NAME}}", &server_name)
        .replace("{{SERVER_PORT}}", &port);

    let headers = base_headers();
    headers.set("Content-Type", "text/html; charset=iso-8859-1")?;
    headers.set("Content-Length", &body.len().to_string())?;

    let resp = Response::from_html(&body)?;
    Ok(resp.with_status(404).with_headers(headers))
}

fn serve_static(body: &[u8], content_type: &str) -> Result<Response> {
    let headers = base_headers();
    headers.set("Content-Type", content_type)?;
    headers.set("Content-Length", &body.len().to_string())?;
    headers.set("ETag", &generate_etag(body.len() as u64, body))?;

    Ok(Response::from_bytes(body.to_vec())?.with_headers(headers))
}

fn serve_html(body: &str, status: u16) -> Result<Response> {
    let headers = base_headers();
    headers.set("Content-Type", "text/html; charset=UTF-8")?;
    headers.set("Content-Length", &body.len().to_string())?;
    headers.set("ETag", &generate_etag(body.len() as u64, body.as_bytes()))?;

    let resp = Response::from_html(body)?;
    Ok(resp.with_status(status).with_headers(headers))
}

fn base_headers() -> Headers {
    let header = Headers::new();
    let _ = header.set("Server", SERVER_SIGNATURE);
    let _ = header.set("Date", &http_date_now());
    let _ = header.set("Accept-Ranges", "bytes");
    let _ = header.set("Connection", "Keep-Alive");
    let _ = header.set("Keep-Alive", KEEP_ALIVE);
    header
}

fn parse_host(host: &str) -> (String, String) {
    match host.rsplit_once(':') {
        Some((name, port)) if port.parse::<u16>().is_ok() => (name.to_string(), port.to_string()),
        _ => (host.to_string(), "80".to_string()),
    }
}

fn generate_etag(size: u64, content: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    format!("\"{:x}-{:x}\"", size, hasher.finish())
}

fn http_date_now() -> String {
    let now = Date::now();
    let secs = (now.as_millis() / 1000) as i64;
    format_rfc7231(secs)
}

fn format_rfc7231(timestamp: i64) -> String {
    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mut days = timestamp / 86400;
    let mut rem = timestamp % 86400;
    let hh = rem / 3600;
    rem %= 3600;
    let mm = rem / 60;
    let ss = rem % 60;
    let mut year = 1970;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let d = if leap { 366 } else { 365 };
        if days < d {
            break;
        }
        days -= d;
        year += 1;
    }
    let mut mon = 0;
    let mdays = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    while mon < 12 {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let d = mdays[mon] + if mon == 1 && leap { 1 } else { 0 };
        if days < d {
            break;
        }
        days -= d;
        mon += 1;
    }
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        WD[((days + 4) % 7) as usize],
        days + 1,
        MO[mon],
        year,
        hh,
        mm,
        ss
    )
}
