// session.rs
// `VeilweaveSession` — a per-connection Durable Object that runs the VLESS Encryption
// data path under the **WebSocket Hibernation API**. The decisive benefit on the
// free plan: each inbound WS frame is delivered as a *separate* `websocket_message`
// invocation with its **own CPU budget**, so the ML-KEM handshake and all upload
// crypto no longer pile into one 10 ms-capped invocation (which is what blew the
// budget on bulk traffic in the single-`fetch` design).
//
//   fetch              → WS upgrade + `accept_web_socket` (hibernatable), return 101.
//   websocket_message  → feed bytes to a resumable state machine:
//                          Handshake → Header(VLESS) → Data | Udp.
//                        Each message decrypts its records (own CPU budget) and
//                        forwards to the target socket.
//   download           → one background loop (target → encrypt → ws.send); the only
//                        continuous task, kept minimal and payload-in-JS.
//
// In-memory per-connection state lives in `RefCell<Inner>`; it survives between
// messages because the open target socket keeps the DO from hibernating while the
// connection is active. RefCell borrows are never held across `await`.

use std::cell::RefCell;

use js_sys::Uint8Array;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::{ReadableStreamDefaultReader, WritableStreamDefaultWriter};
use worker::*;

use crate::conn::Conn;
use crate::datapath::{relay_download, target_write_js};
use crate::egress::{connect_target, Egress};
use crate::enc::{get_header, next_nonce, seal_record_wasm, server_handshake, EncConfig};
use crate::log::vlog;
use crate::vless::{parse_vless_header, Command, VLESS_RESPONSE};
use crate::wsio::WsReader;

#[inline(always)]
fn fb() -> Error {
    Error::RustError(String::new())
}

/// One framed upload record popped from the inbound buffer:
/// `(5-byte record header, AEAD body as a JS buffer, the read nonce)`. The body is
/// copied straight into a `Uint8Array` once — WebCrypto decrypts it in place in the
/// V8 heap, so the payload never makes a second trip through wasm linear memory.
type Record = ([u8; 5], Uint8Array, [u8; 12]);

#[derive(PartialEq, Clone, Copy)]
enum Phase {
    Handshake,
    Header,
    Data,
    Udp,
    Closed,
}

struct Inner {
    phase: Phase,
    /// Inbound ciphertext awaiting framing (handshake bytes, then records).
    buf: Vec<u8>,
    /// Read cursor into `buf`: consumed records advance `pos` instead of shifting
    /// the whole buffer per record (which would be O(n²) within a large frame).
    /// `buf` is compacted by the pump, dropping `..pos`.
    pos: usize,
    /// True while a single invocation is actively draining `buf` in order. A
    /// Durable Object delivers `websocket_message` events concurrently (they
    /// interleave at our non-storage awaits), so without this flag two drains could
    /// pull different records and `await` their target writes out of order,
    /// corrupting the upstream byte stream. Concurrent invocations therefore just
    /// append to `buf` and return; the active pump processes everything in arrival
    /// order. See `websocket_message`.
    pumping: bool,
    key_w: Option<JsValue>, // download (server→client) AES-GCM key
    key_r: Option<JsValue>, // upload (client→server) AES-GCM key
    nonce_w: [u8; 12],
    nonce_r: [u8; 12],
    /// Decrypted plaintext accumulated until the VLESS header parses.
    acc_header: Vec<u8>,
    target_writer: Option<WritableStreamDefaultWriter>,
    conn: Option<Conn>,
    udp_target: Option<(String, u16)>,
}

impl Inner {
    fn new() -> Self {
        Inner {
            phase: Phase::Handshake,
            buf: Vec::new(),
            pos: 0,
            pumping: false,
            key_w: None,
            key_r: None,
            nonce_w: [0u8; 12],
            nonce_r: [0u8; 12],
            acc_header: Vec::new(),
            target_writer: None,
            conn: None,
            udp_target: None,
        }
    }

    /// Pop the next complete `[5-byte header ‖ body]` record at the cursor, copying
    /// the body once into a `Uint8Array` and advancing the cursor + read nonce.
    /// Returns `(header, body, nonce)` or `None` if the record is not yet complete.
    fn take_record(&mut self) -> Result<Option<Record>> {
        let avail = self.buf.len() - self.pos;
        if avail < 5 {
            return Ok(None);
        }
        let mut hdr = [0u8; 5];
        hdr.copy_from_slice(&self.buf[self.pos..self.pos + 5]);
        let l = get_header(&hdr)?;
        if avail < 5 + l {
            return Ok(None);
        }
        next_nonce(&mut self.nonce_r);
        let nonce = self.nonce_r;
        let body = Uint8Array::from(&self.buf[self.pos + 5..self.pos + 5 + l]);
        self.pos += 5 + l;
        Ok(Some((hdr, body, nonce)))
    }

    /// Drop the already-consumed prefix so `buf` holds only the live window (any
    /// partial trailing record). Called by the pump between drains.
    fn compact(&mut self) {
        if self.pos == 0 {
            return;
        }
        if self.pos >= self.buf.len() {
            self.buf.clear();
        } else {
            self.buf.drain(..self.pos);
        }
        self.pos = 0;
    }

    /// Whether a *complete* record is buffered at the cursor — i.e. bytes that
    /// arrived during the pump's awaits still need draining. Only meaningful once
    /// records are being framed (post-handshake). A malformed header counts as
    /// pending so the pump re-enters `drive`, which surfaces the error and closes.
    fn has_pending(&self) -> bool {
        if !matches!(self.phase, Phase::Header | Phase::Data | Phase::Udp) {
            return false;
        }
        let avail = self.buf.len() - self.pos;
        if avail < 5 {
            return false;
        }
        let mut hdr = [0u8; 5];
        hdr.copy_from_slice(&self.buf[self.pos..self.pos + 5]);
        match get_header(&hdr) {
            Ok(l) => avail >= 5 + l,
            Err(_) => true,
        }
    }
}

#[durable_object]
pub struct VeilweaveSession {
    state: State,
    env: Env,
    cfg: Option<EncConfig>,
    inner: RefCell<Inner>,
}

impl DurableObject for VeilweaveSession {
    fn new(state: State, env: Env) -> Self {
        // The encryption config is derived once from the relay's combined secret.
        let cfg = env
            .var("SECRET_KEY")
            .ok()
            .map(|v| v.to_string())
            .and_then(|s| crate::secret::parse(&s).relay_private())
            .map(EncConfig::new);
        Self {
            state,
            env,
            cfg,
            inner: RefCell::new(Inner::new()),
        }
    }

    async fn fetch(&self, _req: Request) -> Result<Response> {
        if self.cfg.is_none() {
            return Response::error("not configured", 500);
        }
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        // Hibernatable: each future inbound frame becomes its own invocation.
        self.state.accept_web_socket(&server);
        server
            .as_ref()
            .set_binary_type(web_sys::BinaryType::Arraybuffer);

        // The veilweave-generated config carries no `?ed=` early-data and no
        // WebSocket subprotocol — the VLESS-Encryption clientHello arrives in the
        // first WS frame — so there is nothing to seed or echo here.
        *self.inner.borrow_mut() = Inner::new();

        vlog!("session: ws accepted (hibernatable), awaiting clientHello");
        Response::from_websocket(pair.client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let data = match message {
            WebSocketIncomingMessage::Binary(d) => d,
            WebSocketIncomingMessage::String(_) => return Ok(()), // VLESS is binary
        };
        vlog!("ws msg: {} bytes inbound", data.len());
        // Append this frame, then decide whether we own the pump. This whole block
        // is synchronous (no await), so concurrent invocations can't interleave
        // here — exactly one becomes the pump; the rest just enqueue their bytes.
        {
            let mut inner = self.inner.borrow_mut();
            if inner.phase == Phase::Closed {
                return Ok(());
            }
            if inner.pumping {
                // A pump is already draining `buf` in order; hand it our bytes and
                // return. It owns the cursor, so we must not compact here.
                inner.buf.extend_from_slice(&data);
                return Ok(());
            }
            inner.compact();
            // Steady state: every record from the previous frame was consumed, so
            // `buf` is empty and we take ownership of the incoming `Vec` with no copy.
            // Only when a record straddles frames (small leftover) do we extend.
            if inner.buf.is_empty() {
                inner.buf = data;
            } else {
                inner.buf.extend_from_slice(&data);
            }
            inner.pumping = true;
        }
        // `enc`/`datapath` and the raw record sends use `web_sys::WebSocket`.
        let wsx: web_sys::WebSocket = ws.as_ref().clone();
        let outcome = self.pump(&wsx).await;
        self.inner.borrow_mut().pumping = false;
        if let Err(_e) = outcome {
            vlog!("pump error → closing 1011: {_e}");
            let _ = ws.close(Some(1011), Some("error"));
            self.cleanup().await;
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _clean: bool,
    ) -> Result<()> {
        vlog!("ws close: code={_code} clean={_clean} reason={:?}", _reason);
        self.cleanup().await;
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: Error) -> Result<()> {
        vlog!("ws error: {_error}");
        self.cleanup().await;
        Ok(())
    }
}

impl VeilweaveSession {
    #[inline]
    fn phase(&self) -> Phase {
        self.inner.borrow().phase
    }

    async fn cleanup(&self) {
        let conn = {
            let mut inner = self.inner.borrow_mut();
            inner.phase = Phase::Closed;
            inner.target_writer = None;
            inner.conn.take()
        };
        if let Some(c) = conn {
            let _ = c.close().await;
        }
    }

    /// The single serialized record processor. Drains every buffered record in
    /// arrival order, then re-checks for bytes that arrived during its awaits
    /// (concurrent invocations append while `pumping`), looping until the buffer
    /// holds no further complete record. Because only one pump runs at a time,
    /// target writes are emitted strictly in order.
    async fn pump(&self, ws: &web_sys::WebSocket) -> Result<()> {
        loop {
            self.drive(ws).await?;
            let more = {
                let mut inner = self.inner.borrow_mut();
                if inner.phase == Phase::Closed {
                    return Ok(());
                }
                inner.compact();
                inner.has_pending()
            };
            if !more {
                return Ok(());
            }
        }
    }

    /// Advance the connection state machine as far as the buffered bytes allow.
    /// Borrows of `inner` are confined to short sync sections (never across await).
    async fn drive(&self, ws: &web_sys::WebSocket) -> Result<()> {
        // ── Handshake ──
        if self.phase() == Phase::Handshake {
            let buf = self.inner.borrow().buf.clone();
            #[cfg(feature = "perf-log")]
            let hs_t0 = crate::log::now_ms();
            let cfg = self.cfg.as_ref().ok_or_else(fb)?;
            match server_handshake(cfg, WsReader::from_buffer(buf), ws).await? {
                None => return Ok(()), // need more clientHello bytes
                Some(hs) => {
                    vlog!(
                        "handshake: complete (~{:.0}ms wall), {} leftover data bytes",
                        crate::log::now_ms() - hs_t0,
                        hs.leftover.len()
                    );
                    // AES-NI WebCrypto, verified byte-identical once per isolate.
                    if !crate::webcrypto::aes_gcm_usable().await {
                        return Err(fb());
                    }
                    let key_w = crate::webcrypto::import_aes_gcm_key(&hs.key_w).await?;
                    let key_r = crate::webcrypto::import_aes_gcm_key(&hs.key_r).await?;
                    let mut inner = self.inner.borrow_mut();
                    inner.key_w = Some(key_w);
                    inner.key_r = Some(key_r);
                    inner.nonce_w = hs.nonce_w;
                    inner.nonce_r = hs.nonce_r;
                    inner.buf = hs.leftover;
                    inner.pos = 0;
                    inner.phase = Phase::Header;
                }
            }
        }

        // ── VLESS header (decrypt records into wasm until parsed) ──
        if self.phase() == Phase::Header {
            let key_r = self.inner.borrow().key_r.clone().ok_or_else(fb)?;
            loop {
                let rec = self.inner.borrow_mut().take_record()?;
                let (hdr, body, nonce) = match rec {
                    Some(r) => r,
                    None => return Ok(()), // need more bytes
                };
                let pt =
                    crate::webcrypto::decrypt_view(&key_r, &nonce, &hdr, body.as_ref()).await?;
                let pt = Uint8Array::new(&pt).to_vec();
                self.inner.borrow_mut().acc_header.extend_from_slice(&pt);

                let acc = self.inner.borrow().acc_header.clone();
                match parse_vless_header(&acc, &self.env) {
                    Ok((req, header_len, egress)) => {
                        let initial = acc[header_len..].to_vec();
                        self.inner.borrow_mut().acc_header = Vec::new();
                        self.establish(ws, req.command, req.host, req.port, egress, initial)
                            .await?;
                        break;
                    }
                    Err(_) if acc.len() < 1024 => continue,
                    Err(e) => return Err(e),
                }
            }
        }

        // ── Data (TCP) ──
        if self.phase() == Phase::Data {
            let (key_r, writer) = {
                let inner = self.inner.borrow();
                (
                    inner.key_r.clone().ok_or_else(fb)?,
                    inner.target_writer.clone().ok_or_else(fb)?,
                )
            };
            #[cfg(feature = "perf-log")]
            let (mut nrec, mut nbytes) = (0u32, 0u64);
            loop {
                let rec = self.inner.borrow_mut().take_record()?;
                let (hdr, body, nonce) = match rec {
                    Some(r) => r,
                    None => {
                        vlog!("upload drive: {nrec} records, {nbytes} ciphertext bytes → target");
                        return Ok(());
                    }
                };
                #[cfg(feature = "perf-log")]
                {
                    nrec += 1;
                    nbytes += body.length() as u64;
                }
                let pt =
                    crate::webcrypto::decrypt_view(&key_r, &nonce, &hdr, body.as_ref()).await?;
                target_write_js(&writer, &pt).await?;
            }
        }

        // ── Data (UDP / DNS) ──
        if self.phase() == Phase::Udp {
            let key_r = self.inner.borrow().key_r.clone().ok_or_else(fb)?;
            loop {
                let rec = self.inner.borrow_mut().take_record()?;
                let (hdr, body, nonce) = match rec {
                    Some(r) => r,
                    None => return Ok(()),
                };
                let pt =
                    crate::webcrypto::decrypt_view(&key_r, &nonce, &hdr, body.as_ref()).await?;
                let pt = Uint8Array::new(&pt).to_vec();
                self.handle_udp_frames(ws, &pt).await?;
            }
        }

        Ok(())
    }

    /// Connect the target and start the appropriate direction(s).
    async fn establish(
        &self,
        ws: &web_sys::WebSocket,
        command: Command,
        host: String,
        port: u16,
        egress: Egress,
        initial: Vec<u8>,
    ) -> Result<()> {
        #[cfg(feature = "perf-log")]
        {
            let cmd = match command {
                Command::Tcp => "TCP",
                Command::Udp => "UDP",
                Command::Mux => "MUX",
            };
            let eg = match &egress {
                Egress::Direct => "direct",
                Egress::ProxyIp { .. } => "proxyip",
                Egress::Socks5(_) => "socks5",
                Egress::Http(_) => "http",
            };
            vlog!(
                "establish: {cmd} {host}:{port} via {eg} ({} initial bytes)",
                initial.len()
            );
        }

        let key_w = self.inner.borrow().key_w.clone().ok_or_else(fb)?;
        let mut nonce_w = self.inner.borrow().nonce_w;

        match command {
            Command::Tcp => {
                #[cfg(feature = "perf-log")]
                let ct0 = crate::log::now_ms();
                let (conn, leftover, _path) = connect_target(&host, port, &egress).await?;
                vlog!(
                    "connect: {host}:{port} via {_path} (~{:.0}ms), {} downstream leftover bytes",
                    crate::log::now_ms() - ct0,
                    leftover.len()
                );
                let reader_t: ReadableStreamDefaultReader =
                    conn.readable().get_reader().dyn_into().map_err(|_| fb())?;
                let writer_t: WritableStreamDefaultWriter =
                    conn.writable().get_writer().map_err(|_| fb())?;

                if !initial.is_empty() {
                    let chunk: JsValue = Uint8Array::from(&initial[..]).into();
                    target_write_js(&writer_t, &chunk).await?;
                }
                // VLESS response (+ proxy-handshake leftover) before bulk download.
                let resp = seal_record_wasm(&key_w, &mut nonce_w, &VLESS_RESPONSE).await?;
                ws.send_with_u8_array(&resp).map_err(|_| fb())?;
                if !leftover.is_empty() {
                    let rec = seal_record_wasm(&key_w, &mut nonce_w, &leftover).await?;
                    ws.send_with_u8_array(&rec).map_err(|_| fb())?;
                }

                // Background download loop owns the write nonce from here on.
                let ws_c: web_sys::WebSocket = ws.clone();
                let key_w_c = key_w.clone();
                let nw = nonce_w;
                spawn_local(async move {
                    let _ = relay_download(&reader_t, &ws_c, &key_w_c, nw).await;
                    let _ = ws_c.close();
                });

                let mut inner = self.inner.borrow_mut();
                inner.target_writer = Some(writer_t);
                inner.conn = Some(conn);
                inner.phase = Phase::Data;
                Ok(())
            }
            Command::Udp => {
                let resp = seal_record_wasm(&key_w, &mut nonce_w, &VLESS_RESPONSE).await?;
                ws.send_with_u8_array(&resp).map_err(|_| fb())?;
                {
                    let mut inner = self.inner.borrow_mut();
                    inner.nonce_w = nonce_w;
                    inner.udp_target = Some((host, port));
                    inner.phase = Phase::Udp;
                }
                if !initial.is_empty() {
                    self.handle_udp_frames(ws, &initial).await?;
                }
                Ok(())
            }
            Command::Mux => Err(fb()),
        }
    }

    /// One inbound plaintext buffer of length-prefixed UDP packets → DNS round-trips
    /// (stateless: a fresh socket per packet), responses sealed back to the client.
    async fn handle_udp_frames(&self, ws: &web_sys::WebSocket, pt: &[u8]) -> Result<()> {
        let (host, port) = match self.inner.borrow().udp_target.clone() {
            Some(t) => t,
            None => return Err(fb()),
        };
        let key_w = self.inner.borrow().key_w.clone().ok_or_else(fb)?;

        let mut p = pt;
        while p.len() >= 2 {
            let l = u16::from_be_bytes([p[0], p[1]]) as usize;
            if p.len() < 2 + l {
                break;
            }
            let payload = &p[2..2 + l];
            p = &p[2 + l..];

            if let Ok(resp) = udp_query(&host, port, payload).await {
                if !resp.is_empty() {
                    let mut framed = Vec::with_capacity(2 + resp.len());
                    framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                    framed.extend_from_slice(&resp);
                    let mut nonce_w = self.inner.borrow().nonce_w;
                    let rec = seal_record_wasm(&key_w, &mut nonce_w, &framed).await?;
                    self.inner.borrow_mut().nonce_w = nonce_w;
                    ws.send_with_u8_array(&rec).map_err(|_| fb())?;
                }
            }
        }
        Ok(())
    }
}

/// Stateless single UDP/DNS round-trip over a fresh socket.
async fn udp_query(host: &str, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut conn = Conn::connect(host, port)?;
    conn.opened().await?;
    conn.write_all(payload).await?;
    let mut buf = [0u8; 4096];
    let n = conn.read(&mut buf).await.unwrap_or(0);
    let _ = conn.close().await;
    Ok(buf[..n].to_vec())
}
