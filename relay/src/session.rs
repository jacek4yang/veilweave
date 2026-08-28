// session.rs
// `VeilweaveSession` — a per-connection Durable Object that runs the VLESS data
// path under the **WebSocket Hibernation API**, in one of two modes selected by
// `SECRET_KEY`:
//
//   Plaintext (default — any raw secret string): the VLESS header arrives as
//     raw WS bytes; once it parses, both directions are a pure passthrough —
//     zero crypto, zero record framing. This is the recommended mode under the
//     Workers free CPU limits.
//   Encrypted (experimental opt-in — a "VW1" blob secret): the VLESS Encryption
//     handshake runs first and all traffic flows in AEAD records. The decisive
//     benefit of hibernation here: each inbound WS frame is delivered as a
//     *separate* `websocket_message` invocation with its **own CPU budget**, so
//     the ML-KEM handshake and all upload crypto no longer pile into one
//     10 ms-capped invocation (which is what blew the budget on bulk traffic in
//     the single-`fetch` design).
//
//   fetch              → WS upgrade + `accept_web_socket` (hibernatable), return 101.
//   websocket_message  → feed bytes to a resumable state machine:
//                          encrypted: Handshake → Header(VLESS) → Data | Udp
//                          plaintext: PlainHeader(VLESS) → PlainData | PlainUdp.
//                        Encrypted messages decrypt their records (own CPU budget)
//                        and forward to the target socket; plaintext messages are
//                        written through as-is.
//   download           → one background loop (target → ws.send, encrypted or raw);
//                        the only continuous task, kept minimal and payload-in-JS.
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
use crate::datapath::{plain_download, relay_download, target_write_js};
use crate::egress::{connect_target, Egress};
use crate::enc::{
    get_header, next_nonce, seal_record_wasm, server_handshake, EncConfig, HandshakePoll,
};
use crate::log::vlog;
use crate::vless::{parse_vless_header, Command, VlessRequest, VLESS_RESPONSE};
use crate::wsio::WsReader;

#[inline(always)]
fn fb() -> Error {
    Error::RustError(String::new())
}

async fn connect_target_observed(
    host: &str,
    port: u16,
    egress: &Egress,
) -> Result<(Conn, Vec<u8>, &'static str)> {
    match connect_target(host, port, egress).await {
        Ok(connected) => Ok(connected),
        Err(_) => {
            let kind = match egress {
                Egress::Direct => "direct",
                Egress::ProxyIp { .. } => "proxyip",
                Egress::Socks5(_) => "socks5",
                Egress::Http(_) => "http",
            };
            console_error!(
                "event=relay_target_connect status=failed code=RelayTargetConnectFailed egress={kind}"
            );
            Err(fb())
        }
    }
}

/// One framed upload record popped from the inbound buffer:
/// `(5-byte record header, AEAD body as a JS view, the read nonce)`. The body is
/// a **zero-copy view over `buf`** (see `take_record`) — WebCrypto copies its
/// input synchronously during the `decrypt` call, so the payload never crosses
/// into the V8 heap and back before that.
type Record = ([u8; 5], Uint8Array, [u8; 12]);

#[derive(PartialEq, Clone, Copy)]
enum Phase {
    // Encrypted mode (blob secret): handshake, then record-framed phases.
    Handshake,
    Header,
    Data,
    Udp,
    // Plaintext mode (raw secret): raw VLESS header, then pure passthrough.
    PlainHeader,
    PlainData,
    PlainUdp,
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
    /// `plaintext` selects the starting phase: a raw (non-blob) `SECRET_KEY`
    /// means the raw VLESS header arrives directly; a blob means the VLESS
    /// Encryption clientHello comes first.
    fn new(plaintext: bool) -> Self {
        Inner {
            phase: if plaintext {
                Phase::PlainHeader
            } else {
                Phase::Handshake
            },
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

    /// Pop the next complete `[5-byte header ‖ body]` record at the cursor,
    /// advancing the cursor + read nonce. The body is handed out as a zero-copy
    /// `Uint8Array::view` over `buf` — this removes the old per-record wasm→JS
    /// copy of the whole ciphertext. Soundness: WebCrypto performs "get a copy
    /// of the bytes held by the buffer source" **synchronously** inside the
    /// `decrypt` call (WebIDL BufferSource conversion), before the promise it
    /// returns exists; the view is never touched after that `apply`. Between
    /// view creation and `apply` there is no `await` and no wasm allocation, so
    /// linear memory cannot grow and move under the view; workers are
    /// single-threaded, so no concurrent invocation can mutate `buf` in that
    /// window either. Returns `None` if the record is not yet complete.
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
        let body = unsafe { Uint8Array::view(&self.buf[self.pos + 5..self.pos + 5 + l]) };
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

    /// Whether buffered bytes still need draining — i.e. bytes that arrived
    /// during the pump's awaits. In the encrypted phases that means a *complete*
    /// record at the cursor (a malformed header counts as pending so the pump
    /// re-enters `drive`, which surfaces the error and closes). In the plaintext
    /// data phases any buffered byte is forwardable as-is; the plaintext header
    /// phase makes no progress without NEW bytes (its parse attempt never
    /// awaits), so nothing can be pending there.
    fn has_pending(&self) -> bool {
        match self.phase {
            Phase::PlainHeader | Phase::Handshake | Phase::Closed => false,
            Phase::PlainData | Phase::PlainUdp => self.buf.len() > self.pos,
            Phase::Header | Phase::Data | Phase::Udp => {
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
        // A "VW1" blob yields `Some` → VLESS Encryption (experimental opt-in);
        // a raw (non-blob) secret yields `None` → plaintext VLESS, the default
        // and recommended mode under the Workers free CPU limits.
        let cfg = env
            .var("SECRET_KEY")
            .ok()
            .map(|v| v.to_string())
            .and_then(|s| crate::secret::parse(&s).relay_private())
            .map(EncConfig::new);
        let plaintext = cfg.is_none();
        Self {
            state,
            env,
            cfg,
            inner: RefCell::new(Inner::new(plaintext)),
        }
    }

    async fn fetch(&self, _req: Request) -> Result<Response> {
        // A missing/empty SECRET_KEY is a misconfiguration in either mode (the
        // UUID codec could not be seeded), so refuse the upgrade early.
        let configured = self
            .env
            .var("SECRET_KEY")
            .ok()
            .map(|v| v.to_string())
            .is_some_and(|s| !s.is_empty());
        if !configured {
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
        // WebSocket subprotocol — in encrypted mode the VLESS-Encryption
        // clientHello arrives in the first WS frame, in plaintext mode the raw
        // VLESS header does — so there is nothing to seed or echo here.
        *self.inner.borrow_mut() = Inner::new(self.cfg.is_none());

        vlog!(
            "session: ws accepted (hibernatable), mode={}",
            if self.cfg.is_some() {
                "vless-encryption"
            } else {
                "plaintext"
            }
        );
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
            console_error!("event=relay_session status=failed code=RelaySessionFailed");
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
        // Plaintext mode runs its own phases — no handshake, no record framing.
        if matches!(
            self.phase(),
            Phase::PlainHeader | Phase::PlainData | Phase::PlainUdp
        ) {
            return self.drive_plain(ws).await;
        }

        // ── Handshake ──
        if self.phase() == Phase::Handshake {
            #[cfg(feature = "perf-log")]
            let hs_t0 = crate::log::now_ms();
            let cfg = self.cfg.as_ref().ok_or_else(fb)?;
            // Move the buffer out instead of cloning it: the handshake retries on
            // every inbound frame until the clientHello is complete, so copying
            // the whole accumulation per invocation is pure churn. `NeedMore`
            // hands the bytes straight back.
            let buf = std::mem::take(&mut self.inner.borrow_mut().buf);
            match server_handshake(cfg, WsReader::from_buffer(buf), ws).await? {
                HandshakePoll::NeedMore(reader) => {
                    // Incomplete clientHello: restore the bytes and wait for the
                    // next frame. Anything concurrent invocations appended during
                    // the await sorts behind what we already had.
                    let mut inner = self.inner.borrow_mut();
                    let mut buf = reader.into_inner();
                    buf.extend_from_slice(&inner.buf);
                    inner.buf = buf;
                    return Ok(()); // need more clientHello bytes
                }
                HandshakePoll::Done(hs) => {
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
                    // Any bytes appended mid-await sort behind the handshake leftover.
                    let mut buf = hs.leftover;
                    buf.extend_from_slice(&inner.buf);
                    inner.buf = buf;
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

                // `parse_vless_header` is fully synchronous, so borrow
                // `acc_header` in place and copy out ONLY the post-header payload
                // on success — the old code cloned the whole accumulation for
                // every parse attempt (i.e. per header record).
                enum Hdr {
                    More,
                    Parsed(VlessRequest, Egress, Vec<u8>),
                }
                let step = {
                    let inner = self.inner.borrow();
                    match parse_vless_header(&inner.acc_header, &self.env) {
                        Ok((req, header_len, egress)) => {
                            let initial = inner.acc_header[header_len..].to_vec();
                            Hdr::Parsed(req, egress, initial)
                        }
                        Err(_) if inner.acc_header.len() < 1024 => Hdr::More,
                        Err(e) => {
                            console_error!(
                                "event=relay_protocol status=failed code=RelayProtocolInvalid"
                            );
                            return Err(e);
                        }
                    }
                };
                match step {
                    Hdr::More => continue,
                    Hdr::Parsed(req, egress, initial) => {
                        self.inner.borrow_mut().acc_header = Vec::new();
                        self.establish(ws, req.command, req.host, req.port, egress, initial)
                            .await?;
                        break;
                    }
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

    /// Plaintext-mode state machine (raw `SECRET_KEY`, no VLESS Encryption): the
    /// VLESS header arrives as raw WS bytes and the data phases are a pure
    /// passthrough — zero crypto, zero record framing. Uploads reuse the same
    /// serialized pump (`pumping`/`buf`), so concurrent invocations cannot
    /// interleave target writes; the download side is `plain_download`.
    async fn drive_plain(&self, ws: &web_sys::WebSocket) -> Result<()> {
        // ── VLESS header (raw bytes, accumulate until it parses) ──
        if self.phase() == Phase::PlainHeader {
            enum Hdr {
                More,
                Parsed(VlessRequest, Egress, Vec<u8>),
            }
            let step = {
                let inner = self.inner.borrow();
                match parse_vless_header(&inner.buf[inner.pos..], &self.env) {
                    Ok((req, header_len, egress)) => {
                        // Bytes past the header are the first payload chunk.
                        let initial = inner.buf[inner.pos + header_len..].to_vec();
                        Hdr::Parsed(req, egress, initial)
                    }
                    // Same rule as the encrypted header phase: an incomplete
                    // header waits for more bytes; past 1 KiB it is a failure.
                    Err(_) if inner.buf.len() - inner.pos < 1024 => Hdr::More,
                    Err(e) => {
                        console_error!(
                            "event=relay_protocol status=failed code=RelayProtocolInvalid"
                        );
                        return Err(e);
                    }
                }
            };
            match step {
                Hdr::More => return Ok(()), // need more header bytes
                Hdr::Parsed(req, egress, initial) => {
                    {
                        let mut inner = self.inner.borrow_mut();
                        inner.buf.clear();
                        inner.pos = 0;
                    }
                    self.establish_plain(ws, req.command, req.host, req.port, egress, initial)
                        .await?;
                }
            }
        }

        // ── Data (TCP): frame bytes → target socket, verbatim ──
        //
        // Two copies per frame remain here and both are FFI-mandated:
        //   1. JS→wasm, done by worker-rs when it delivers `websocket_message`
        //      as a `Vec<u8>` — irreducible without abandoning worker-rs's
        //      Durable Object event plumbing (not worth it).
        //   2. wasm→JS, the `Uint8Array::from` below — required because the
        //      socket's WritableStream may read the chunk ASYNCHRONOUSLY after
        //      we return (unlike WebCrypto/`ws.send`, the Streams spec does not
        //      copy the chunk synchronously), so handing it a zero-copy view
        //      over `buf` would alias memory we later reuse. Everything else —
        //      the move into `buf` in `websocket_message`, the cursor drain
        //      here — is copy-free in the common case.
        if self.phase() == Phase::PlainData {
            let writer = self.inner.borrow().target_writer.clone().ok_or_else(fb)?;
            loop {
                let chunk = {
                    let mut inner = self.inner.borrow_mut();
                    if inner.pos == inner.buf.len() {
                        return Ok(());
                    }
                    // One copy into the JS heap, then the cursor consumes all of
                    // it; bytes landing during the await are taken next round.
                    let chunk = Uint8Array::from(&inner.buf[inner.pos..]);
                    inner.pos = inner.buf.len();
                    chunk
                };
                target_write_js(&writer, chunk.as_ref()).await?;
            }
        }

        // ── Data (UDP / DNS): length-prefixed packets, unsealed responses ──
        if self.phase() == Phase::PlainUdp {
            loop {
                let pt = {
                    let mut inner = self.inner.borrow_mut();
                    if inner.pos == inner.buf.len() {
                        return Ok(());
                    }
                    let pt = inner.buf[inner.pos..].to_vec();
                    inner.pos = inner.buf.len();
                    pt
                };
                self.handle_udp_frames(ws, &pt).await?;
            }
        }

        Ok(())
    }

    /// Plaintext-mode connect: the same target/egress logic as `establish`, but
    /// the VLESS response and every following chunk flow unsealed.
    async fn establish_plain(
        &self,
        ws: &web_sys::WebSocket,
        command: Command,
        host: String,
        port: u16,
        egress: Egress,
        initial: Vec<u8>,
    ) -> Result<()> {
        match command {
            Command::Tcp => {
                #[cfg(feature = "perf-log")]
                let ct0 = crate::log::now_ms();
                let (conn, leftover, _path) = connect_target_observed(&host, port, &egress).await?;
                vlog!(
                    "plain connect: {host}:{port} via {_path} (~{:.0}ms), {} initial / {} leftover bytes",
                    crate::log::now_ms() - ct0,
                    initial.len(),
                    leftover.len()
                );
                let reader_t: ReadableStreamDefaultReader =
                    conn.readable().get_reader().dyn_into().map_err(|_| fb())?;
                let writer_t: WritableStreamDefaultWriter =
                    conn.writable().get_writer().map_err(|_| fb())?;

                // Header-remainder payload goes upstream first (order preserved).
                if !initial.is_empty() {
                    let chunk: JsValue = Uint8Array::from(&initial[..]).into();
                    target_write_js(&writer_t, &chunk).await?;
                }
                // VLESS response (+ proxy-handshake leftover) go down raw.
                ws.send_with_u8_array(&VLESS_RESPONSE).map_err(|_| fb())?;
                if !leftover.is_empty() {
                    ws.send_with_u8_array(&leftover).map_err(|_| fb())?;
                }

                // Background download loop: raw socket reads straight to ws.send.
                let ws_c: web_sys::WebSocket = ws.clone();
                spawn_local(async move {
                    let _ = plain_download(&reader_t, &ws_c).await;
                    let _ = ws_c.close();
                });

                let mut inner = self.inner.borrow_mut();
                inner.target_writer = Some(writer_t);
                inner.conn = Some(conn);
                inner.phase = Phase::PlainData;
                Ok(())
            }
            Command::Udp => {
                ws.send_with_u8_array(&VLESS_RESPONSE).map_err(|_| fb())?;
                {
                    let mut inner = self.inner.borrow_mut();
                    inner.udp_target = Some((host, port));
                    inner.phase = Phase::PlainUdp;
                }
                if !initial.is_empty() {
                    self.handle_udp_frames(ws, &initial).await?;
                }
                Ok(())
            }
            Command::Mux => Err(fb()),
        }
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
                let (conn, leftover, _path) = connect_target_observed(&host, port, &egress).await?;
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
    /// (stateless: a fresh socket per packet), responses sent back to the client —
    /// sealed records in encrypted mode, raw frames in plaintext mode (`key_w`
    /// is `None` there).
    async fn handle_udp_frames(&self, ws: &web_sys::WebSocket, pt: &[u8]) -> Result<()> {
        let (host, port) = match self.inner.borrow().udp_target.clone() {
            Some(t) => t,
            None => return Err(fb()),
        };
        let key_w = self.inner.borrow().key_w.clone();

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
                    match &key_w {
                        Some(key_w) => {
                            let mut nonce_w = self.inner.borrow().nonce_w;
                            let rec = seal_record_wasm(key_w, &mut nonce_w, &framed).await?;
                            self.inner.borrow_mut().nonce_w = nonce_w;
                            ws.send_with_u8_array(&rec).map_err(|_| fb())?;
                        }
                        None => {
                            ws.send_with_u8_array(&framed).map_err(|_| fb())?;
                        }
                    }
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
