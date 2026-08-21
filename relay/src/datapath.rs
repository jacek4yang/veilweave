// datapath.rs
// JS-handle data-path helpers shared by the VeilweaveSession Durable Object. In
// encrypted mode the download direction (target → client) runs as one background
// loop that reads the target socket as JS `Uint8Array` frames, seals each
// ≤16384-byte record with WebCrypto AES-256-GCM (BoringSSL/AES-NI), and sends one
// `[header‖ciphertext]` WS frame per record — the same single-frame-per-record
// shape xray reads (never split a record across frames). Payload never enters
// wasm. The upload direction is handled per `websocket_message` in `session.rs`.
// Plaintext mode uses `plain_download` below: raw chunks straight to `ws.send`.
//
// The download loop is tuned for throughput close to the link limit while keeping
// the per-byte CPU low (it all runs in one background task, so it never adds WS
// invocations):
//   • Pipelined reads — the next `reader.read()` is started *before* the current
//     batch is encrypted and sent, so the target's read latency overlaps the
//     crypto + `ws.send` work instead of serializing behind it.
//   • Latency-free coalescing — small target chunks (the socket tends to hand us
//     ~4 KiB) that have *already arrived* are merged into one ≤16 KiB record before
//     sealing. This is done by polling the in-flight read with a no-op waker: it
//     never waits for more data (so interactive latency is preserved), and because
//     a `JsFuture` only yields an already-stored result (polling it cannot cancel
//     the underlying read), no chunk is lost. Fewer, larger records ⇒ up to ~4×
//     fewer WebCrypto calls, `ws.send`s and allocations.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use js_sys::Uint8Array;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{ReadableStreamDefaultReader, WritableStreamDefaultWriter};
use worker::{Error, Result};

use crate::enc::{next_nonce, put_header};
use crate::log::vlog;

#[inline(always)]
fn fb() -> Error {
    Error::RustError(String::new())
}

/// Throttle the download loops once the WS send buffer exceeds this.
const WS_SEND_HWM: u32 = 1 << 20; // 1 MiB

/// Max plaintext per download record, still **one record = one WS frame** (never
/// split a record across frames — that breaks the client's reassembly).
///
/// 16384 is safe: the client decodes any header length ≤ 16640 and `rawInput.Grow(l)`s
/// to it (`common.go`), buffering oversized plaintext in `c.input` — so a 16 KiB
/// record is read correctly even though xray's *own* writer caps at 8192.
const DL_RECORD: u32 = 16384;

/// Resolve after `ms` via the global `setTimeout`.
pub async fn sleep(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        match js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .and_then(|f| f.dyn_into::<js_sys::Function>())
        {
            Ok(set_timeout) => {
                let _ = set_timeout.call2(&global, &resolve, &JsValue::from_f64(ms as f64));
            }
            Err(_) => {
                let _ = resolve.call0(&JsValue::UNDEFINED);
            }
        }
    });
    let _ = JsFuture::from(promise).await;
}

/// Is a stream-read result `{done: true}`?
fn read_done(val: &JsValue) -> bool {
    js_sys::Reflect::get(val, &JsValue::from_str("done"))
        .map(|d| d.is_truthy())
        .unwrap_or(true)
}

/// Extract `result.value` (a non-done read) as a `Uint8Array`.
fn read_value(val: &JsValue) -> Result<Uint8Array> {
    let value = js_sys::Reflect::get(val, &JsValue::from_str("value")).map_err(|_| fb())?;
    Ok(Uint8Array::new(&value))
}

/// Merge coalesced read chunks into one contiguous JS buffer. The common
/// single-chunk batch returns that chunk's own view with **no copy**; only when
/// two or more already-buffered reads were merged do we pay one concatenation.
fn coalesce(mut parts: Vec<Uint8Array>, total: u32) -> Uint8Array {
    if parts.len() == 1 {
        return parts.pop().unwrap();
    }
    let buf = Uint8Array::new_with_length(total);
    let mut off = 0u32;
    for p in &parts {
        buf.set(p, off);
        off += p.length();
    }
    buf
}

/// Frame one record as `[5-byte header ‖ ciphertext]` and send it as a single WS
/// message — the exact shape xray reads. The 5 header bytes are written directly
/// into the framed buffer (no per-record temporary typed array).
fn send_record(ws: &web_sys::WebSocket, hdr: &[u8; 5], ct: &JsValue) -> Result<()> {
    let ct = Uint8Array::new(ct);
    let out = Uint8Array::new_with_length(5 + ct.length());
    for i in 0..5u32 {
        out.set_index(i, hdr[i as usize]);
    }
    out.set(&ct, 5);
    ws.send_with_array_buffer_view(&out).map_err(|_| fb())
}

/// Write one plaintext chunk (a JS buffer) to the target's writable side.
pub async fn target_write_js(writer: &WritableStreamDefaultWriter, chunk: &JsValue) -> Result<()> {
    JsFuture::from(writer.write_with_chunk(chunk))
        .await
        .map_err(|_| fb())?;
    Ok(())
}

/// Download loop: target readable → WebCrypto-encrypt into records → `ws.send`.
/// Pipelined (next read in flight during crypto+send) and coalescing (already-
/// arrived chunks merged into ≤16 KiB records). Runs until the target ends;
/// payload stays in JS, WS backpressure paces reads.
pub async fn relay_download(
    target_reader: &ReadableStreamDefaultReader,
    ws: &web_sys::WebSocket,
    key: &JsValue,
    mut nonce: [u8; 12],
) -> Result<()> {
    // Download accounting (perf-log only): records sealed, plaintext bytes, target
    // reads (reads-vs-records shows the coalescing factor), backpressure stalls.
    #[cfg(feature = "perf-log")]
    let (mut nrec, mut nbytes, mut nread, mut nstall) = (0u64, 0u64, 0u64, 0u64);
    #[cfg(feature = "perf-log")]
    let dl_t0 = crate::log::now_ms();

    // Keep exactly one read in flight at all times: start the next before encrypting
    // and sending the current batch.
    let mut inflight = JsFuture::from(target_reader.read());

    loop {
        // Block only on the read started last iteration.
        let val = (&mut inflight).await.map_err(|_| fb())?;
        if read_done(&val) {
            vlog!(
                "download: target EOF — {nrec} records / {nread} reads, {nbytes} \
                 plaintext bytes, {nstall} stalls over ~{:.0}ms",
                crate::log::now_ms() - dl_t0
            );
            return Ok(());
        }
        let first = read_value(&val)?;
        #[cfg(feature = "perf-log")]
        {
            nread += 1;
        }
        // Pipeline: kick off the next read immediately so it overlaps the work below.
        inflight = JsFuture::from(target_reader.read());

        // Coalesce every read that has ALREADY resolved (bytes sitting in the socket
        // queue) into this batch, up to DL_RECORD, without ever waiting. A no-op
        // waker poll returns `Pending` the instant no data is ready (latency is never
        // added), and polling a `JsFuture` only reads its stored result, so a pending
        // read is never cancelled / lost.
        let mut total = first.length();
        let mut parts: Vec<Uint8Array> = vec![first];
        let mut eof = false;
        while total < DL_RECORD {
            let mut cx = Context::from_waker(Waker::noop());
            match Pin::new(&mut inflight).poll(&mut cx) {
                Poll::Ready(r) => {
                    let v = r.map_err(|_| fb())?;
                    if read_done(&v) {
                        eof = true;
                        break;
                    }
                    let u = read_value(&v)?;
                    #[cfg(feature = "perf-log")]
                    {
                        nread += 1;
                    }
                    inflight = JsFuture::from(target_reader.read());
                    total += u.length();
                    parts.push(u);
                }
                Poll::Pending => break,
            }
        }
        #[cfg(feature = "perf-log")]
        {
            nbytes += total as u64;
        }

        // Seal the coalesced bytes into ≤DL_RECORD records, one WS frame each.
        let data = coalesce(parts, total);
        let len = data.length();
        let mut off = 0u32;
        while off < len {
            let n = (len - off).min(DL_RECORD);
            let sub = data.subarray(off, off + n);
            next_nonce(&mut nonce);
            let mut hdr = [0u8; 5];
            put_header(&mut hdr, n as usize + 16);
            let ct = crate::webcrypto::encrypt_view(key, &nonce, &hdr, sub.as_ref()).await?;
            send_record(ws, &hdr, &ct)?;
            off += n;
            #[cfg(feature = "perf-log")]
            {
                nrec += 1;
            }
        }

        if eof {
            vlog!(
                "download: target EOF — {nrec} records / {nread} reads, {nbytes} \
                 plaintext bytes, {nstall} stalls over ~{:.0}ms",
                crate::log::now_ms() - dl_t0
            );
            return Ok(());
        }

        // Throttle if the WS send buffer is backing up (rare — usually read-bound).
        while ws.ready_state() == web_sys::WebSocket::OPEN && ws.buffered_amount() > WS_SEND_HWM {
            #[cfg(feature = "perf-log")]
            {
                nstall += 1;
            }
            sleep(1).await;
        }
    }
}

/// Plaintext download loop (raw `SECRET_KEY` mode): target readable → `ws.send`
/// of each chunk as-is — no record framing, no crypto, so the per-byte cost is
/// the floor. Reads stay pipelined (the next `read()` is started before the
/// send, overlapping socket latency), and the same 1 MiB WS backpressure
/// throttle paces reads. Coalescing is deliberately skipped: every chunk goes
/// out the moment it arrives, keeping interactive latency at zero.
pub async fn plain_download(
    target_reader: &ReadableStreamDefaultReader,
    ws: &web_sys::WebSocket,
) -> Result<()> {
    #[cfg(feature = "perf-log")]
    let (mut nread, mut nbytes, mut nstall) = (0u64, 0u64, 0u64);
    #[cfg(feature = "perf-log")]
    let dl_t0 = crate::log::now_ms();

    // Keep exactly one read in flight at all times: start the next before
    // sending the current chunk.
    let mut inflight = JsFuture::from(target_reader.read());

    loop {
        let val = (&mut inflight).await.map_err(|_| fb())?;
        if read_done(&val) {
            vlog!(
                "plain download: target EOF — {nread} reads, {nbytes} bytes, \
                 {nstall} stalls over ~{:.0}ms",
                crate::log::now_ms() - dl_t0
            );
            return Ok(());
        }
        let chunk = read_value(&val)?;
        #[cfg(feature = "perf-log")]
        {
            nread += 1;
            nbytes += chunk.length() as u64;
        }
        // Pipeline: kick off the next read immediately so it overlaps the send.
        inflight = JsFuture::from(target_reader.read());

        ws.send_with_array_buffer_view(&chunk).map_err(|_| fb())?;

        // Throttle if the WS send buffer is backing up (same rule as encrypted).
        while ws.ready_state() == web_sys::WebSocket::OPEN && ws.buffered_amount() > WS_SEND_HWM {
            #[cfg(feature = "perf-log")]
            {
                nstall += 1;
            }
            sleep(1).await;
        }
    }
}
