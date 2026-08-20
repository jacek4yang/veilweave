// wsio.rs
// A byte-oriented reader over the bytes buffered for one `websocket_message`
// invocation, giving the VLESS Encryption handshake and record layer the
// `io.ReadFull` semantics the xray-core protocol assumes over a `net.Conn`.
//
// The encrypted data path runs entirely inside the `VeilweaveSession` Durable Object,
// where each inbound WS frame is delivered as a *separate* hibernatable
// invocation. The DO accumulates frame bytes in its own buffer and feeds a fully
// in-memory slice here, so this reader never touches a stream: `read_exact` either
// succeeds from the buffer or reports a clean short read (`false`), which the
// handshake treats as "need more frames" and retries on the next message.

use worker::Result;

pub struct WsReader {
    buf: Vec<u8>,
    pos: usize,
}

impl WsReader {
    /// A reader over a fully-buffered byte slice. Reads never await and run out of
    /// bytes (short read) once the buffer is consumed — the DO runs the handshake
    /// inside one message invocation against the bytes accumulated so far.
    pub fn from_buffer(buf: Vec<u8>) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    fn avail(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Fill `out` completely. Returns `Ok(true)` on success, `Ok(false)` if the
    /// buffer ended before `out.len()` bytes were available — a clean retry signal
    /// (the handshake performs no side effects until it holds the whole clientHello).
    pub async fn read_exact(&mut self, out: &mut [u8]) -> Result<bool> {
        if self.avail() < out.len() {
            return Ok(false);
        }
        let n = out.len();
        out.copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(true)
    }

    /// Unconsumed bytes already buffered past the handshake (the start of the
    /// encrypted data stream).
    pub fn leftover(self) -> Vec<u8> {
        self.buf[self.pos..].to_vec()
    }
}
