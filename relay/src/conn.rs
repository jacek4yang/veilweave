// conn.rs
// A thin, safe wrapper around a Cloudflare `cloudflare:sockets` TCP connection.
//
// Why this exists instead of `worker::Socket`:
//   The zero-copy relay needs the *native* `ReadableStream`/`WritableStream` of
//   the TCP socket so it can `pipeTo` them directly (bytes never enter WASM
//   linear memory). `worker::Socket` keeps those streams private and the only
//   way to reach them through it is an unsound transmute that relies on
//   `repr(Rust)` field ordering. Building on `worker_sys::Socket` ourselves lets
//   us expose `readable()`/`writable()` with zero `unsafe` layout assumptions,
//   while still implementing `AsyncRead`/`AsyncWrite` so the SOCKS5/HTTP-CONNECT
//   handshakes can use the ergonomic tokio helpers.

use std::io::{Error as IoError, Result as IoResult};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::FutureExt;
use js_sys::{Boolean as JsBoolean, JsString, Number as JsNumber, Object as JsObject, Reflect, Uint8Array};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    ReadableStream, ReadableStreamDefaultReader, WritableStream, WritableStreamDefaultWriter,
};
use worker::Result;

#[derive(Default)]
enum Reading {
    #[default]
    None,
    Pending(JsFuture, ReadableStreamDefaultReader),
    Ready(Vec<u8>),
}

#[derive(Default)]
enum Writing {
    Pending(JsFuture, WritableStreamDefaultWriter, usize),
    #[default]
    None,
}

/// An outbound TCP connection plus tokio AsyncRead/AsyncWrite adapters.
pub struct Conn {
    inner: worker_sys::Socket,
    readable: ReadableStream,
    writable: WritableStream,
    read: Option<Reading>,
    write: Option<Writing>,
}

// Workers are single-threaded; the JS handles are never sent across threads.
unsafe impl Send for Conn {}
unsafe impl Sync for Conn {}

impl Conn {
    /// Open a plaintext TCP connection. TLS is intentionally never used here:
    /// for a VLESS proxy the *client* terminates TLS end-to-end through us, so
    /// our socket only carries already-encrypted bytes.
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        let address = JsObject::new();
        Reflect::set(&address, &JsValue::from_str("hostname"), &JsString::from(host).into())?;
        Reflect::set(&address, &JsValue::from_str("port"), &JsNumber::from(port as f64).into())?;

        let options = JsObject::new();
        Reflect::set(&options, &JsValue::from_str("allowHalfOpen"), &JsBoolean::from(false).into())?;
        Reflect::set(&options, &JsValue::from_str("secureTransport"), &JsString::from("off").into())?;

        let inner = worker_sys::connect(address.into(), options.into())?;
        let readable = inner.readable()?;
        let writable = inner.writable()?;
        Ok(Self {
            inner,
            readable,
            writable,
            read: Some(Reading::None),
            write: Some(Writing::None),
        })
    }

    /// Resolves once the TCP connection is established (or rejects on failure).
    pub async fn opened(&self) -> Result<()> {
        JsFuture::from(self.inner.opened()?).await?;
        Ok(())
    }

    /// Forcibly close both halves of the socket.
    pub async fn close(&self) -> Result<()> {
        JsFuture::from(self.inner.close()?).await?;
        Ok(())
    }

    /// Native readable side — feed this into `pipeTo` for zero-copy download.
    pub fn readable(&self) -> &ReadableStream {
        &self.readable
    }

    /// Native writable side — `pipeTo` destination for zero-copy upload.
    pub fn writable(&self) -> &WritableStream {
        &self.writable
    }

    /// Take any bytes that a handshake read pulled past what it needed.
    ///
    /// `AsyncRead` may buffer the tail of a stream chunk in WASM (`Reading::Ready`).
    /// Those bytes belong downstream (target→client) and would be lost once we
    /// hand the raw `readable` to `pipeTo`, so the caller must drain them first.
    pub fn take_buffered(&mut self) -> Vec<u8> {
        match self.read.take() {
            Some(Reading::Ready(v)) => {
                self.read = Some(Reading::None);
                v
            }
            other => {
                self.read = other;
                Vec::new()
            }
        }
    }
}

fn js_err(value: JsValue) -> IoError {
    let s = value
        .as_string()
        .or_else(|| value.dyn_ref::<js_sys::Error>().map(|e| e.to_string().into()))
        .unwrap_or_else(|| format!("{value:?}"));
    IoError::other(s)
}

// Writes as much as possible into `buf`, stashing the remainder for next poll.
fn handle_data(buf: &mut ReadBuf<'_>, mut data: Vec<u8>) -> (Reading, Poll<IoResult<()>>) {
    let idx = buf.remaining().min(data.len());
    let store = data.split_off(idx);
    buf.put_slice(&data);
    if store.is_empty() {
        (Reading::None, Poll::Ready(Ok(())))
    } else {
        (Reading::Ready(store), Poll::Ready(Ok(())))
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        fn handle_future(
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
            mut fut: JsFuture,
            reader: ReadableStreamDefaultReader,
        ) -> (Reading, Poll<IoResult<()>>) {
            match fut.poll_unpin(cx) {
                Poll::Pending => (Reading::Pending(fut, reader), Poll::Pending),
                Poll::Ready(res) => match res {
                    Ok(value) => {
                        reader.release_lock();
                        let done = match Reflect::get(&value, &JsValue::from_str("done")) {
                            Ok(v) => v.is_truthy(),
                            Err(e) => return (Reading::None, Poll::Ready(Err(js_err(e)))),
                        };
                        if done {
                            (Reading::None, Poll::Ready(Ok(())))
                        } else {
                            match Reflect::get(&value, &JsValue::from_str("value")) {
                                Ok(v) => handle_data(buf, Uint8Array::new(&v).to_vec()),
                                Err(e) => (Reading::None, Poll::Ready(Err(js_err(e)))),
                            }
                        }
                    }
                    Err(e) => (Reading::None, Poll::Ready(Err(js_err(e)))),
                },
            }
        }

        let (new_reading, poll) = match self.read.take().unwrap_or_default() {
            Reading::None => {
                let reader: ReadableStreamDefaultReader = match self.readable.get_reader().dyn_into() {
                    Ok(r) => r,
                    Err(e) => return Poll::Ready(Err(js_err(e.into()))),
                };
                handle_future(cx, buf, JsFuture::from(reader.read()), reader)
            }
            Reading::Pending(fut, reader) => handle_future(cx, buf, fut, reader),
            Reading::Ready(data) => handle_data(buf, data),
        };
        self.read = Some(new_reading);
        poll
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        fn handle_future(
            cx: &mut Context<'_>,
            mut fut: JsFuture,
            writer: WritableStreamDefaultWriter,
            len: usize,
        ) -> (Writing, Poll<IoResult<usize>>) {
            match fut.poll_unpin(cx) {
                Poll::Pending => (Writing::Pending(fut, writer, len), Poll::Pending),
                Poll::Ready(res) => {
                    writer.release_lock();
                    match res {
                        Ok(_) => (Writing::None, Poll::Ready(Ok(len))),
                        Err(e) => (Writing::None, Poll::Ready(Err(js_err(e)))),
                    }
                }
            }
        }

        let (new_writing, poll) = match self.write.take().unwrap_or_default() {
            Writing::None => {
                let chunk: JsValue = Uint8Array::from(buf).into();
                let writer = match self.writable.get_writer() {
                    Ok(w) => w,
                    Err(e) => return Poll::Ready(Err(js_err(e))),
                };
                handle_future(cx, JsFuture::from(writer.write_with_chunk(&chunk)), writer, buf.len())
            }
            Writing::Pending(fut, writer, len) => handle_future(cx, fut, writer, len),
        };
        self.write = Some(new_writing);
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        // Drive any in-flight write to completion; a fresh write needs no flush.
        let pending = matches!(self.write, Some(Writing::Pending(..)));
        if pending {
            match self.as_mut().poll_write(cx, &[]) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        // The relay closes the socket explicitly; nothing to do on shutdown.
        Poll::Ready(Ok(()))
    }
}
