# Architecture

This document covers the **data path** of veilweave at a level deeper than
the top-level README — what happens to a byte from the moment a WS upgrade
arrives at the edge until it lands on the target socket, and back.

## High-level pipeline

```
[client] ──►  CF edge (TLS)  ──►  [relay worker fetch]   (worker.ts)
                                          │
                                          ▼
                              [VeilweaveSession DO]     (Rust)
                              │   ① enc::server_handshake
                              │     · ML-KEM-768 encap
                              │     · X25519 DH × 2
                              │     · BLAKE3 derive_key × 4
                              │     · AES-256-GCM seal/open × N (handshake)
                              │     · self-test WebCrypto AES-GCM
                              │
                              │   ② vless::parse_vless_header
                              │     · signed-UUID decode (cached)
                              │     · pick egress from UUID type byte
                              │
                              │   ③ egress::connect_target
                              │     · Direct: cloudflare:sockets → host:port
                              │     · ProxyIp: direct-first, fallback to PIP
                              │     · Socks5/Http: handshake then tunnel
                              │
                              │   ④ send VLESS_RESPONSE[2] + proxy-leftover
                              │
                              ├─ background: datapath::relay_download
                              │   (target → encrypt → ws.send)
                              │
                              └─ on each websocket_message:
                                  decode records → egress.writable
```

## WebSocket Hibernation

The decisive free-plan optimization: every inbound WS frame is delivered
as **its own** `websocket_message` invocation with **its own 10 ms CPU
budget**. The post-quantum handshake and bulk upload crypto no longer
pile into a single capped `fetch`.

```rust
#[durable_object]
pub struct VeilweaveSession { state: State, env: Env, cfg: EncConfig, inner: RefCell<Inner> }

impl DurableObject for VeilweaveSession {
    async fn fetch(...) -> Response          // WS upgrade + accept_web_socket
    async fn websocket_message(ws, msg)      // 1 per inbound frame, 1 CPU budget
    async fn websocket_close(ws, ...)
    async fn websocket_error(ws, ...)
}
```

### Concurrency model

`websocket_message` may interleave at non-storage await points. The DO
guards this with a `pumping: bool` flag inside `RefCell<Inner>`:

- exactly one invocation becomes the "pump";
- others append to the inbound buffer and return immediately;
- the pump loops, draining everything in arrival order, until no further
  complete record is buffered.

`RefCell` borrows are never held across an `await` — only short sync
sections.

## Handshake (ML-KEM-768 + X25519)

The relay implements **xray-core's `mlkem768x25519plus` profile**, byte-for-byte
interoperable. The single-flow handshake (a server handshake) consists of:

| Step | Bytes (client→server)                          | Action |
|------|------------------------------------------------|--------|
| 1    | `iv(16) ‖ client_nfs_pub_x25519(32)`            | NFS X25519 DH with server's `nfs_secret` |
| 2    | `sealed_length(18)`                             | AES-GCM open → length of next blob |
| 3    | `sealed_pfs_pub = mlkem_ek(1184) ‖ x25519_pub(32)` | the client's PFS public |
| 4    | `sealed_padding`                                | length + body (discarded) |
| 5    | (server sends) `sealed_pfs_pub ‖ sealed_ticket ‖ sealed_padding` | ML-KEM encap + eph X25519 + ticket + pad |

The server emits its response in **one shot** — no fragmentation gaps.

After the handshake:

- `key_w = BLAKE3.derive_key(pfs_pub_server, pfs_key ‖ nfs_key)` — download (server→client)
- `key_r = BLAKE3.derive_key(pfs_pub_client, pfs_key ‖ nfs_key)` — upload (client→server)
- nonces: `nonce_w = 4` (used 1,2,3 for ticket/padding), `nonce_r = 1` (unused)

The keys are imported into WebCrypto as non-extractable AES-GCM `CryptoKey`s.
From this point on, **the bulk record path stays in the V8 heap**.

## Signed UUID

The 16-byte VLESS UUID is the user's identity token AND carries the egress:

```
[4 bytes nonce] [7 bytes ciphertext] [5 bytes MAC]
                    ciphertext = type_byte | ipv4(4) | port(2)  encrypted
                    MAC        = HMAC-SHA256(derived_k_mac, nonce ‖ ciphertext)[:5]
```

Derivation (per `SECRET_KEY`):

```
master = SECRET_KEY
prk    = HKDF-Extract("signed-uuid-hkdf-salt-v1-20250629", master)
k_enc  = HKDF-Expand(prk, "uuid-enc-v1")
k_mac  = HKDF-Expand(prk, "uuid-mac-v1")
keystream = HMAC-SHA256(k_enc, nonce ‖ 0x00)        // counter = 0
plaintext = ciphertext � keystream[:7]
mac       = HMAC-SHA256(k_mac, nonce ‖ ciphertext)[:5]   // constant-time compare
```

Egress mapping (in `vless::build_egress`):

| `type_byte` | egress   |
|-------------|----------|
| `0x00`      | Direct   |
| `0x01`      | ProxyIp  |
| `0x02`      | SOCKS5   |
| `0x03`      | HTTP-CONNECT |

### Two-layer per-isolate cache

```
Layer A: UuidCodec  = OnceCell<UuidCodec>   derived once from SECRET_KEY
Layer B: DecodeCache = LRU 16 entries       verified UUIDs only
```

A cache hit short-circuits to a 16-byte compare. Forged UUIDs always
take the full path — no validity timing oracle is added because the
cache is only inserted after a successful MAC verify.

## Bulk record path

Each record on the wire is one **WS binary frame**:

```
[5-byte TLS-record header] [AES-GCM ciphertext] [16-byte GCM tag]
```

Header layout (5 bytes):

```
byte 0 : 0x17
byte 1 : 0x03
byte 2 : 0x03
byte 3 : length high
byte 4 : length low   (length is ciphertext_len + tag_len = plaintext_len + 16)
```

Allowed `length`: 17..=16640 (so plaintext up to 16624 bytes; the relay
defaults to 16384 for downloads).

### Upload (client→server→target)

- A single `websocket_message` carries ≥0 records.
- The pump frames them out of `inner.buf` at a read cursor (`pos`); one
  `Uint8Array` per body.
- Each body goes through `crypto.subtle.decrypt` directly — the bytes
  never enter wasm linear memory.
- The plaintext is then written to the target's `writable` via
  `target_write_js`.

### Download (target→client)

A single background loop in `datapath::relay_download` owns the
write nonce and the WS:

1. Keep exactly one `target.readable.read()` in flight.
2. When it resolves, kick off the **next** read immediately (pipeline).
3. Coalesce already-arrived chunks (polled with a no-op waker that never
   waits) into one ≤16 KiB batch.
4. Seal the batch into one record per ≤16 KiB slice via
   `crypto.subtle.encrypt`.
5. Send each record as **one** `ws.send` (header + ciphertext in a single
   `ArrayBuffer` view).
6. Throttle on `ws.bufferedAmount() > 1 MiB` to apply backpressure.

The result: 4× fewer `crypto.subtle` calls, `ws.send` calls, and
allocations, compared to "1 record per read".

## WebCrypto offload

`crypto.subtle.encrypt`/`decrypt` run in BoringSSL/C++ with AES-NI. The
relay binds the `subtle` object and its method functions **once per
isolate** (`webcrypto::Ctx`):

- `crypto.subtle.encrypt`
- `crypto.subtle.decrypt`
- `crypto.subtle.importKey`
- constant `JsValue`s for `"name"`, `"iv"`, `"additionalData"`,
  `"tagLength"`, `"AES-GCM"`, `128.0`.

A one-time per-isolate self-test gates the fast path: it seals a known
plaintext with WebCrypto and byte-compares against the RustCrypto
reference, then round-trips. A failure is fatal for the data path
(returned by `aes_gcm_usable()`); the worker returns 500.

## Per-connection state

`VeilweaveSession::Inner` (in `RefCell<Inner>`) is **in-memory only** —
no storage I/O. The fields:

```rust
struct Inner {
    phase: Phase,                     // Handshake | Header | Data | Udp | Closed
    buf: Vec<u8>,                     // inbound ciphertext
    pos: usize,                       // read cursor into `buf`
    pumping: bool,                    // true while a pump is draining
    key_w: Option<JsValue>,           // download AES-GCM key
    key_r: Option<JsValue>,           // upload   AES-GCM key
    nonce_w: [u8; 12],
    nonce_r: [u8; 12],
    acc_header: Vec<u8>,              // decrypted VLESS header accumulator
    target_writer: Option<WritableStreamDefaultWriter>,
    conn: Option<Conn>,               // cloudflare:sockets TCP
    udp_target: Option<(String, u16)>,
}
```

The open target socket keeps the DO warm; an idle (no in-flight WS or
target) DO will hibernate. The `new_sqlite_classes` migration is just
what the free plan requires for DOs — it's never used.

## Egress

`egress::connect_target` returns `(Conn, Vec<u8>, &'static str)` —
the connection, any bytes the proxy handshake already buffered
downstream (must be sealed back to the client first), and a path label
for `perf-log`.

| Type       | Behavior |
|------------|----------|
| `Direct`   | `cloudflare:sockets.connect(host, port)` |
| `ProxyIp`  | Direct first; on failure, dial `pip_host:pip_port` |
| `Socks5`   | SOCKS5 handshake (RFC 1928) then tunnel |
| `Http`     | HTTP CONNECT then tunnel |

## UDP (DNS) path

When the VLESS command byte is `0x02` (`Udp`):

- DO enters `Phase::Udp`, records `(host, port)` in `udp_target`.
- Each record body is a sequence of `(u16 len, payload)` packets.
- Per packet: open a fresh `cloudflare:sockets` UDP-ish TCP socket, write
  payload, read response, seal back. (Cloudflare's `cloudflare:sockets`
  is TCP-only; UDP "sockets" are emulated by short-lived TCP connect
  with `Connection: close`, the standard VLESS UDP-over-TCP hack.)

## Constants reference

| Where | Constant | Value | Why |
|-------|----------|-------|-----|
| `enc.rs` | `MLKEM_EK` | 1184 | ML-KEM-768 encapsulation key |
| `enc.rs` | `MLKEM_CT` | 1088 | ML-KEM-768 ciphertext |
| `enc.rs` | `MLKEM_SS` | 32 | ML-KEM-768 shared secret |
| `enc.rs` | `MAX_NONCE` | `0xFF..FF` | xray seals PFS pub at MaxNonce |
| `datapath.rs` | `DL_RECORD` | 16384 | per-record plaintext cap |
| `datapath.rs` | `WS_SEND_HWM` | 1 MiB | backpressure threshold |
| `vless.rs` | `DECODE_CACHE_CAP` | 16 | LRU size |

## Why there's no KV on the data path

KV reads are **eventually consistent and ~1–10 ms** — orders of
magnitude slower than the operations they could replace here:

- UUID decode is a 16-byte compare in the LRU. A KV read would replace
  a sub-microsecond compare with a multi-ms network round-trip on the
  connection's critical path.
- The codec / X25519 config is derived once per isolate.
- The handshake is per-connection PFS — its expensive part (ML-KEM-768)
  produces fresh ephemeral key material; caching would break forward
  secrecy.

The only legitimate use of KV is **0-RTT session resumption** (an xray
ticket store shared across isolates), which is deliberately out of
scope: it changes the profile from `1rtt` to `0rtt`, weakens forward
secrecy, and adds replay surface.

## Build profile

`Cargo.toml` uses two opt-levels:

```toml
[profile.release]
opt-level = "z"     # our own code — keep wasm small
lto = true
codegen-units = 1
panic = "abort"
strip = true

[profile.release.package."*"]
opt-level = 3       # deps — buttersmooth handshake
```

`wasm-opt` is configured for `-O2` and `--enable-simd` to leverage
the target's SIMD128.

See [`relay/.cargo/config.toml`](../relay/.cargo/config.toml) for the
target-feature flags (`+simd128` etc.) and the `blake3` `wasm32_simd`
feature for vectorized BLAKE3.
