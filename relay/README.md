# Veilweave relay Worker

The relay terminates VLESS over WebSocket at Cloudflare, validates the signed
UUID capability, opens the selected egress, and forwards bytes in a hibernatable
SQLite Durable Object (`VeilweaveSession`). Non-WebSocket requests receive the
static Apache-style camouflage page, which is only camouflage and endpoint
reachability—not a proxy health proof.

## Modes

The compatibility/default `SECRET_KEY` is a random raw string. It seeds UUID
validation and uses `encryption=none`: outer TLS ends at Cloudflare and the
VLESS/payload bytes pass through after authentication.

An experimental `VW1` relay blob additionally enables Xray-core's
`mlkem768x25519plus.native.1rtt` record layer: ML-KEM-768 plus X25519,
BLAKE3-derived keys, and WebCrypto AES-256-GCM. This is opt-in because handshake
and record CPU can exceed Cloudflare Free limits. It does not change the
16-byte signed UUID v1 format.

## Signed egress selection

The relay accepts only a valid 16-byte signed UUID under its own secret. The
decoded type byte selects:

- `0x00` Direct
- `0x01` ProxyIP: try the requested target directly, then connect to the
  encoded IPv4/port when Cloudflare rejects the direct socket
- `0x02` SOCKS5
- `0x03` HTTP CONNECT

Unknown types, bad/truncated MACs, wrong relay secrets, invalid encoded ports,
Mux, and malformed VLESS addresses are rejected. A UUID created for relay A is
not valid for relay B.

The automatic Sub Worker always generates `TYPE_PROXYIP` nodes from the compact
`https://zip.cm.edu.kg/all.json` cache. Cloudflare-hosted destinations exercise
the proxyIP fallback; ordinary Internet destinations normally take the direct
fast path. Target hostnames themselves support IPv4, IPv6, and domain forms,
while the compact egress capability remains IPv4 by the deployed wire format.

## State machine

`lib.rs` accepts the WebSocket and routes it to one named session object.
`session.rs` maintains ordered phases across hibernatable
`websocket_message` invocations. Concurrent events append to one buffer; a
single pump owns parsing/writes so upload order cannot interleave across await
points. The plaintext parser waits for fragmented headers and preserves payload
bytes delivered in the same frame as the completed header.

After connection, `datapath.rs` owns target-to-WebSocket forwarding and
`wsio.rs`/the session pump own the reverse direction. Target failure, protocol
failure, client close/error, and target EOF close the corresponding state
without converting an invalid capability to Direct.

TCP is the production-proven path. UDP uses the project's framed DNS-oriented
handling; Mux and 0-RTT are not advertised or accepted. See
`../docs/protocol.md` for exact bytes and limitations.

## Observability

Default builds keep the high-volume `perf-log` feature off. Safe operational
errors categorize protocol rejection and target/egress connection failure
without logging a UUID, relay secret, subscription token, target payload, or
private key. A temporary diagnostic build can enable structured performance
logs:

```bash
worker-build --release --features perf-log
wrangler deploy
wrangler tail
```

Do not leave that mirror deployed longer than needed. Camouflage HTTP 200 is
not acceptance; the protected E2E uses pinned Xray-core and verifies real HTTPS
through the VLESS/WebSocket/Durable Object/socket path, including a
Cloudflare-hosted proxyIP-fallback destination.

## Build and validation

```bash
cargo fmt -- --check
cargo test
cargo check --target wasm32-unknown-unknown
cargo clippy --all-targets --target wasm32-unknown-unknown -- -D warnings
worker-build --release
```

Regression tests cover the canonical signed-UUID vector, canonical UUID text
parsing, wrong secret and modified-MAC rejection, fragmented VLESS headers,
initial upload preservation, decoded proxyIP egress, and rejection of Mux,
unknown egress types, and invalid addresses.

Production deletion must use the Veilweave control plane so it promotes the
Durable Object deletion tombstone before removing the Worker script.
