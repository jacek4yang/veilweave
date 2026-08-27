# Veilweave

Veilweave is a Cloudflare Workers VLESS-over-WebSocket relay with an automatic
subscription plane, a shared Rust control plane, a desktop app, and a CLI. Its
production path is designed to be proven end to end:

```text
Cloudflare deployment
  -> automatic proxyIP preparation
  -> valid subscription
  -> Xray VLESS/WebSocket client
  -> relay Durable Object
  -> real HTTPS traffic
```

Compilation, a successful upload, or an Apache camouflage page alone is not
treated as proof that the proxy works.

## Components

- `relay/`: Cloudflare Worker and hibernatable `VeilweaveSession` Durable
  Object for VLESS/WebSocket, signed capability validation, sockets, and
  direct/proxyIP/SOCKS5/HTTP egress.
- `sub/`: subscription Worker, serialized `ProxyIpRefresher` Durable Object,
  compact KV cache, and fresh VLESS URI rendering.
- `core/`: canonical bundles, Cloudflare API, transactions, role-aware health,
  credentials, recovery, and shared network policy.
- `tools/`: CLI deployer, lifecycle/diagnostic commands, standalone protocol
  utilities, and bundle tooling.
- `app/`: Tauri desktop adapter over the same core.

## Quick deployment

Download a release and run the desktop app or CLI; end users do not need Rust,
Node.js, Wrangler, or source code.

```bash
# Interactive
veilweave-tools deploy

# Secret-free declarative topology
veilweave-tools plan --config veilweave.toml --bundle-dir bundle
veilweave-tools apply --config veilweave.toml --bundle-dir bundle --yes
```

Each Worker can use Workers.dev, one exact Custom Domain, or both, with an
explicit primary endpoint. A topology may distribute relays across accounts
and gives every relay an independent secret. The Sub Worker signs each URI with
the secret for the relay named in that URI.

Secrets are stored in the OS credential manager (or explicit environment
references for headless use) and deployed as Cloudflare secret bindings.
Declarative `apply` and JSON output never print bearer subscription URLs; the
desktop/interactive `manage` action reveals one only on explicit request.

## Automatic proxyIP architecture

The sole authoritative proxyIP source is:

```text
https://zip.cm.edu.kg/all.json
```

Users do not configure or maintain proxyIP lists. `PROXYIP_LIST` is not an
active production path.

The source document can be many MiB, so it is never fetched or parsed by the
user-facing `/sub` route. A six-hour Cron Trigger delegates to one named SQLite
Durable Object. That object serializes refreshes, bounds fetch time/body size,
parses malformed records tolerantly, rejects unusable IPv4/ports, deduplicates,
groups/caps by country, and validates a candidate before promotion.

KV stores compact active and previous known-good generations plus a bounded
last-failure diagnostic. A failed/empty/corrupt/suspicious update cannot replace
working data. Normal subscription requests perform one compact KV read and
small selection/rendering. A fresh deploy explicitly bootstraps and will not be
reported healthy without usable data and structurally valid nodes.

```bash
veilweave-tools proxyip status --deployment <sub-uuid>
veilweave-tools proxyip refresh --deployment <sub-uuid>
```

## Subscription contract

```text
GET /sub?token=<token>&format=raw&secure=true
```

- `format=raw` (stable default): newline-delimited `vless://` URIs.
- `format=base64`: standard Base64 of the complete raw list.
- `country=JP`/`cc=JP`: select one proxyIP egress country.
- `filter=JP,US`: select a normalized country set; commas, spaces, and plus
  separators are accepted.
- `secure=true` (default): TLS/443 with matching SNI and certificate checks.
- `secure=false`: plain WebSocket/80.

Responses are private/no-store and include format, node count, update interval,
and proxyIP revision/stale headers. Rendered bodies are not cached, so security,
format, filter, topology, ECH, dataset revision, and fresh nonces cannot share a
stale rendered-cache key. No usable data/topology returns HTTP 503—not a zero
UUID or fake node. Invalid/missing tokens and unknown routes share generic 404.

`MAX_NODES` defaults to 100 and is consistently bounded from 1 through 200.
Carrier-optimized Cloudflare entry IPs are optional; their failure falls back
to the relay hostname. ECH is disabled by default and is emitted only when an
operator supplies an explicit client-compatible value.

## Protocol and security

The default raw secret uses `encryption=none`. Outer TLS terminates at
Cloudflare; Cloudflare can observe the VLESS target and payload after
termination. The signed UUID authenticates and carries egress—it does not
provide end-to-end payload encryption.

Experimental `VW1` secret pairs enable Xray's
`mlkem768x25519plus.native.1rtt` VLESS Encryption inside WebSocket
(ML-KEM-768 + X25519, BLAKE3, WebCrypto AES-256-GCM). It is off by default
because of client and Cloudflare Free CPU costs.

Signed capability v1 stays exactly 16 bytes:

```text
4-byte CSPRNG nonce | 7-byte encrypted payload | 5-byte truncated HMAC
```

The 32-bit nonce has birthday collisions around 2^16 generated UUIDs per key,
and the MAC has about 40-bit online-forgery strength. These limits are
documented rather than hidden. A stronger scheme requires an explicit protocol
v2; Veilweave does not silently reinterpret the deployed v1 format.

## Client compatibility

The protected live gate tests raw VLESS URI import and real proxied traffic
with the pinned official Xray-core 25.6.8 binary. Standard Base64 output is also
decoded and structurally validated.

v2rayN often uses an Xray core, but its own subscription import is not tested
separately. sing-box, NekoBox/NekoRay, and mihomo differ in URI-list and
experimental parameter handling; they are considered structurally, not claimed
live-compatible. Use raw `encryption=none` with ECH off for the broadest base
compatibility and test the exact client/version you intend to deploy.

## Lifecycle and diagnostics

```bash
veilweave-tools status --json
veilweave-tools doctor --json
veilweave-tools proxy test --json
veilweave-tools update --deployment <uuid> --bundle-dir bundle
veilweave-tools rollback --deployment <uuid>
veilweave-tools rotate-token --deployment <sub-uuid> --bundle-dir bundle
veilweave-tools delete --deployment <uuid>
veilweave-tools recover --account <label-or-id>
```

Updates inherit secret bindings and restore the previous Worker and Sub Cron
schedules when health fails. Custom Domain readiness uses policy-aware HTTPS,
not direct UDP DNS that could bypass SOCKS5H/HTTP proxy policy. Explicit control
plane proxies fail closed.

Deletion promotes Cloudflare's explicit Durable Object `deleted` export before
removing the Worker; Sub deletion also removes KV. This prevents orphaned
Durable Object namespaces.

## Build and local checks

There is deliberately no top-level Cargo workspace because Worker crates target
WASM while core/tools/app are native. Run commands per crate:

```bash
cargo fmt --manifest-path core/Cargo.toml -- --check
cargo test --manifest-path core/Cargo.toml
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings

cargo test --manifest-path relay/Cargo.toml
cargo check --manifest-path relay/Cargo.toml --target wasm32-unknown-unknown
cargo clippy --manifest-path relay/Cargo.toml --target wasm32-unknown-unknown -- -D warnings

cargo test --manifest-path sub/Cargo.toml
cargo check --manifest-path sub/Cargo.toml --target wasm32-unknown-unknown
cargo clippy --manifest-path sub/Cargo.toml --target wasm32-unknown-unknown -- -D warnings

cargo test --manifest-path tools/Cargo.toml
cargo clippy --manifest-path tools/Cargo.toml --all-targets -- -D warnings

(cd relay && worker-build --release)
(cd sub && worker-build --release)
```

Canonical bundles are manifest-backed, role-specific, SHA-256 validated, and
reject unknown/stale modules or build metadata such as `package.json`.

## Live E2E and release gate

`.github/workflows/cloudflare-smoke.yml` runs only with credentials in the
protected `cloudflare-smoke` GitHub Environment. It creates unique disposable
resources, tests bootstrap/cold/warm/raw/Base64/filter/security/update/rollback,
starts checksum-pinned Xray, and performs HTTPS through SOCKS to both an
ordinary domain and a Cloudflare-hosted target (the proxyIP fallback case).
Cleanup verifies Workers, KV, and Durable Object namespace removal.

The Environment must define `CLOUDFLARE_API_TOKEN`,
`CLOUDFLARE_ACCOUNT_ID`, and `CLOUDFLARE_WORKERS_SUBDOMAIN`. Custom-hostname
runs also require `CLOUDFLARE_TEST_ZONE_ID` and `CLOUDFLARE_TEST_ZONE_NAME`.
The workflow fails before installing build dependencies when any required name
is absent.

The Release workflow calls this E2E first. It packages the exact canonical
Worker bundles uploaded by the passing E2E job, then builds CLI/desktop assets,
signed updater metadata, SHA-256 sums, and an SBOM. Compile-only artifacts cannot
bypass the live runtime gate.

## Documentation

- [Production deployment](docs/deployment.md)
- [Architecture](docs/architecture.md)
- [Protocol](docs/protocol.md)
- [Security model](docs/security-v2.md)
- [Control plane](docs/control-plane-v2.md)
- [Declarative configuration](docs/declarative-config.md)
- [Migration](docs/migration-v2.md)
- [Release gates](docs/release-v2.md)
- [Relay Worker](relay/README.md)
- [Subscription Worker](sub/README.md)
- [CLI](tools/README.md)
- [Desktop app](app/README.md)

## Legal and security reports

Veilweave is a network proxy/tunnel relay. Use it in compliance with applicable
law and service terms. See [SECURITY.md](SECURITY.md) for private vulnerability
reporting; do not disclose security-sensitive issues in public tickets.

Licensed under [MIT](LICENSE).
