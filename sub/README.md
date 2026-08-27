# Veilweave subscription Worker

The Sub Worker turns a relay topology and the automatic proxyIP dataset into
short-lived, signed VLESS URI lists. Its normal `/sub` path performs one compact
KV read plus bounded selection/rendering; it never downloads or parses the
multi-megabyte source document on a user request.

## Automatic proxyIP pipeline

`https://zip.cm.edu.kg/all.json` is the sole authoritative proxyIP source.
`PROXYIP_LIST` and manual proxyIP maintenance are not supported.

1. A Cron Trigger runs every six hours (`17 */6 * * *`). Deployment and update
   configure that schedule automatically.
2. The scheduled handler delegates to the singleton SQLite Durable Object
   `ProxyIpRefresher`. This serializes refreshes and gives the large parse the
   Durable Object CPU allowance instead of the Free-plan HTTP/Cron 10 ms limit.
3. Fetching has a 30-second timeout, a 20 MiB body limit, redirect rejection,
   HTTP status checks, ETag support, and bounded streaming.
4. Records are parsed tolerantly. Invalid records, unusable IPv4 ranges, port
   zero, and unsupported ports are discarded. Host/port pairs are deduplicated
   with deterministic country conflict resolution.
5. Only the fields needed at render time are stored. Data is grouped by country
   and capped at 8,192 entries globally and 256 per country.
6. A candidate must pass structural and anti-catastrophic-drop checks before it
   becomes `proxyip:active:v2`. The prior generation remains at
   `proxyip:previous:v2`; a failed refresh records a bounded diagnostic and does
   not replace known-good data.

A fresh deployment explicitly triggers the refresher and will not be reported
healthy unless a valid dataset and a structurally valid subscription exist.
If neither active nor previous data is usable, `/sub` returns HTTP 503 instead
of inventing a zero UUID or fake node.

## Subscription API

```text
GET /sub?token=<subscription-token>[&format=raw|base64]
        [&secure=true|false][&country=JP]
        [&filter=JP,US]
```

The stable default is `format=raw` and `secure=true`.

- `format=raw`: newline-delimited `vless://` URIs.
- `format=base64`: standard Base64 of that complete newline-delimited list.
- `country` (alias `cc`): one case-insensitive two-letter ISO-style code.
- `filter`: a proxyIP egress-country set. Commas, spaces, and `+` are accepted;
  case is normalized and duplicates are removed. `country` and `filter` cannot
  be combined.
- `secure=true`: relay entry port 443, TLS, matching SNI, and certificate
  validation required.
- `secure=false`: relay entry port 80 without outer TLS.

Successful responses are `text/plain; charset=utf-8`, `private, no-store`, and
include `X-Veilweave-Format`, `X-Node-Count`, `X-ProxyIP-Revision`,
`X-ProxyIP-Stale`, and `Profile-Update-Interval: 6`. Final rendered bodies are
not cached, so format, security, country, topology, nonce, ECH, and dataset
generations cannot cross-contaminate one another.

An invalid or missing token gets the same generic HTTP 404 as an unknown route.
The token is never logged. Client parameter errors use HTTP 400; missing
known-good data or topology uses HTTP 503 with a small non-secret message.

## Node generation

Each selected proxyIP entry gets a fresh four-byte nonce from WebCrypto and a
`TYPE_PROXYIP` signed UUID containing its IPv4 address and port. With multiple
relays, entries are distributed round-robin and every UUID is signed with the
secret belonging to the relay named in that URI. The normal maximum is 100 and
the enforced configurable range is 1 through 200.

Carrier-optimized Cloudflare entry addresses are only an optional front-door
optimization. Their refresh/load failure falls back to the relay hostname and
does not affect proxy correctness or proxyIP cache promotion.

ECH is disabled by default. Setting the optional `ECH` variable adds a
percent-encoded `ech=` URI parameter; operators must confirm that their client
understands the configured value. No DoH/ECH provider is forced.

## Authenticated management

The control plane uses Bearer authentication for these non-public endpoints:

- `GET /_veilweave/proxyip/status`
- `POST /_veilweave/proxyip/refresh`

Users normally invoke them without handling the token directly:

```bash
veilweave-tools proxyip status --deployment <sub-uuid> --json
veilweave-tools proxyip refresh --deployment <sub-uuid> --json
```

Status reports the source, revision, age, validation/stale state, accepted,
rejected, stored and country counts, plus the last bounded failure diagnostic.

## Wrangler reference

`wrangler.example.toml` documents the bindings needed for a manual build:

- KV namespace plus `KV_BINDING`
- `PROXYIP_REFRESHER` SQLite Durable Object and migration
- six-hour Cron Trigger
- secrets `VEILWEAVE_NODES` and `SUBSCRIPTION_TOKEN`
- optional `MAX_NODES`, `FP`, `ALPN`, and `ECH`

The direct deployer creates all of these automatically. Do not put secret
values in TOML.

## Validation

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets --target wasm32-unknown-unknown -- -D warnings
worker-build --release
```

The live-source parser test is ignored by default because it requires the
downloaded fixture:

```bash
VEILWEAVE_ALL_JSON_FIXTURE=/path/to/all.json \
  cargo test live_authoritative_fixture_is_bounded -- --ignored
```
