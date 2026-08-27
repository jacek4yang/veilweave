# Production deployment

Veilweave deploys a relay Worker, a subscription Worker, one KV namespace, two
SQLite Durable Object classes, Workers.dev/custom endpoints, and a six-hour
Cron Trigger through the Cloudflare API. The desktop app and CLI use the same
control-plane implementation and canonical Worker bundles.

## Cloudflare token

Use a dedicated account-scoped token with the narrowest permissions your
topology needs:

- Workers Scripts: Edit
- Workers KV Storage: Edit
- Account Settings: Read (workers.dev discovery)
- Workers Custom Domains and Zone/DNS permissions only when using a Custom
  Domain
- Account Analytics: Read only for the optional dashboard

Keep the token in the OS credential manager or an explicit environment-backed
credential reference for headless automation. Never put it in TOML, logs, or a
command-line URL.

## Recommended deploy

Download a release and run the desktop app, or use the interactive CLI:

```bash
veilweave-tools deploy
```

For a reviewable, secret-free topology:

```bash
veilweave-tools plan --config veilweave.toml --bundle-dir bundle
veilweave-tools apply --config veilweave.toml --bundle-dir bundle --yes
veilweave-tools status --json
```

`apply` stores generated relay, node, and subscription credentials in the OS
credential manager. Automation output is deliberately redacted; use the
interactive `manage` action when a human explicitly needs to reveal a
subscription URL.

The deployment is transactional. It creates inert versions, promotes explicit
100% deployments, configures the Sub Cron Trigger, waits for the selected
endpoint, triggers first proxyIP preparation, and structurally verifies the
subscription. A 404, 403, HTML page, empty list, malformed Base64, zero UUID,
or invalid VLESS/WebSocket/TLS field fails health verification and rolls back.
A relay camouflage GET is recorded only as endpoint reachability, not as proof
that proxy traffic works.

## Automatic proxyIP bootstrap and refresh

The only authoritative proxyIP source is:

```text
https://zip.cm.edu.kg/all.json
```

There is no supported `PROXYIP_LIST` production path and users do not maintain
addresses manually.

The first deployment calls the authenticated refresher and refuses to report a
healthy Sub Worker without a valid compact generation. Later refreshes run on
`17 */6 * * *`. A named `ProxyIpRefresher` Durable Object serializes refreshes,
fetches with timeout/size/redirect/status controls, parses records tolerantly,
filters unusable addresses and ports, deduplicates host/port pairs, groups by
country, and applies promotion sanity checks. KV contains only the bounded
active generation, previous known-good generation, and last failure status.

Normal `/sub` requests perform one compact KV read and bounded rendering. They
never download the large source. A source outage records a non-secret failure
and keeps serving known-good data; no usable generation results in HTTP 503,
never a fake node.

Management commands:

```bash
veilweave-tools proxyip status --deployment <sub-uuid>
veilweave-tools proxyip refresh --deployment <sub-uuid>
```

## Subscription contract

```text
https://<sub-host>/sub?token=<token>&format=raw&secure=true
```

- `format=raw` (default): newline-delimited VLESS URIs.
- `format=base64`: standard Base64 of the complete raw list.
- `country=JP` or `cc=JP`: one egress country.
- `filter=JP,US`: a normalized multi-country egress set; commas, spaces and
  plus separators are accepted.
- `secure=true` (default): TLS/443 with SNI and certificate validation.
- `secure=false`: plain WebSocket/80.

ECH is disabled by default. An explicit `sub.settings.ech` value is emitted
only for operators who have verified compatible clients. `MAX_NODES` defaults
to 100 and is consistently limited to 1 through 200.

Invalid/missing subscription tokens and unknown routes return the same generic
404. Successful output is private/no-store and includes format, node-count,
dataset-revision/stale, and update-interval headers.

## Runtime verification

Camouflage reachability is not a data-plane test. A real proof requires:

1. fetch the authorized subscription and validate all nodes;
2. import one generated URI into a compatible Xray-core version;
3. expose a local SOCKS inbound;
4. request an ordinary HTTPS domain through SOCKS;
5. request a Cloudflare-hosted domain through SOCKS to exercise the encoded
   proxyIP fallback.

The protected GitHub E2E workflow performs that sequence with Xray-core 25.6.8
whose Linux archive SHA-256 is pinned. It also destroys/restores the compact
cache, tests cold and warm paths, invalid-token indistinguishability, raw and
Base64 formats, secure-mode separation, country/filter behavior, update and
rollback, and verifies cleanup of Workers, KV, and Durable Object namespaces.

## Updates, rollback, rotation, and deletion

```bash
veilweave-tools update --deployment <uuid> --bundle-dir bundle
veilweave-tools rollback --deployment <uuid>
veilweave-tools rotate-token --deployment <sub-uuid> --bundle-dir bundle
veilweave-tools delete --deployment <uuid>
```

Updates inherit deployed secrets, promote a new version, restore the previous
Worker and Cron schedule on failed health verification, and persist stable and
previous IDs only after success. Token rotation similarly restores both the
old deployment and credential if verification or secure-store persistence
fails.

Deletion first promotes Cloudflare's explicit Durable Object `deleted` export
tombstone, then deletes the Worker and its Sub KV namespace. This avoids
orphaning a class namespace/data by deleting only the script.

## Custom Domains and network policy

Endpoint modes are Workers.dev, one exact Custom Domain, or both, with an
explicit primary hostname. The control plane checks ownership/conflicts before
mutation and polls policy-aware HTTPS rather than sending direct UDP DNS
queries. Direct, System, SOCKS5H, and HTTP(S) proxy policies therefore apply
consistently to Cloudflare API calls and health requests; explicit proxy mode
fails closed.

## Cloudflare Free resource model

Ordinary Worker HTTP requests and Cron invocations have a 10 ms Free-plan CPU
limit and Workers have a 128 MiB memory limit. The multi-megabyte source parse
is delegated to the SQLite Durable Object request, whose default CPU allowance
is 30 seconds. The hot subscription path stays small.

Steady state is one KV read per subscription request, a few KV writes every six
hours, and one hibernatable Durable Object plus socket per relay connection.
Carrier-optimized entry IPs are optional; failure falls back to the relay
hostname. Check current official Cloudflare Workers, Durable Objects, and KV
limits before production sizing because quotas can change.

## Manual Wrangler path

Prefer the deployer. If operating Wrangler directly, start from both committed
`wrangler.example.toml` files, build with `worker-build --release`, and keep:

- Relay `VEILWEAVE_SESSION` SQLite Durable Object migration;
- Sub KV plus `KV_BINDING`;
- Sub `PROXYIP_REFRESHER` SQLite Durable Object migration;
- Sub six-hour Cron Trigger;
- Cloudflare secrets `SECRET_KEY`, `VEILWEAVE_NODES`, and
  `SUBSCRIPTION_TOKEN`.

After the first manual Sub deploy, deterministically bootstrap with:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer <subscription token>" \
  https://<sub-host>/_veilweave/proxyip/refresh
```

Do not add `PROXYIP_LIST`, hard-code secret values, or enable ECH merely because
a client exposes the option.

## Failure recovery

- Source outage with cache: inspect `proxyip status`; known-good nodes continue.
- Source outage without cache: deployment/bootstrap fails clearly; retry after
  the authoritative source recovers.
- Suspected subscription-token leak: use `rotate-token`.
- Relay/node secret leak: deploy a matched new relay secret and Sub topology;
  old signed UUIDs will fail validation.
- Bad code version: `rollback` uses the recorded known-good version.
- Lost local metadata: use `recover` with explicit existing credential
  references; Cloudflare secret values are not readable through the API.
