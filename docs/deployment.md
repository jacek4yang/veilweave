# Deployment guide

Step-by-step production deployment for the **three-piece** veilweave stack.
Designed for the Cloudflare Workers free plan.

> **Easiest path:** you don't need this guide at all. Download the **desktop
> app** from the release page (Windows NSIS/MSI, macOS `.dmg`, Linux
> AppImage/`.deb`), or run `veilweave-tools deploy` from the CLI archive — both
> publish the workers through the Cloudflare API: accounts, KV, secrets, and
> the subscription URL included. The app adds a usage dashboard, one-click
> updates, and "扫描已有部署" recovery after a reinstall. This guide covers
> the manual wrangler flow and the operational details underneath.

## 0. Prerequisites

For the manual flow in this guide:

| Tool         | Version      | Verify            |
|--------------|--------------|-------------------|
| Rust         | 1.81+        | `rustc --version` |
| rustup       | latest       | `rustup --version`|
| `wasm32-unknown-unknown` | latest | `rustup target list --installed` |
| wrangler     | ≥ 3.x        | `wrangler --version` |
| Cloudflare   | free or paid | `wrangler whoami`  |

For the deployer path (desktop app / `veilweave-tools deploy`) you only need a
Cloudflare **API token** with:

- Account → Workers Scripts → **Edit**
- Account → Workers KV Storage → **Edit**
- Account → Account Settings → **Read** (resolves the workers.dev subdomain)
- Account → Account Analytics → **Read** (*optional* — only the desktop app's
  usage dashboard needs it)

Create it at <https://dash.cloudflare.com/profile/api-tokens>
("Create Custom Token"). The deployer supports **multiple accounts** — a
common hardening topology is sub on account A and each relay on its own
account (B, C, D…), with an independent secret per relay.

## 0.1 Plaintext vs. experimental encryption

Since v1.0.0 the **default and recommended datapath is plaintext VLESS
passthrough** (`encryption=none`): the client ↔ Cloudflare hop is normal TLS,
and the relay forwards bytes without any handshake or per-record crypto, so
per-frame CPU is near zero and the free plan's 10 ms per-invocation budget is
never a concern. The tradeoff, stated plainly: Cloudflare terminates that TLS
and can see the plaintext destination and payload — the same trust model as
any site hosted on Cloudflare.

VLESS Encryption (`mlkem768x25519plus`: ML-KEM-768 + X25519 PFS handshake,
AES-256-GCM records) hides the stream from Cloudflare too, but its
per-connection handshake and per-record AEAD are CPU-heavy and can exceed the
free plan's CPU limit. It is **experimental** and opt-in: generate the blob
pair with `gen-secret --encryption` (or `bundle --encryption`) and deploy the
relay blob as `SECRET_KEY`. Existing blob deployments from ≤ 0.x keep working
unchanged.

## 1. Generate secrets

```bash
git clone https://github.com/<owner>/veilweave.git
cd veilweave
rustup target add wasm32-unknown-unknown
cargo run --manifest-path tools/Cargo.toml -- gen-secret
```

The default output is **one raw random secret**, used verbatim as the relay's
`SECRET_KEY` and in the sub's `VEILWEAVE_NODES` as `<domain>|<secret>`
(plaintext mode). For the experimental encryption mode, run
`gen-secret --encryption` instead — you'll get two blobs (relay + sub).

**Copy the secret(s) somewhere safe (1Password / Bitwarden)** before pasting
them in the next step. Run `gen-secret` once **per relay node**.

## 2. Deploy the relay (`relay/`)

### 2.1 Set the secret

In production, **never** put the secret in `wrangler.toml`. Use:

```bash
cd relay
wrangler secret put SECRET_KEY
# paste the raw secret (or, for experimental encryption, the **relay blob**)
```

Then open `wrangler.toml` and **delete the entire `[vars]` block**
(the placeholder line is not needed once the secret is set).

### 2.2 Bind a custom domain (optional but recommended)

In the Cloudflare dashboard:

1. Add the worker — `Workers & Pages → veilweave → Settings → Triggers → Custom Domains`.
2. Add `relay.your-domain.com` (or whatever subdomain).
3. SSL/TLS will be automatic (Cloudflare-issued).

### 2.3 Deploy

```bash
wrangler deploy
```

Note the deployed URL (e.g. `https://veilweave.your-name.workers.dev`) and
the custom domain. The custom domain is what clients will use.

### 2.4 Verify

```bash
# Browser — should return Apache 2.4.62 (Debian) default page
curl -I https://relay.your-domain.com/

# Should return 426 (Upgrade required) for plain GET
curl -I -H "Connection: Upgrade" -H "Upgrade: websocket" \
  https://relay.your-domain.com/
```

## 3. Deploy the subscription worker (`sub/`)

### 3.1 Create KV namespace

```bash
cd ../sub
wrangler kv:namespace create VEILWEAVE_KV
# → Returns: { binding = "VEILWEAVE_KV", id = "..." }
# Paste the id into wrangler.toml's [[kv_namespaces]].id
```

For preview / staging, also create a preview id:

```bash
wrangler kv:namespace create VEILWEAVE_KV --preview
# → Paste the preview id into wrangler.toml's
#    [[kv_namespaces]]  preview_id = "..."
```

**The binding name is customizable.** The worker resolves its namespace via
the `KV_BINDING` var first, then `VEILWEAVE_KV`, then `KV`. To use your own
name (recommended — see naming hygiene below), set both to the same value:

```toml
[[kv_namespaces]]
binding = "my_cache"      # any valid JS identifier
id = "..."

[vars]
KV_BINDING = "my_cache"
```

(`veilweave-tools bundle` and the deployer randomize the binding name, e.g.
`kv_x7f2a9`, and wire up `KV_BINDING` for you.)

### 3.2 Set the secret token

```bash
# generate a 32-byte random token
openssl rand -hex 32
# paste it
wrangler secret put SUBSCRIPTION_TOKEN
```

### 3.3 Fill `VEILWEAVE_NODES`

Edit `wrangler.toml` and replace the placeholder:

```toml
VEILWEAVE_NODES = "relay.your-domain.com|<the same raw secret from step 1>"
```

For multiple relay nodes, comma-separate, each with its own secret:

```toml
VEILWEAVE_NODES = """
node-a.example.com|<secret a>,
node-b.example.com|<secret b>
"""
```

> Different nodes with different secrets sign their UUIDs independently —
> a UUID issued for node a won't validate on node b (this is **a feature**:
> per-node key isolation).
>
> For the experimental encryption mode, each node's secret is the **sub blob**
> from `gen-secret --encryption` instead, and links automatically carry
> `encryption=mlkem768x25519plus.native.1rtt.<pubkey>`.

### 3.4 Bind a custom domain

Same as 2.2 — add `sub.your-domain.com`.

### 3.5 Deploy

```bash
wrangler deploy
```

### 3.6 Verify

```bash
# Should 404 (Apache 404 page)
curl -I https://sub.your-domain.com/

# Should return subscription body (200, base64)
curl "https://sub.your-domain.com/sub?token=<your token>"
```

## 4. Smoke-test the link

Use the CLI to generate a single link (faster than spinning up xray):

```bash
cd ..
cargo run --manifest-path tools/Cargo.toml -- gen-link \
  --address relay.your-domain.com \
  --port 443 \
  --type proxyip \
  --proxy-ip 1.2.3.4 \
  --proxy-port 443 \
  --secret-key "<the same secret from step 1>"
```

Then:

1. Copy the `vless://...` line.
2. Open `v2rayN` (or `NekoBox for Android`, `sing-box`, `mihomo`).
3. Add the link as a new server.
4. Connect.
5. Tail the relay:

   ```bash
   cd relay && wrangler tail
   ```

   (Logs need a `perf-log` build — see §6. Without it the worker compiles
   with zero logging.)

## 5. Key rotation

There is no in-place rotation. To rotate keys:

1. `cargo run -p veilweave-tools -- gen-secret` — generate a fresh secret.
2. Deploy the **new** secret (`wrangler secret put SECRET_KEY`).
3. Re-deploy `wrangler deploy`.
4. Update `VEILWEAVE_NODES` in the sub worker with the new secret.
5. Re-deploy the sub worker.
6. Notify users to re-fetch the subscription.

Old UUIDs (signed with the old key) immediately fail MAC validation
once the relay restarts with the new key — there is no overlap window.

## 6. Observability

### Workers Logs

Both workers have `[observability].enabled = true` in `wrangler.toml`.
Logs surface in the Cloudflare dashboard (sampled on the free plan) and
via `wrangler tail`.

### Profiling the relay

The default build compiles **no logging at all** (the `perf-log` feature is
off; zero hot-path overhead). To get per-record / per-frame counter dumps,
build explicitly with the feature:

```bash
cd relay
worker-build --release --features perf-log
wrangler deploy
wrangler tail
```

You'll see lines like:

```
[veilweave] handshake: complete (~6ms wall), 18 leftover data bytes
[veilweave] establish: TCP www.example.com:443 via direct (0 initial bytes)
[veilweave] connect: www.example.com:443 via direct (~12ms), 0 downstream leftover bytes
[veilweave] upload drive: 12 records, 16384 ciphertext bytes → target
[veilweave] download: target EOF — 248 records / 67 reads, 4056880 plaintext bytes, 0 stalls over ~1234ms
```

(Handshake / record lines only appear in the experimental encryption mode;
the plaintext datapath logs connection lifecycle and byte counts.)

Turn the feature back off for long-term production deploys.

### Custom metrics

For the free plan you can't add Workers Analytics Engine. Use:

- **`wrangler tail`** for live log inspection.
- **Workers Logs** in the dashboard for the last 3 days.
- **Logpush** (paid) for long-term archival.
- A **Logflare / Axiom** pipeline if you need it.

## 7. Rate-limiting & abuse

Cloudflare provides zone-level rate limiting (free plan: 10 000 requests
per 10 minutes). Configure at **Security → WAF → Rate limit rules**:

- Match URI path `^/sub$` and `cookie`/`header` `token`.
- Action: challenge or block.

For the relay (`relay.your-domain.com`), the only publicly-routable path
that accepts non-WS is the Apache page. WS upgrades that fail the
handshake will close fast. A simple rate-limit rule by `cf.client.ip` is
usually enough.

## 7.1 Naming hygiene

Every veilweave deployment should look like *your* deployment, not like a
stock one:

- Pick your own **worker names** (not `veilweave` / `veilweave-sub`).
- Pick your own **KV namespace title and binding name** (set `KV_BINDING`).
- `veilweave-tools bundle` and the deployer already randomize worker names,
  the KV binding, and inject a per-run nonce into each script so artifacts
  never share a content hash — if you deploy manually, at least rename the
  workers.

## 8. Cost & limits (free plan)

| Limit                         | Free plan | Note |
|-------------------------------|-----------|------|
| Requests                      | 100 000 / day | Both workers share this |
| CPU time per invocation       | 10 ms       | 30 s wall is fine |
| DO concurrent                 | 1000        | each WS = 1 DO instance |
| DO storage                     | 1 GB        | sqlite backend, but we use 0 |
| KV reads                      | 100 000 / day | sub's main cost |
| KV writes                     | 1000 / day   | cache writes on cold path |
| KV stored                     | 1 GB         | fine |
| Subrequests / request         | 50           | sub's cold path uses ~4 |

A single relay with 50 concurrent VLESS connections uses roughly:

- 50 DO instances × few ms CPU = well under the 100k request budget.
  (Plaintext mode: essentially zero CPU per frame. The experimental
  encryption mode is the one that can approach the 10 ms cap.)
- 0 KV / subreq.

A sub worker serving 1000 unique users/day with 90% cache hit rate:

- 1000 sub requests × 0.1 cold × 4 subrequests = 400 subrequests
- 1000 KV reads (cache hits) + 100 KV writes (cold paths)
- well under all limits.

## 9. Disaster recovery

| Failure | Recovery |
|---------|----------|
| `SECRET_KEY` leaked | Run `gen-secret` → deploy the new secret → notify users |
| `SUBSCRIPTION_TOKEN` leaked | `wrangler secret put SUBSCRIPTION_TOKEN` (new value) |
| Sub KV corrupted | `wrangler kv:delete --binding <KV_BINDING> 'proxyip_cache_v1'` |
| Relay misbehaving | `wrangler rollback` (Cloudflare keeps last 5 deploys) |
| Cloudflare region down | Free plan = single region; consider paid plan for HA |
| Whole account suspended | Redeploy from the deployer to another account (`deploy` → pick account) |

## 10. Common gotchas

- **Clients see "connection reset"**: usually the relay's `SECRET_KEY`
  doesn't match what the client thinks. Re-check `gen-link --secret-key`
  vs. the deployed `SECRET_KEY`.
- **Sub returns 404**: token mismatch or `SUBSCRIPTION_TOKEN` env not
  set. Tail the worker to confirm.
- **Client and relay disagree on encryption**: the link's `encryption=...`
  parameter comes from the secret type. Raw secret → `encryption=none`;
  `VW1` blob → `encryption=mlkem768x25519plus...`. If you switch modes,
  regenerate the links/subscription — old links keep the old mode.
- **CPU limit exceeded in encryption mode**: expected on busy connections —
  that's why encryption is experimental. Switch to the plaintext default if
  this bites.
- **Slow downloads**: the egress `ProxyIp` may be down. The direct
  fallback in `egress::connect_target` should still serve most traffic;
  check `wrangler tail` for "connect" failures.
- **`cargo install worker-build` slow**: the first install compiles a
  lot. Subsequent deploys are cached.

## 11. Updating

```bash
git pull
# edit wrangler.toml if compatibility_date bumped
cd relay && wrangler deploy && cd ..
cd sub   && wrangler deploy && cd ..
```

The Durable Object class `VeilweaveSession` is stable; adding new
methods or fields is backward-compatible. Renaming it requires a
`[[migrations]]` update.
