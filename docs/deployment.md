# Deployment guide

Step-by-step production deployment for the **three-piece** veilweave stack.
Designed for the Cloudflare Workers free plan.

## 0. Prerequisites

| Tool         | Version      | Verify            |
|--------------|--------------|-------------------|
| Rust         | 1.81+        | `rustc --version` |
| rustup       | latest       | `rustup --version`|
| `wasm32-unknown-unknown` | latest | `rustup target list --installed` |
| wrangler     | ≥ 3.x        | `wrangler --version` |
| Cloudflare   | free or paid | `wrangler whoami`  |

## 1. Generate a matched keypair

```bash
git clone https://github.com/<owner>/veilweave.git
cd veilweave
rustup target add wasm32-unknown-unknown
cargo run --manifest-path tools/Cargo.toml -- gen-secret
```

You'll see two blobs. **Copy them somewhere safe (1Password / Bitwarden)**
before pasting them in the next step.

## 2. Deploy the relay (`relay/`)

### 2.1 Set the secret

In production, **never** put the relay blob in `wrangler.toml`. Use:

```bash
cd relay
wrangler secret put SECRET_KEY
# paste the **relay blob** when prompted
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
VEILWEAVE_NODES = "relay.your-domain.com|<paste SUB blob from step 1>"
```

For multiple relay nodes, comma-separate, each with its own SUB blob:

```toml
VEILWEAVE_NODES = """
node-a.example.com|<sub blob a>,
node-b.example.com|<sub blob b>
"""
```

> Different nodes with different blobs sign their UUIDs independently —
> a UUID issued for node a won't validate on node b (this is **a feature**:
> per-node key isolation).

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
  --secret-key "<the same relay blob from step 1>"
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

   You should see `[veilweave] handshake: complete` and download lines.

## 5. Key rotation

There is no in-place rotation. To rotate keys:

1. `cargo run -p veilweave-tools -- gen-secret` — generate a fresh pair.
2. Deploy the **new** relay blob (`wrangler secret put SECRET_KEY`).
3. Re-deploy `wrangler deploy`.
4. Update `VEILWEAVE_NODES` in the sub worker with the new sub blob.
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

Default build has `perf-log` enabled in the build command. To get
**even more** lines (per-record / per-frame counter dumps), build
explicitly with the feature:

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
- 0 KV / subreq.

A sub worker serving 1000 unique users/day with 90% cache hit rate:

- 1000 sub requests × 0.1 cold × 4 subrequests = 400 subrequests
- 1000 KV reads (cache hits) + 100 KV writes (cold paths)
- well under all limits.

## 9. Disaster recovery

| Failure | Recovery |
|---------|----------|
| `SECRET_KEY` leaked | Run `gen-secret` → deploy new blobs → notify users |
| `SUBSCRIPTION_TOKEN` leaked | `wrangler secret put SUBSCRIPTION_TOKEN` (new value) |
| Sub KV corrupted | `wrangler kv:delete --binding VEILWEAVE_KV 'proxyip_cache_v1'` |
| Relay misbehaving | `wrangler rollback` (Cloudflare keeps last 5 deploys) |
| Cloudflare region down | Free plan = single region; consider paid plan for HA |

## 10. Common gotchas

- **Clients see "connection reset"**: usually the relay's `SECRET_KEY`
  doesn't match what the client thinks. Re-check `gen-link --secret-key`
  vs. the deployed `SECRET_KEY`.
- **Sub returns 404**: token mismatch or `SUBSCRIPTION_TOKEN` env not
  set. Tail the worker to confirm.
- **`handshake: complete` then immediate close**: client and relay
  disagree on the encryption profile. Make sure the client is
  configured with `encryption=mlkem768x25519plus` (not `none`).
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
