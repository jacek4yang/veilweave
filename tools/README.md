# veilweave-tools

`veilweave-tools` is the native deployment, recovery, and bundle control plane.
Release archives include this binary and prebuilt canonical Worker bundles, so
operators do not need Rust, Node.js, Wrangler, or source code.

## Deployment lifecycle

```bash
# Interactive account/topology wizard
veilweave-tools deploy

# Secret-free declarative workflow
veilweave-tools plan --config veilweave.toml --bundle-dir bundle
veilweave-tools apply --config veilweave.toml --bundle-dir bundle --yes

# Redacted local state
veilweave-tools status --json

# Version lifecycle
veilweave-tools update --deployment <uuid> --bundle-dir bundle
veilweave-tools rollback --deployment <uuid>
veilweave-tools rotate-token --deployment <sub-uuid> --bundle-dir bundle

# Noninteractive resource cleanup, including Durable Object retirement
veilweave-tools delete --deployment <uuid>

# Interactive URL reveal and deletion
veilweave-tools manage
```

Declarative `apply` never prints a bearer subscription URL, even in JSON mode.
Generated Cloudflare API, Worker, node, subscription, proxy, and private-key
credentials remain in environment-backed references or the OS credential
manager. `manage` reveals a subscription URL only after an explicit human
action.

`delete` promotes an explicit Cloudflare Durable Object `deleted` export before
removing the Worker. A Sub deletion also removes its KV namespace and local
credential records.

## Automatic proxyIP management

```bash
veilweave-tools proxyip status --deployment <sub-uuid>
veilweave-tools proxyip status --deployment <sub-uuid> --json
veilweave-tools proxyip refresh --deployment <sub-uuid>
```

These commands resolve the subscription credential internally and call the
authenticated management endpoints. Output contains only the fixed source URL,
validation/stale state, revision/age, counts, and bounded last-failure detail.
It never exposes the compact dataset or token.

The automatic and only production source is
`https://zip.cm.edu.kg/all.json`. There is no `PROXYIP_LIST` option. Deployment
creates the KV/Durable Object/Cron resources, bootstraps a generation, and
requires a structurally valid subscription before reporting health.

## Diagnostics and recovery

```bash
veilweave-tools doctor --json
veilweave-tools proxy test --json
veilweave-tools domain --account <label-or-id> --json
veilweave-tools recover --account <label-or-id>
```

Secure v2 adoption requires explicit existing credential references because
Cloudflare never returns deployed secret values:

```bash
veilweave-tools recover --account production \
  --adopt-worker edge-one \
  --worker-secret-ref env:EDGE_ONE_WORKER_SECRET \
  --node-secret-ref env:EDGE_ONE_NODE_SECRET
```

For Sub recovery also provide `--subscription-token-ref`. Recovery discovers
automatic proxyIP bindings/metadata; it does not depend on a manual address
list.

Every control-plane network operation uses the same Direct, System,
SOCKS5/SOCKS5H, or HTTP(S) proxy policy. CLI `--proxy` overrides saved policy;
explicit proxy modes fail closed.

## Canonical Worker bundles

```bash
veilweave-tools worker-bundle prepare \
  --role relay --source relay/build --out bundle/relay
veilweave-tools worker-bundle prepare \
  --role sub --source sub/build --out bundle/sub
veilweave-tools worker-bundle validate --role relay --dir bundle/relay
veilweave-tools worker-bundle validate --role sub --dir bundle/sub
```

The manifest models the exact runtime module set, MIME types, roles, and SHA-256
hash. Unknown/stale modules, escaping paths, missing modules, and tampering are
rejected. Worker build metadata such as `package.json` is not shipped.

`bundle --out dist` copies release-provided canonical bundles into
Wrangler-ready directories with randomized resource names and secret-free
configuration. It prints commands for injecting secrets; it does not write
secret values to TOML.

## Standalone link/secret utilities

```bash
# Default plaintext VLESS mode: one random raw signing secret
veilweave-tools gen-secret

# Experimental VLESS Encryption matched relay/Sub blobs
veilweave-tools gen-secret --encryption

# Advanced single-link generation (bypasses the automatic Sub service)
veilweave-tools gen-link \
  --address relay.example.com --port 443 \
  --type proxyip --proxy-ip 203.0.113.9 --proxy-port 443 \
  --secret-key '<matching relay secret>'
```

`gen-link` is an advanced one-off protocol utility, not the production proxyIP
source. Normal subscriptions obtain egress addresses automatically. Optional
`--ech` is emitted only when supplied; ECH is off by default.

## Cloudflare permissions

Use a dedicated account-scoped Custom Token:

- Workers Scripts: Edit
- Workers KV Storage: Edit
- Account Settings: Read
- Custom Domain/Zone permissions only when used
- Account Analytics: Read only for optional dashboard usage

## Build and test

```bash
cargo fmt --manifest-path tools/Cargo.toml -- --check
cargo check --manifest-path tools/Cargo.toml
cargo test --manifest-path tools/Cargo.toml
cargo clippy --manifest-path tools/Cargo.toml --all-targets -- -D warnings
cargo build --release --locked --manifest-path tools/Cargo.toml
```
