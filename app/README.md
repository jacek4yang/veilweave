# Veilweave desktop app

The Tauri 2 desktop app is a graphical adapter over `veilweave-core`. It uses
the same transactional deploy/update/rollback/recovery/network logic as the CLI
and embeds the same canonical relay/Sub Worker bundles.

## Features

- Manage one or more Cloudflare accounts with API tokens in the OS credential
  manager.
- Deploy one Sub Worker and one or more independently keyed relay Workers to
  Workers.dev, exact Custom Domains, or both.
- Configure compatible defaults (`MAX_NODES=100`, ECH off) and optional ECH.
- Copy a subscription URL only after an explicit click; ordinary DTOs and
  deployment events are redacted.
- Inspect proxyIP health (state, age, endpoint/country counts) and trigger an
  authenticated refresh without exposing its token or dataset.
- Update, roll back, rotate a Sub token, and delete deployments. Deletion
  retires the Durable Object namespace before removing Worker/KV resources.
- Recover remote metadata with explicit existing credential references.
- Share one Direct, System, SOCKS5H, or HTTP(S) proxy policy across Cloudflare
  operations, health checks, diagnostics, and updater downloads.

ProxyIP addresses are automatic and exclusively sourced from
`https://zip.cm.edu.kg/all.json`; the app has no manual `PROXYIP_LIST` field.
Deployment bootstraps the compact cache and refuses false-positive health when
the subscription has no valid nodes.

## Security boundary

The WebView receives account/deployment names, IDs, endpoint state, safe
proxyIP summary fields, and network metadata. It does not receive API tokens,
relay/node secrets, subscription-token references, proxy passwords, or private
keys. A dedicated backend command briefly returns the bearer subscription URL
only for the copy action.

Cloudflare secrets are written as secret bindings. Local credential values use
the platform store and zeroizing core wrappers. The operation guard prevents
overlapping topology mutations.

## Source build

Prerequisites are Rust, Node.js, the platform Tauri dependencies, and
`worker-build` for the two Worker crates.

```bash
(cd relay && worker-build --release)
(cd sub && worker-build --release)

cargo run --locked --manifest-path tools/Cargo.toml -- \
  worker-bundle prepare --role relay --source relay/build \
  --out app/src-tauri/bundle/relay
cargo run --locked --manifest-path tools/Cargo.toml -- \
  worker-bundle prepare --role sub --source sub/build \
  --out app/src-tauri/bundle/sub

cd app
npm ci
npm run tauri -- build
```

The prepared `src-tauri/bundle/` tree is ignored build output. The Tauri build
script rejects a missing, stale, wrong-role, or tampered bundle.

Native checks:

```bash
cargo fmt --manifest-path app/src-tauri/Cargo.toml -- --check
cargo test --manifest-path app/src-tauri/Cargo.toml
cargo clippy --manifest-path app/src-tauri/Cargo.toml --all-targets -- -D warnings
node --check app/ui/js/app.js
node --check app/ui/js/i18n.js
```

## Updates and releases

`tauri.conf.json` enables signed updater artifacts. Release CI holds
`TAURI_SIGNING_PRIVATE_KEY` and its password; only the matching public key is
committed. The Release workflow cannot package the app until the protected
Cloudflare/Xray E2E passes, and it embeds the exact `tested-worker-bundles`
artifact produced by that run.

See `../docs/deployment.md`, `../docs/security-v2.md`, and
`../docs/release-v2.md` for operational details.
