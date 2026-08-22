# Changelog

All notable changes to veilweave are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.0.0] — 2026-08-22

### Added

- Canonical, manifest-backed Worker bundles shared by the CLI, desktop app,
  release packaging, and Cloudflare client. Runtime modules are allowlisted,
  typed, hashed, and validated before any network request.
- Transactional Cloudflare Version/Deployment flow with a resource journal,
  compensation, health verification, stored stable/previous version IDs, and
  explicit update and rollback commands.
- Exact-hostname Custom Domains for every relay and Sub Worker, including
  workers.dev-only, Custom-Domain-only, and dual exposure with a selectable
  primary endpoint and asynchronous certificate state.
- Schema-v2 configuration, stable account/deployment IDs, OS credential-store
  references, verified v1 migration, redacted WebView DTOs, and secret-aware
  recovery classifications.
- Declarative TOML topology specifications plus `plan`, `apply`, `status`,
  `update`, `rollback`, `doctor`, `recover`, and `domain` CLI workflows.
- Application-wide Direct, System, SOCKS5/SOCKS5H, and HTTP(S) proxy policy.
  Cloudflare calls, diagnostics, update checks, and update downloads share one
  immutable runtime transport generation. Explicit proxies fail closed and
  authenticated proxy passwords live only in the secure credential store.

### Changed

- Worker code is uploaded as an inert version and promoted separately. Updates
  inherit secrets strictly; coordinated topology updates rotate only the Sub
  node binding while preserving the subscription token.
- Relay Durable Object creation is declarative only for a new Worker. Code-only
  updates preserve the existing free-plan SQLite namespace.
- Manual Wrangler bundles no longer write relay, node, or subscription secrets
  to TOML; operators use `wrangler secret put`.
- All shipped component versions are checked against the root `VERSION` file.

### Fixed

- Cloudflare error 10162: `worker-build`'s `package.json` was recursively staged
  and uploaded as an `application/json` Worker module. Build metadata is now
  excluded and unsupported runtime files fail locally.
- Rollback can no longer delete pre-existing Workers, KV namespaces, domains,
  or exposure state owned outside the failed transaction.

## [1.1.1] — 2026-08-22

### Fixed
- **Usage dashboard** (`cfapi::account_usage`): the GraphQL dataset is
  `workersInvocationsAdaptive`, not `workersInvocationsAdaptiveGroups` —
  Cloudflare answered `unknown field` and the app misreported it as a
  missing `Account Analytics: Read` permission. Verified end-to-end against
  a real account: per-script requests / errors / CPU P50 now load.

## [1.1.0] — 2026-08-21

### Added
- **Desktop app** (`app/`, `veilweave-app`): a Tauri 2 graphical deployer —
  the new primary install path. Sidebar pages 概览 / 账号 / 部署 / 管理 /
  设置; dark, polished design.
  - Multi-token Cloudflare account management (API token, same permission
    model as the CLI wizard).
  - Per-account **usage dashboard**: today's requests against the 100k free
    tier, error counts, per-worker rows — via the GraphQL Analytics API
    (requires the optional `Account → Analytics → Read` token permission).
  - **Recover** ("扫描已有部署"): reads worker script settings through the
    Cloudflare API and rebuilds the local config — restores your deployment
    inventory after a reinstall.
  - Deploy wizard with the CLI's topology model (sub on one account, N
    relays across any accounts, per-relay secrets), all names customizable
    with one-click 随机 buttons.
  - Manage: copy subscription URLs, **update a deployment** in place
    (re-uploads the latest embedded worker code, keeping all secrets), or
    delete a worker including its KV namespace.
  - Settings: language (中文/English) and check-for-updates.
  - Ships as installers per platform: NSIS `*-setup.exe` + MSI (Windows),
    `.dmg` (macOS arm64), `.AppImage` + `.deb` (Linux). The Windows build
    has no console window (`windows_subsystem`). The app embeds the prebuilt
    workers — deploy/update runs fully offline from the installed app.
  - **In-app auto-update**: releases now publish a signed `latest.json`
    updater manifest next to the installers.
- **`core/` crate** (`veilweave-core`): the shared deploy library — Cloudflare
  API client, config persistence, deploy/recover orchestration, secret/name
  utilities — now used by both `tools` (CLI) and `app` (desktop).

### Changed
- **The egui GUI was removed from `veilweave-tools`**; the tools crate is a
  pure CLI again (`gen-secret` / `gen-link` / `bundle` / `deploy` / `manage`).
  Running it with no arguments prints a hint pointing at `deploy` and the
  desktop app. Graphical users should install the desktop app instead.
- **Relay hot-path zero-copy pass** (`relay` 1.0.1; wire-compatible, `sub`
  unchanged): plaintext upload takes ownership of arriving WS frames instead
  of append-copying them; the download loop moves no bytes through wasm
  linear memory and caches JS property strings. Encrypted mode gets
  zero-copy views into WebCrypto, a per-connection staging buffer for
  records, zero per-record JS allocations for GCM parameters, and the
  header-phase clone is eliminated. No protocol or configuration changes.

## [1.0.1] — 2026-08-21

### Fixed
- **GUI now opens on DisplayLink / RDP / software-GL machines**: the window
  tries the `wgpu` renderer first (DX12 on Windows, Metal on macOS, Vulkan on
  Linux — fully static, zero runtime dependencies), falls back to `glow`
  (OpenGL), and only then to the CLI wizard message.
- **GUI language auto-detect**: the UI follows the OS locale (Chinese for
  `zh*`, English otherwise) with a persistent manual 中文/English override in
  the sidebar.
- **GUI contrast**: dark theme is now the default (light is a sidebar toggle);
  all status/log colors are theme-aware, eliminating the unreadable
  pale-yellow-on-white warning text.
- CI: winit `x11`/`wayland` backends enabled so the Linux build compiles;
  gitleaks false positives annotated.

## [1.0.0] — 2026-08-21

### Added
- Initial monorepo restructure: `relay/`, `sub/`, `tools/`.
- Top-level `README.md` with architecture overview and quick start.
- `.github/` templates, CI workflow, and CODEOWNERS.
- `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`.
- `wrangler.example.toml` for each Worker crate — committed `wrangler.toml`
  files now ship with placeholders only.
- **Plaintext passthrough datapath**: a raw (non-blob) `SECRET_KEY` now serves
  plaintext VLESS (`encryption=none`) — no handshake, no per-frame AEAD, and
  near-zero per-frame CPU on the relay. This is the new default.
- **Customizable KV binding** (`sub`): the worker resolves its KV namespace via
  the `KV_BINDING` var, falling back to `VEILWEAVE_KV` and then `KV`, so the
  binding name is no longer hard-coded.
- **Deployer** (`veilweave-tools`):
  - `deploy` — interactive wizard: add Cloudflare accounts via API token
    (Workers Scripts Edit, Workers KV Storage Edit, Account Settings Read),
    plan a topology (sub on one account, N relays across any accounts, each
    relay with its own secret), and deploy directly over the Cloudflare API —
    no wrangler or Node.js required. Prints the subscription URL when done.
  - `manage` — list or delete existing deployments, re-show subscription URLs.
  - Running the executable with no arguments launches the graphical deployer
    (Accounts / Deploy / Manage pages).
  - Account and deployment state persists at the platform config dir
    (`~/.config/veilweave/config.toml`, `%APPDATA%\veilweave\config.toml`).

### Changed
- **Security**: removed real `SECRET_KEY` / `VEILWEAVE_NODES` /
  `SUBSCRIPTION_TOKEN` values from committed `wrangler.toml` files.
  Operators must supply their own via `wrangler secret put` (relay) or
  `[vars]` (sub).
- **VLESS Encryption (`mlkem768x25519plus`) is now experimental and off by
  default.** The per-connection ML-KEM-768 + X25519 + AES-256-GCM datapath is
  too CPU-heavy for the Workers free plan's per-invocation CPU budget. It is
  still fully implemented and opt-in: a `VW1` blob `SECRET_KEY` enables it on
  the relay, and `gen-secret --encryption` / `bundle --encryption` generate the
  matching blob pair. Migration note: existing `VW1` blob deployments keep
  working unchanged; nothing about the blob format or wire protocol changed.
- `gen-secret` now prints **one raw shared secret** (for relay `SECRET_KEY`
  and sub `VEILWEAVE_NODES` alike) by default; pass `--encryption` for the
  old blob-pair behavior.
- `bundle` defaults to plaintext mode (`--encryption` opts in) and generates a
  randomized KV binding name (e.g. `kv_x7f2a9`) with a matching `KV_BINDING`
  var in the sub's `wrangler.toml`. Users are encouraged to pick their own
  worker names, KV titles, and binding names.

### Fixed
- N/A.

## [0.1.0] — 2026-05-26

### Added
- Initial public release of `veilweave` (relay) and `veilweave-sub`.
- `veilweave-tools` CLI: `gen-secret`, `gen-link`.
- VLESS Encryption (`mlkem768x25519plus`) server handshake:
  hybrid post-quantum PFS (ML-KEM-768 + X25519), BLAKE3 key derivation,
  AES-256-GCM data path via WebCrypto (BoringSSL/AES-NI), `+simd128`
  WASM for the handshake crypto.
- WebSocket Hibernation API integration: per-frame CPU budget, in-memory
  per-connection state, single background download loop.
- Apache 2.4.62 / Debian camouflage page (`static/apache_default.html`).
- Signed-UUID scheme with per-isolate HKDF derivation and bounded LRU.

[Unreleased]: https://github.com/jacek4yang/veilweave/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/jacek4yang/veilweave/compare/v1.1.1...v2.0.0
[1.1.1]: https://github.com/jacek4yang/veilweave/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/jacek4yang/veilweave/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/jacek4yang/veilweave/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/jacek4yang/veilweave/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/jacek4yang/veilweave/releases/tag/v0.1.0
