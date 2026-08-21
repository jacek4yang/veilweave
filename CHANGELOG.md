# Changelog

All notable changes to veilweave are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/) and the project
adheres to [Semantic Versioning](https://semver.org/).

> **Note:** Until `1.0.0`, breaking changes are documented under
> `Changed` with a clear migration note. Patch-level releases are
> wire-compatible with the previous patch release; minor releases
> may change the build profile but stay wire-compatible.

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

## [Unreleased]

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

[Unreleased]: https://github.com/<owner>/veilweave/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/<owner>/veilweave/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/<owner>/veilweave/releases/tag/v0.1.0
