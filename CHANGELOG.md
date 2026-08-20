# Changelog

All notable changes to veilweave are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/) and the project
adheres to [Semantic Versioning](https://semver.org/).

> **Note:** Until `1.0.0`, breaking changes are documented under
> `Changed` with a clear migration note. Patch-level releases are
> wire-compatible with the previous patch release; minor releases
> may change the build profile but stay wire-compatible.

## [Unreleased]

### Added
- Initial monorepo restructure: `relay/`, `sub/`, `tools/`.
- Top-level `README.md` with architecture overview and quick start.
- `.github/` templates, CI workflow, and CODEOWNERS.
- `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`.
- `wrangler.example.toml` for each Worker crate — committed `wrangler.toml`
  files now ship with placeholders only.

### Changed
- **Security**: removed real `SECRET_KEY` / `VEILWEAVE_NODES` /
  `SUBSCRIPTION_TOKEN` values from committed `wrangler.toml` files.
  Operators must supply their own via `wrangler secret put` (relay) or
  `[vars]` (sub).

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

[Unreleased]: https://github.com/<owner>/veilweave/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/<owner>/veilweave/releases/tag/v0.1.0
