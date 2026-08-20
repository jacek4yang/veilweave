# Contributing to veilweave

Thanks for your interest in veilweave! Whether it's a typo, a new codec, or a
core protocol change — all contributions are welcome.

## Code of conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/).
By participating, you are expected to uphold this code. Please report unacceptable
behavior to the maintainers listed in [`CODEOWNERS`](CODEOWNERS).

## Workflow

1. **Open an issue first** for non-trivial changes. Bug fixes and small tweaks
   can go straight to a PR, but anything that touches the wire format, the
   per-isolate state model, or the build profile deserves a design discussion
   before code lands.
2. **Fork the repository** and create a branch off `main`. Use a descriptive
   branch name (`fix/connect-leftover`, `feat/optimize-handshake`, …).
3. **Follow the existing code style**:
   - `rustfmt` defaults, no nightly-only style.
   - Public items have doc comments.
   - The hot path stays `#[inline]`-friendly; if your change adds a
     non-trivial allocation, leave a note in the PR.
4. **Commit messages** follow [Conventional Commits](https://www.conventionalcommits.org/):
   `feat: …`, `fix: …`, `refactor: …`, `docs: …`, `perf: …`, `test: …`, `chore: …`.
5. **Open a pull request** against `main`. Fill in the PR template; CI will
   run `cargo check`, `cargo fmt --check`, and `cargo build` for all three
   crates.
6. **One approval** from a CODEOWNER is required to merge.

## Build & test locally

```bash
# Format check (run on each crate)
cargo fmt --manifest-path relay/Cargo.toml   -- --check
cargo fmt --manifest-path sub/Cargo.toml     -- --check
cargo fmt --manifest-path tools/Cargo.toml   -- --check

# Compile (release; matches CI)
cargo build --release --target wasm32-unknown-unknown --manifest-path relay/Cargo.toml
cargo build --release --target wasm32-unknown-unknown --manifest-path sub/Cargo.toml
cargo build --release                                       --manifest-path tools/Cargo.toml

# Native build of the CLI for local link generation
cargo run --manifest-path tools/Cargo.toml -- gen-secret
```

## Project-specific notes

- **Cargo profile** — the relay uses `opt-level = "z"` for the local crate and
  `opt-level = 3` for everything else (`Cargo.toml`). Don't flip the global
  default to `3` without measuring the wasm size impact.
- **WASM features** — the relay enables `+simd128` (`.cargo/config.toml`).
  Don't add new intrinsics without verifying the resulting module still
  loads in workerd.
- **WebCrypto on the data path** — the bulk AES-GCM lives in the host. New
  data-path code should keep payload bytes in JS (the V8 heap) rather than
  bouncing them through wasm linear memory.
- **Per-isolate caches** — `OnceCell`/`thread_local!` are fine; never reach
  for `lazy_static`/`OnceLock` cross-thread primitives (Workers are
  single-threaded).
- **No telemetry** — this project does not phone home. Don't add a default-on
  network call to your feature; gate it behind a config flag and document it.

## Reporting bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).
Include the `wrangler --version` output and a minimal `wrangler tail` excerpt
(if you can reproduce it locally).

## Security

For vulnerabilities, **do not** file a public issue. Follow
[`SECURITY.md`](SECURITY.md).
