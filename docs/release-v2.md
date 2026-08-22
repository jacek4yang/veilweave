# v2 CI and release

Pull requests run formatting, checks, Clippy with warnings denied, tests for
core/tools/relay/Sub/desktop, WebAssembly checks, a real `worker-build`,
canonical bundle validation, secret scanning, and dependency audit. Ordinary
PRs need no Cloudflare credentials. A protected smoke workflow may deploy only
to explicitly configured test accounts and resource prefixes.

`VERSION` is the release version source and `scripts/check_version.py` rejects
component drift. A `v2.0.0` tag must point at the reviewed merge commit. The
tag-triggered Release workflow builds Workers once, validates the exact bundles
embedded/shipped on Windows, Linux, and macOS, signs updater artifacts using the
CI-only Tauri private key, creates `latest.json`, and publishes SHA-256 hashes
and CycloneDX SBOMs.

Before tagging, verify that the configured Tauri public key matches the CI
private key in a protected dry run. After publishing, download every asset,
verify `SHA256SUMS`, confirm all three updater platforms and URLs in
`latest.json`, validate each CLI archive's Worker manifests, and perform one
signed update from the previous desktop release. Never commit or print the
private signing key or its password.
