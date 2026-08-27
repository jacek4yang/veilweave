# CI and release gates

Ordinary pull requests run formatting, checks, Clippy with warnings denied,
unit tests for native and Worker crates, WebAssembly checks, real
`worker-build`, canonical bundle validation, secret scanning, and dependency
audit. These jobs establish compile/unit/bundle correctness; they do not claim
that a deployed proxy transports traffic.

## Protected live E2E

`.github/workflows/cloudflare-smoke.yml` is manually dispatchable and reusable
by the Release workflow. Its credentials exist only in the protected
`cloudflare-smoke` GitHub Environment, so untrusted fork PR code cannot access
them. Names include the Actions run ID/attempt and are confined to the dedicated
test account. Cleanup is trapped for every exit.

The job:

1. builds and validates the exact canonical relay/Sub bundles;
2. downloads Xray-core 25.6.8 from the official XTLS release and verifies the
   pinned Linux archive SHA-256;
3. deploys disposable relay, Sub, KV, Durable Objects, endpoints, and Cron;
4. verifies bootstrap from `https://zip.cm.edu.kg/all.json`;
5. masks the subscription token before constructing any URL;
6. proves invalid-token 404 behavior;
7. deletes both known-good KV generations to observe a real cold 503, then
   performs an authenticated refresh and warm reads;
8. validates raw/Base64 headers and every VLESS URI, secure-mode separation,
   Japan override, and Japan/US filtering;
9. updates and rolls back every Worker;
10. runs Xray with one generated node and completes HTTPS through SOCKS to an
    ordinary Internet domain and a Cloudflare-hosted Worker target. The latter
    exercises signed proxyIP decoding and direct-then-proxyIP fallback;
11. promotes Durable Object deletion tombstones, removes Workers/KV/domains,
    and compares Durable Object namespaces with the pre-test snapshot.

No subscription body, signed UUID, Xray config, token, or relay secret is
uploaded. The only uploaded artifact is `tested-worker-bundles`.

## Stable release provenance

The Release workflow calls the protected E2E as its first job. Tools and Worker
packaging require it. The Worker packaging job downloads
`tested-worker-bundles` from that same workflow run, validates it again, and
uses those exact bytes for CLI archives and desktop embedding. A compile-only
artifact cannot bypass the live gate.

`VERSION` is the release version source and `scripts/check_version.py` rejects
component drift. Tauri updater artifacts are signed with the CI-only private
key; the matching public key is committed. Release outputs include updater
metadata, per-platform artifacts, SHA-256 sums, and a CycloneDX SBOM.

Before tagging, confirm the protected test account quota and environment token
permissions. After publishing, download every asset, verify `SHA256SUMS`, check
all updater platform URLs/signatures, validate each CLI archive's Worker
manifests, and test one signed update from the previous desktop release. Never
commit or print signing credentials.
