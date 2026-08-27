# v2 security model

The control-plane trust boundary includes the local config, OS credential
store, WebView, logs, Cloudflare account, configured proxy, GitHub Releases,
and CI signing secrets.

- A stolen TOML reveals names, IDs, endpoints, and topology, but no API token,
  relay secret, subscription token, proxy password, or private key.
- The WebView receives redacted account/deployment DTOs. A subscription URL is
  returned only by a dedicated user action and is not retained in normal UI
  state. Tauri plugin capabilities are not exposed directly to JavaScript.
- Secret values use Cloudflare secret bindings and zeroizing local wrappers;
  logs, errors, recovery snapshots, and network summaries never serialize them.
- Unrelated Worker ownership, Custom Domain ownership, and DNS conflicts are
  checked before mutation. Transaction rollback deletes only resources created
  by that transaction.
- Atomic config writes and a redacted backup recover interrupted/corrupt local
  state. One process-wide operation guard prevents overlapping topology writes.
- Explicit proxies fail closed. SOCKS5H avoids local DNS leakage by default.
- Desktop updates retain Tauri signature verification. CI owns the private key;
  only the matching public key is committed. Releases publish hashes, SBOMs,
  signed updater metadata, and platform artifacts.

Remaining risks that require operator controls include compromise of the local
OS account/credential store, a Cloudflare token with broader permissions than
documented, and compromise of GitHub Actions/release signing secrets. Use a
feature-scoped Cloudflare token, protect the GitHub environment and tag rules,
and revoke/rotate credentials after suspected exposure.

## Data-plane confidentiality

Outer TLS terminates at Cloudflare. In the default, Free-plan-compatible
`encryption=none` mode, Cloudflare can observe the VLESS header, target, and
payload after TLS termination. The signed UUID authenticates and carries an
egress capability; it does not encrypt the proxied stream.

The `VW1` secret format enables the experimental
`mlkem768x25519plus.native.1rtt` VLESS Encryption layer inside WebSocket. That
reduces what Cloudflare can observe but costs substantially more CPU and is not
the compatibility default. ECH is a separate outer-TLS feature, is disabled by
default, and must not be described as end-to-end payload encryption.

## Signed UUID v1 risk analysis

The deployed 16-byte capability format is intentionally unchanged:

```text
4-byte public nonce | 7-byte encrypted payload | 5-byte truncated MAC
```

The nonce is generated with WebCrypto. A 32-bit nonce begins to have a material
collision probability around 2^16 generated UUIDs under one key (the birthday
bound), although a collision exposes only equality of the seven-byte
keystream/payload combination and does not directly reveal the key. Operators
should rotate long-lived relay secrets periodically and after suspected
credential exposure.

The 40-bit MAC gives an online attacker roughly a 1 in 2^40 success probability
per independent forgery attempt. That is much stronger than an unauthenticated
identifier but weaker than modern 96/128-bit authentication tags. Rate limits,
Cloudflare abuse controls, and relay-secret rotation are important defense in
depth; the scheme must not be marketed as equivalent to a full-length MAC.
Failed MACs and unknown type bytes are rejected without an egress fallback.

Strengthening nonce/tag sizes cannot fit the existing UUID without breaking the
wire contract. Any replacement must be an explicit capability protocol v2 with
version negotiation and a migration period. It must not silently reinterpret
the v1 16 bytes.

## Protected E2E secrets

Live Cloudflare credentials are available only in the protected
`cloudflare-smoke` GitHub Environment. Fork PRs cannot invoke them. The workflow
masks the subscription token before constructing a URL, keeps signed UUIDs and
Xray configs in runner-temporary files, uploads only secret-free canonical
Worker bundles, and retires disposable Durable Object namespaces during
cleanup. Release packaging depends on that same E2E artifact generation.
