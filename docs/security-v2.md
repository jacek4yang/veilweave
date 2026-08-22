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
