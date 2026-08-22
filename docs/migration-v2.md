# Migrating from v1 to v2

On first startup, v2 recognizes the v1 configuration before any remote
mutation. It validates the complete input, writes API tokens and deployment
secrets to the OS credential store, reads each value back to verify it, then
atomically installs schema-v2 TOML containing stable IDs and credential
references only. The old plaintext primary file is retired only after all
credential writes succeed; the durability backup is also redacted.

If any secure-store write or verification fails, migration stops and the v1
file remains the authoritative copy. Veilweave never silently falls back to a
plaintext credential file. Headless environments may use explicit `env:NAME`
references or an interactive ephemeral token.

Launching v2 does not rewrite production Workers. Existing v1 plaintext
bindings continue to run. The next explicit coordinated update uploads a v2
version with secret bindings while preserving the topology and known-good
version. Keep an external encrypted backup until the migrated configuration
and credentials have been tested with `veilweave-tools doctor`.

Recovery cannot retrieve secret values from Cloudflare. If the local secure
credential is gone, scan still inventories the Worker but marks secret material
unavailable; re-link or rotate the topology explicitly. When the OS credential
store or environment references still contain the exact deployed values,
re-link one secure v2 Worker without exposing them:

```text
veilweave-tools recover --account production --adopt-worker edge-one \
  --worker-secret-ref env:EDGE_ONE_WORKER_SECRET \
  --node-secret-ref env:EDGE_ONE_NODE_SECRET
```

For a Sub Worker, provide `--subscription-token-ref` instead of
`--node-secret-ref`. Add `--primary custom-domain` when its recovered primary
endpoint is a Custom Domain. Adoption refuses unrelated, legacy-plaintext, and
broken bindings; repair or securely rotate those remotely first.
