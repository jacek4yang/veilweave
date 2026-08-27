# Declarative deployment

`veilweave.toml` is a secret-free desired topology. Account values resolve to a
configured label or stable Cloudflare account ID. Unknown fields—including
attempts to embed tokens or Worker secrets—are rejected.

```toml
version = 2

[topology]
encryption = "none"

[sub]
account = "production"
worker = "subscription-service"
kv_title = "subscription-service-kv"
kv_binding = "VEILWEAVE_KV"

[sub.endpoint]
mode = "custom-domain"
primary = "custom-domain"
hostname = "sub.example.com"
zone_id = "cloudflare-zone-id"
zone_name = "example.com"

[sub.settings]
max_nodes = 100
fingerprint = "chrome"
# ech = "example-ech-config" # optional; disabled by default

[[relay]]
account = "production"
worker = "edge-us"

[relay.endpoint]
mode = "both"
primary = "custom-domain"
hostname = "us.example.com"
zone_id = "cloudflare-zone-id"
zone_name = "example.com"
```

Use `plan --config veilweave.toml` for local validation and a redacted plan.
Use `apply --config veilweave.toml --dry-run` to include bundle/account checks
without mutation, then `apply --config veilweave.toml --yes`. `status`,
`update --deployment <uuid>`, and `rollback --deployment <uuid>` operate on
the persisted v2 deployment IDs. `doctor --json`, `recover --account ...`, and
`domain --account ...` provide automation-friendly diagnostics. Sub proxyIP
state is automatic and fixed to `https://zip.cm.edu.kg/all.json`; no
`PROXYIP_LIST` field exists. Use `proxyip status|refresh --deployment <uuid>`
for authenticated cache management and `delete --deployment <uuid>` for
noninteractive Worker/KV/Durable Object cleanup.
