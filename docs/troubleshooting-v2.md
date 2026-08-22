# Doctor and troubleshooting

Run `veilweave-tools doctor` (or `--json`) before changing remote state. It
checks local schema, credential availability, the canonical bundle, current
network policy, Cloudflare reachability, and the GitHub update endpoint without
printing credentials.

## Cloudflare 10162

If Cloudflare reports `module package.json has unsupported Content-Type
application/json`, the artifact is not a v2 canonical bundle. `package.json` is
worker-build metadata, not a runtime module. Re-download the complete v2
archive or run `worker-bundle prepare`, then `worker-bundle validate`. Do not
rename the MIME type.

## Proxy failures

“proxy unreachable” means the configured host/port did not accept TCP.
“authentication failed” means SOCKS/HTTP credentials were rejected. A local
DNS error with SOCKS5 usually means proxy-side DNS is disabled; use SOCKS5H.
TLS and HTTP failures are reported separately. Veilweave does not retry direct
when an explicit proxy fails.

## Domains and certificates

An exact hostname must be inside the selected active zone and not be attached
to another Worker. Remove conflicting DNS records yourself; Veilweave does not
request DNS Write. `provisioning` is normal immediately after attach. An error
state is retained for inspection instead of deleting an otherwise healthy
Worker.

## Interrupted deployments

Read the transaction journal in the final error. `compensated` resources were
rolled back; `retained` entries still exist and include exact identifiers.
`recover` rescans them without reading secrets. Never delete a retained KV or
domain solely by name without checking ownership.
