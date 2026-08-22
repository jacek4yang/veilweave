# Veilweave v2 control plane

## Lifecycle

The CLI and desktop are adapters over `veilweave-core`; they do not carry
separate Cloudflare orchestration. A deployment follows this sequence:

1. Load and validate the canonical relay/Sub bundle and its SHA-256 manifest.
2. Resolve account tokens from the OS credential store and verify ownership.
3. Reuse exact pre-existing resources or create journalled KV/resources.
4. Upload an inert Worker version with strict binding inheritance.
5. Promote that version to 100% through the Deployment API.
6. converge workers.dev and exact Custom Domain exposure.
7. Verify the selected primary endpoint.
8. Atomically persist stable and previous version/deployment IDs.

The transaction records resources as pre-existing, created, or updated. On an
error, compensations run in reverse order and never delete pre-existing user
resources. If local persistence fails after a healthy remote promotion, the
diagnostic reports retained remote state instead of claiming nothing changed.

## Bundles and Cloudflare 10162

In v1, `worker-build` generated `build/package.json`; release staging copied the
whole directory, and both deployers treated every recursive file as a Worker
module. The multipart upload therefore sent `package.json` as
`application/json`, which Cloudflare rejected with error 10162.

In v2, a `WorkerBundleManifest` declares only `index.js`, `index_bg.wasm`, and
`worker/shim.mjs` (plus explicitly modeled source maps when present). Each
entry has a role, kind, MIME type, size, and SHA-256. Unknown files, duplicate
paths, traversal, absolute paths, a missing main module, or a hash mismatch fail
locally. Build metadata is never relabeled or uploaded.

The deployed relay/Sub datapaths are otherwise unchanged; application proxy
settings affect only the local control plane and updater, never Worker request
latency. Compared with the v1.1.1 Windows release archive, the full shipped
relay bundle is 578,354 bytes instead of 628,787 (-8.0%), and the Sub bundle is
536,666 instead of 563,942 (-4.8%), even after adding the v2 manifest. No
per-run code nonce or other runtime mutation is used.

## Versions, rollback, and Durable Objects

Creating a Worker uses secret bindings for `SECRET_KEY`, `VEILWEAVE_NODES`, and
`SUBSCRIPTION_TOKEN`. Updates use Cloudflare strict inheritance and never read
secret values back. A coordinated relay endpoint change deliberately replaces
only `VEILWEAVE_NODES`; the subscription token is inherited.

The relay's initial version declares `VeilweaveSession` as a SQLite Durable
Object. Later code versions preserve the binding and omit class creation, so an
initial migration is not replayed. Rollback promotes the stored previous stable
version; the last known-good version is not deleted.

## Custom Domains

Every Worker can expose workers.dev only, one exact Custom Domain only, or
both. One enabled endpoint is primary. Zone ID/name and hostname membership are
validated, existing domain ownership is checked, and DNS conflicts are checked
when DNS Read is available. Cloudflare manages DNS and certificates; Veilweave
does not request DNS Write or create CNAMEs. Certificate provisioning is a
persisted state and does not destroy an otherwise healthy deployment.

Relay primary hostnames are serialized into `VEILWEAVE_NODES`; a Sub primary
hostname is used when generating its privileged subscription URL.

## Recovery

Recovery inventories Workers, versions/deployments, binding names and types,
KV namespaces, Durable Object bindings, workers.dev exposure, ownership
markers, and Custom Domains. Cloudflare secrets are treated as unreadable.
Candidates are classified as fully managed, adoptable, secret-unavailable,
broken, or unrelated. Adoption requires an explicit local credential link and
never converts a secret binding back to plaintext.
