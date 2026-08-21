//! Async client for the Cloudflare API v4 — everything the direct-deploy path
//! needs: token verification, account/subdomain lookup, KV namespaces, worker
//! script uploads (multipart), workers.dev enablement, and deletion.
//!
//! Verified against the official docs and wrangler's own upload code:
//! - script upload: PUT /accounts/{id}/workers/scripts/{name}, multipart with a
//!   `metadata` part (JSON) + one part per module file
//! - Durable Object first deploy: `migrations: {new_tag, steps: [{new_sqlite_classes}]}`
//! - workers.dev: POST /accounts/{id}/workers/scripts/{name}/subdomain {enabled:true}

use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::path::{Path, PathBuf};

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Matches relay/wrangler.toml and sub/wrangler.toml.
pub const COMPATIBILITY_DATE: &str = "2026-05-26";

/// One file of a worker upload: part name is the path relative to the build
/// dir (forward slashes), so module imports resolve exactly as on disk.
pub struct UploadFile {
    pub name: String,
    pub contents: Vec<u8>,
    pub content_type: &'static str,
}

#[derive(Debug, Clone)]
pub struct AccountSummary {
    pub id: String,
    pub name: String,
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: Option<T>,
}

#[derive(Deserialize, Debug)]
struct ApiError {
    code: i64,
    message: String,
}

pub struct CfClient {
    http: reqwest::Client,
    token: String,
}

impl CfClient {
    pub fn new(token: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("veilweave-tools/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build HTTP client")?;
        Ok(Self {
            http,
            token: token.to_string(),
        })
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http
            .get(format!("{API_BASE}{path}"))
            .bearer_auth(&self.token)
    }

    /// Send a request and unwrap the Cloudflare `{success, errors, result}`
    /// envelope into either the typed result or a readable error.
    async fn send<T: DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
        what: &str,
    ) -> Result<T> {
        let resp = req
            .send()
            .await
            .with_context(|| format!("{what}: request failed"))?;
        let status = resp.status();
        let body: Envelope<T> = resp
            .json()
            .await
            .with_context(|| format!("{what}: unexpected response (HTTP {status})"))?;
        if !body.success {
            bail!("{what}: {}", format_api_errors(&body.errors, status));
        }
        body.result
            .ok_or_else(|| anyhow!("{what}: API returned no result"))
    }

    /// Like `send` for endpoints whose `result` payload we ignore (uploads,
    /// subdomain toggles, deletes — some of these return `result: null`).
    async fn send_ok(&self, req: reqwest::RequestBuilder, what: &str) -> Result<()> {
        let resp = req
            .send()
            .await
            .with_context(|| format!("{what}: request failed"))?;
        let status = resp.status();
        let body: Envelope<serde_json::Value> = resp
            .json()
            .await
            .with_context(|| format!("{what}: unexpected response (HTTP {status})"))?;
        if !body.success {
            bail!("{what}: {}", format_api_errors(&body.errors, status));
        }
        Ok(())
    }

    /// GET /user/tokens/verify — fails unless the token is active.
    pub async fn verify_token(&self) -> Result<()> {
        #[derive(Deserialize)]
        struct TokenStatus {
            status: String,
        }
        let r: TokenStatus = self
            .send(self.get("/user/tokens/verify"), "verify API token")
            .await?;
        if r.status != "active" {
            bail!(
                "verify API token: token status is {:?}, expected \"active\"",
                r.status
            );
        }
        Ok(())
    }

    /// GET /accounts — accounts the token can see.
    pub async fn list_accounts(&self) -> Result<Vec<AccountSummary>> {
        #[derive(Deserialize)]
        struct Raw {
            id: String,
            name: String,
        }
        let r: Vec<Raw> = self
            .send(self.get("/accounts?per_page=50"), "list accounts")
            .await?;
        Ok(r.into_iter()
            .map(|a| AccountSummary {
                id: a.id,
                name: a.name,
            })
            .collect())
    }

    /// GET /accounts/{id}/workers/subdomain — the account's workers.dev subdomain.
    pub async fn get_workers_subdomain(&self, account_id: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct Subdomain {
            subdomain: String,
        }
        let r: Subdomain = self
            .send(
                self.get(&format!("/accounts/{account_id}/workers/subdomain")),
                "get workers.dev subdomain",
            )
            .await
            .context(
                "no workers.dev subdomain — create one in the dashboard \
                 (Workers & Pages → your account → workers.dev)",
            )?;
        Ok(r.subdomain)
    }

    /// POST /accounts/{id}/storage/kv/namespaces — returns the new namespace id.
    pub async fn create_kv_namespace(&self, account_id: &str, title: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct Ns {
            id: String,
        }
        let req = self
            .http
            .post(format!(
                "{API_BASE}/accounts/{account_id}/storage/kv/namespaces"
            ))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "title": title }));
        let r: Ns = self.send(req, "create KV namespace").await?;
        Ok(r.id)
    }

    /// PUT /accounts/{id}/workers/scripts/{name} — multipart upload of `files`
    /// plus the JSON `metadata` part (see `relay_metadata` / `sub_metadata`).
    pub async fn upload_worker(
        &self,
        account_id: &str,
        name: &str,
        files: Vec<UploadFile>,
        metadata: serde_json::Value,
    ) -> Result<()> {
        let mut form = reqwest::multipart::Form::new().part(
            "metadata",
            reqwest::multipart::Part::text(metadata.to_string())
                .mime_str("application/json")
                .context("metadata content type")?,
        );
        for f in files {
            let part = reqwest::multipart::Part::bytes(f.contents)
                .file_name(f.name.clone())
                .mime_str(f.content_type)
                .with_context(|| format!("content type for {}", f.name))?;
            form = form.part(f.name, part);
        }
        let req = self
            .http
            .put(format!(
                "{API_BASE}/accounts/{account_id}/workers/scripts/{name}"
            ))
            .bearer_auth(&self.token)
            .multipart(form);
        self.send_ok(req, &format!("upload worker {name:?}"))
            .await?;
        Ok(())
    }

    /// POST /accounts/{id}/workers/scripts/{name}/subdomain {enabled:true}.
    pub async fn enable_workers_dev(&self, account_id: &str, name: &str) -> Result<()> {
        let req = self
            .http
            .post(format!(
                "{API_BASE}/accounts/{account_id}/workers/scripts/{name}/subdomain"
            ))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "enabled": true }));
        self.send_ok(req, &format!("enable workers.dev for {name:?}"))
            .await?;
        Ok(())
    }

    pub async fn delete_worker(&self, account_id: &str, name: &str) -> Result<()> {
        let req = self
            .http
            .delete(format!(
                "{API_BASE}/accounts/{account_id}/workers/scripts/{name}"
            ))
            .bearer_auth(&self.token);
        self.send_ok(req, &format!("delete worker {name:?}"))
            .await?;
        Ok(())
    }

    pub async fn delete_kv_namespace(&self, account_id: &str, namespace_id: &str) -> Result<()> {
        let req = self
            .http
            .delete(format!(
                "{API_BASE}/accounts/{account_id}/storage/kv/namespaces/{namespace_id}"
            ))
            .bearer_auth(&self.token);
        self.send_ok(req, "delete KV namespace").await?;
        Ok(())
    }

    /// GET /accounts/{id}/workers/scripts — every script on the account.
    pub async fn list_workers(&self, account_id: &str) -> Result<Vec<WorkerScript>> {
        #[derive(Deserialize)]
        struct Raw {
            id: String,
            created_on: Option<String>,
        }
        let r: Vec<Raw> = self
            .send(
                self.get(&format!("/accounts/{account_id}/workers/scripts")),
                "list workers",
            )
            .await?;
        Ok(r.into_iter()
            .map(|w| WorkerScript {
                id: w.id,
                created_on: w.created_on,
            })
            .collect())
    }

    /// GET /accounts/{id}/workers/scripts/{name}/settings — the
    /// ScriptAndVersionSettings endpoint (wrangler's own SDK uses it; unlike
    /// the newer `script-settings` variant it returns `bindings`). plain_text
    /// values ARE readable here — this is the config-recovery mechanism.
    pub async fn get_script_settings(
        &self,
        account_id: &str,
        name: &str,
    ) -> Result<Vec<BindingInfo>> {
        let v: serde_json::Value = self
            .send(
                self.get(&format!(
                    "/accounts/{account_id}/workers/scripts/{name}/settings"
                )),
                &format!("get settings for {name:?}"),
            )
            .await?;
        let bindings = v["bindings"].as_array().cloned().unwrap_or_default();
        Ok(bindings
            .iter()
            .map(|b| BindingInfo {
                name: b["name"].as_str().unwrap_or_default().to_string(),
                kind: b["type"].as_str().unwrap_or_default().to_string(),
                text: b["text"].as_str().map(str::to_string),
                namespace_id: b["namespace_id"].as_str().map(str::to_string),
                class_name: b["class_name"].as_str().map(str::to_string),
            })
            .collect())
    }

    /// GET /accounts/{id}/storage/kv/namespaces — all namespaces, following
    /// `page` until a short page comes back (per_page=100).
    pub async fn list_kv_namespaces(&self, account_id: &str) -> Result<Vec<KvNamespace>> {
        #[derive(Deserialize)]
        struct Raw {
            id: String,
            title: String,
        }
        let mut out = Vec::new();
        let mut page = 1u32;
        loop {
            let batch: Vec<Raw> = self
                .send(
                    self.get(&format!(
                        "/accounts/{account_id}/storage/kv/namespaces?per_page=100&page={page}"
                    )),
                    "list KV namespaces",
                )
                .await?;
            let short = batch.len() < 100;
            out.extend(batch.into_iter().map(|n| KvNamespace {
                id: n.id,
                title: n.title,
            }));
            if short {
                return Ok(out);
            }
            page += 1;
        }
    }

    /// Today's per-script usage via the GraphQL Analytics API
    /// (POST /client/v4/graphql, dataset `workersInvocationsAdaptive`).
    ///
    /// REQUIRES the `Account → Account Analytics → Read` token permission;
    /// without it Cloudflare hides the dataset and the query fails with
    /// `unknown field "workersInvocationsAdaptive"` — callers must treat any
    /// error here as non-fatal (the UI shows "需要 Analytics Read 权限 /
    /// needs Analytics Read").
    pub async fn account_usage(&self, account_id: &str) -> Result<Vec<UsageRow>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let day_start = now - now % 86_400;
        let body = serde_json::json!({
            "query": "query($account: String!, $from: Time!, $to: Time!) { viewer { accounts(filter: {accountTag: $account}) { workersInvocationsAdaptive(limit: 100, filter: {datetime_geq: $from, datetime_leq: $to}) { dimensions { scriptName } sum { requests errors } quantiles { cpuTimeP50 } } } } }",
            "variables": {
                "account": account_id,
                "from": crate::config::format_unix_utc(day_start),
                "to": crate::config::format_unix_utc(now),
            },
        });
        let resp = self
            .http
            .post(format!("{API_BASE}/graphql"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .context("account usage: request failed")?;
        // GraphQL returns HTTP 200 even for errors — check the errors array.
        let v: serde_json::Value = resp.json().await.context("account usage: bad response")?;
        if let Some(errors) = v["errors"].as_array().filter(|e| !e.is_empty()) {
            let msgs = errors
                .iter()
                .filter_map(|e| e["message"].as_str())
                .collect::<Vec<_>>()
                .join("; ");
            bail!("account usage: {msgs}");
        }
        let groups = v["data"]["viewer"]["accounts"][0]["workersInvocationsAdaptive"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        Ok(groups
            .iter()
            .map(|g| UsageRow {
                script: g["dimensions"]["scriptName"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                requests: g["sum"]["requests"].as_u64().unwrap_or(0),
                errors: g["sum"]["errors"].as_u64().unwrap_or(0),
                cpu_p50_us: g["quantiles"]["cpuTimeP50"].as_f64().unwrap_or(0.0),
            })
            .collect())
    }
}

/// A worker script as returned by the scripts list endpoint.
#[derive(Debug, Clone)]
pub struct WorkerScript {
    pub id: String,
    pub created_on: Option<String>,
}

/// One binding as reported by the script settings endpoint. `text` is only
/// present for `plain_text` (secrets of type `secret_text` are never
/// readable via the API).
#[derive(Debug, Clone, Default)]
pub struct BindingInfo {
    pub name: String,
    /// Binding type string: "plain_text", "kv_namespace",
    /// "durable_object_namespace", "secret_text", …
    pub kind: String,
    pub text: Option<String>,
    pub namespace_id: Option<String>,
    pub class_name: Option<String>,
}

/// A KV namespace (id + title).
#[derive(Debug, Clone)]
pub struct KvNamespace {
    pub id: String,
    pub title: String,
}

/// Free-plan daily request cap — for UI usage ratios.
pub const FREE_TIER_DAILY_REQUESTS: u64 = 100_000;

/// Per-script usage for the current UTC day. `cpu_p50_us` is the P50 CPU
/// time per invocation in microseconds (GraphQL `cpuTimeP50`).
#[derive(Debug, Clone)]
pub struct UsageRow {
    pub script: String,
    pub requests: u64,
    pub errors: u64,
    pub cpu_p50_us: f64,
}

fn format_api_errors(errors: &[ApiError], status: reqwest::StatusCode) -> String {
    if errors.is_empty() {
        return format!("Cloudflare API error (HTTP {status})");
    }
    errors
        .iter()
        .map(|e| format!("[{}] {}", e.code, e.message))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Read every file under `build_dir` into upload parts. Part names are
/// relative paths with forward slashes, matching the module import specifiers.
pub fn collect_build_files(build_dir: &Path) -> Result<Vec<UploadFile>> {
    let mut files = Vec::new();
    collect_into(build_dir, build_dir, &mut files)?;
    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(files)
}

/// MIME content type for a worker upload part, by file extension.
pub fn content_type_for(name: &str) -> &'static str {
    match name.rsplit('.').next() {
        Some("js") | Some("mjs") => "application/javascript+module",
        Some("wasm") => "application/wasm",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

fn collect_into(root: &Path, dir: &Path, out: &mut Vec<UploadFile>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path: PathBuf = entry?.path();
        if path.is_dir() {
            collect_into(root, &path, out)?;
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        out.push(UploadFile {
            content_type: content_type_for(&rel),
            name: rel,
            contents: std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
        });
    }
    Ok(())
}

/// Upload metadata for a relay worker. The Durable Object binding and the
/// SQLite migration are REQUIRED even in plaintext mode — VeilweaveSession
/// still hosts the WebSocket connection state.
pub fn relay_metadata(secret: &str) -> serde_json::Value {
    serde_json::json!({
        "main_module": "index.js",
        "compatibility_date": COMPATIBILITY_DATE,
        "compatibility_flags": ["nodejs_compat"],
        "bindings": [
            { "name": "SECRET_KEY", "type": "plain_text", "text": secret },
            {
                "name": "VEILWEAVE_SESSION",
                "type": "durable_object_namespace",
                "class_name": "VeilweaveSession",
            },
        ],
        "migrations": {
            "new_tag": "v1",
            "steps": [{ "new_sqlite_classes": ["VeilweaveSession"] }],
        },
    })
}

/// Upload metadata for a sub worker. The worker resolves its KV namespace via
/// the `KV_BINDING` var (lookup order: KV_BINDING → VEILWEAVE_KV → KV), so the
/// `KV_BINDING` plain-text var and the `kv_namespace` binding must match.
pub fn sub_metadata(
    nodes: &str,
    subscription_token: &str,
    kv_binding: &str,
    kv_namespace_id: &str,
) -> serde_json::Value {
    let var = |name: &str, text: &str| serde_json::json!({ "name": name, "type": "plain_text", "text": text });
    serde_json::json!({
        "main_module": "index.js",
        "compatibility_date": COMPATIBILITY_DATE,
        "compatibility_flags": ["nodejs_compat"],
        "bindings": [
            var("KV_BINDING", kv_binding),
            var("VEILWEAVE_NODES", nodes),
            var("SUBSCRIPTION_TOKEN", subscription_token),
            var("MAX_NODES", "100"),
            var("FP", "chrome"),
            var("DISABLE_BUILTIN_PROXYIP", "false"),
            {
                "name": kv_binding,
                "type": "kv_namespace",
                "namespace_id": kv_namespace_id,
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_metadata_has_do_binding_and_sqlite_migration() {
        let m = relay_metadata("test-secret");
        assert_eq!(m["main_module"], "index.js");
        assert_eq!(
            m["compatibility_flags"],
            serde_json::json!(["nodejs_compat"])
        );

        let bindings = m["bindings"].as_array().unwrap();
        let secret = bindings
            .iter()
            .find(|b| b["name"] == "SECRET_KEY")
            .expect("SECRET_KEY binding");
        assert_eq!(secret["type"], "plain_text");
        assert_eq!(secret["text"], "test-secret");

        let dob = bindings
            .iter()
            .find(|b| b["name"] == "VEILWEAVE_SESSION")
            .expect("DO binding");
        assert_eq!(dob["type"], "durable_object_namespace");
        assert_eq!(dob["class_name"], "VeilweaveSession");

        // First deploy of a SQLite-backed DO class: new_tag + steps form,
        // exactly what wrangler sends (verified against wrangler source).
        assert_eq!(m["migrations"]["new_tag"], "v1");
        assert_eq!(
            m["migrations"]["steps"][0]["new_sqlite_classes"],
            serde_json::json!(["VeilweaveSession"])
        );
    }

    #[test]
    fn sub_metadata_has_kv_binding_var_and_namespace() {
        let m = sub_metadata("a.dev|s1,b.dev|s2", "tok", "kv_x7f2a9", "ns-id-123");
        assert_eq!(m["main_module"], "index.js");

        let bindings = m["bindings"].as_array().unwrap();
        let var = bindings
            .iter()
            .find(|b| b["name"] == "KV_BINDING")
            .expect("KV_BINDING var");
        assert_eq!(var["type"], "plain_text");
        assert_eq!(var["text"], "kv_x7f2a9");

        let nodes = bindings
            .iter()
            .find(|b| b["name"] == "VEILWEAVE_NODES")
            .expect("VEILWEAVE_NODES var");
        assert_eq!(nodes["text"], "a.dev|s1,b.dev|s2");

        let kv = bindings
            .iter()
            .find(|b| b["type"] == "kv_namespace")
            .expect("kv_namespace binding");
        assert_eq!(kv["name"], "kv_x7f2a9");
        assert_eq!(kv["namespace_id"], "ns-id-123");

        for required in [
            "SUBSCRIPTION_TOKEN",
            "MAX_NODES",
            "FP",
            "DISABLE_BUILTIN_PROXYIP",
        ] {
            assert!(
                bindings.iter().any(|b| b["name"] == required),
                "missing var {required}"
            );
        }
    }
}
