//! Typed Cloudflare API v4 client used by every control-plane operation.
//!
//! Worker code is uploaded as an inert version first. A separate deployment
//! request promotes that version, which makes health verification and rollback
//! possible without destroying the last known-good version.

use crate::bundle::WorkerBundle;
use crate::credentials::SecretValue;
use crate::network::NetworkManager;
use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use reqwest::{Method, RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

pub const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";
pub const COMPATIBILITY_DATE: &str = "2026-05-26";
pub const OWNERSHIP_BINDING: &str = "VEILWEAVE_MANAGED";
pub const OWNERSHIP_RELAY: &str = "veilweave:v2:relay";
pub const OWNERSHIP_SUB: &str = "veilweave:v2:sub";
pub const FREE_TIER_DAILY_REQUESTS: u64 = 100_000;

/// Deserialize `null` as `Default::default()` instead of failing.
fn deserialize_null_default<'de, D, T: Default + Deserialize<'de>>(
    deserializer: D,
) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    Option::<T>::deserialize(deserializer).map(|opt| opt.unwrap_or_default())
}

#[derive(Clone)]
pub struct CfClient {
    network: NetworkManager,
    token: SecretValue,
    api_base: String,
    max_safe_retries: u8,
}

impl fmt::Debug for CfClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CfClient")
            .field("network", &self.network)
            .field("token", &"[REDACTED]")
            .field("api_base", &self.api_base)
            .finish()
    }
}

impl CfClient {
    /// Direct-mode convenience for compatibility and tests. Application and
    /// CLI entry points use [`CfClient::with_network`] so policy is shared.
    pub fn new(token: &str) -> Result<Self> {
        Self::with_network(token, NetworkManager::direct()?)
    }

    pub fn with_network(token: &str, network: NetworkManager) -> Result<Self> {
        if token.trim().is_empty() {
            bail!("Cloudflare API token is empty");
        }
        Ok(Self {
            network,
            token: SecretValue::new(token),
            api_base: DEFAULT_API_BASE.into(),
            max_safe_retries: 3,
        })
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Result<Self> {
        let api_base = api_base.into().trim_end_matches('/').to_string();
        reqwest::Url::parse(&api_base).context("invalid Cloudflare API base URL")?;
        self.api_base = api_base;
        Ok(self)
    }

    pub fn network(&self) -> &NetworkManager {
        &self.network
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.network
            .snapshot()
            .client()
            .request(method, format!("{}{path}", self.api_base))
            .bearer_auth(self.token.expose())
    }

    fn get(&self, path: &str) -> RequestBuilder {
        self.request(Method::GET, path)
    }

    async fn send<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        operation: &str,
        safe_to_retry: bool,
    ) -> Result<T> {
        let attempts = if safe_to_retry {
            self.max_safe_retries.saturating_add(1)
        } else {
            1
        };
        let mut one_shot = Some(request);
        for attempt in 0..attempts {
            let current = if attempts == 1 {
                one_shot.take().expect("one-shot request is available")
            } else {
                one_shot
                    .as_ref()
                    .and_then(RequestBuilder::try_clone)
                    .context("Cloudflare request body cannot be replayed")?
            };
            match self.send_once(current, operation).await {
                Ok(result) => return Ok(result),
                Err(error) if safe_to_retry && attempt + 1 < attempts && error.retryable() => {
                    let delay = error.retry_after.unwrap_or_else(|| {
                        let base = 200u64.saturating_mul(1u64 << attempt.min(5));
                        Duration::from_millis(base + rand::thread_rng().gen_range(0..=100))
                    });
                    tokio::time::sleep(delay.min(Duration::from_secs(10))).await;
                }
                Err(error) => return Err(anyhow!(error)),
            }
        }
        unreachable!("request attempt loop always returns")
    }

    async fn send_once<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        operation: &str,
    ) -> std::result::Result<T, CfApiFailure> {
        let response = request.send().await.map_err(|source| {
            let category = if source.is_timeout() {
                "timeout"
            } else if source.is_connect() {
                "connection"
            } else {
                "transport"
            };
            CfApiFailure {
                operation: operation.into(),
                status: None,
                codes: vec![],
                messages: vec![format!("{category} failure: {source}")],
                cf_ray: None,
                retry_after: None,
            }
        })?;
        let status = response.status();
        let cf_ray = response
            .headers()
            .get("cf-ray")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let retry_after = parse_retry_after(response.headers());
        let bytes = response.bytes().await.map_err(|source| CfApiFailure {
            operation: operation.into(),
            status: Some(status),
            codes: vec![],
            messages: vec![format!("failed to read response: {source}")],
            cf_ray: cf_ray.clone(),
            retry_after,
        })?;
        let envelope: Envelope<T> =
            serde_json::from_slice(&bytes).map_err(|source| CfApiFailure {
                operation: operation.into(),
                status: Some(status),
                codes: vec![],
                messages: vec![format!(
                    "malformed API response ({source}); body preview: {}",
                    safe_body_preview(&bytes)
                )],
                cf_ray: cf_ray.clone(),
                retry_after,
            })?;
        if !status.is_success() || !envelope.success {
            return Err(CfApiFailure {
                operation: operation.into(),
                status: Some(status),
                codes: envelope.errors.iter().map(|error| error.code).collect(),
                messages: envelope
                    .errors
                    .iter()
                    .map(|error| error.message.clone())
                    .collect(),
                cf_ray,
                retry_after,
            });
        }
        envelope.result.ok_or_else(|| CfApiFailure {
            operation: operation.into(),
            status: Some(status),
            codes: vec![],
            messages: vec!["Cloudflare returned success without a result".into()],
            cf_ray,
            retry_after,
        })
    }

    async fn send_ok(
        &self,
        request: RequestBuilder,
        operation: &str,
        safe_to_retry: bool,
    ) -> Result<()> {
        let attempts = if safe_to_retry {
            self.max_safe_retries.saturating_add(1)
        } else {
            1
        };
        let mut one_shot = Some(request);
        for attempt in 0..attempts {
            let current = if attempts == 1 {
                one_shot.take().expect("one-shot request is available")
            } else {
                one_shot
                    .as_ref()
                    .and_then(RequestBuilder::try_clone)
                    .context("Cloudflare request body cannot be replayed")?
            };
            match self.send_ok_once(current, operation).await {
                Ok(()) => return Ok(()),
                Err(error) if safe_to_retry && attempt + 1 < attempts && error.retryable() => {
                    let delay = error.retry_after.unwrap_or_else(|| {
                        Duration::from_millis(200u64.saturating_mul(1u64 << attempt.min(5)))
                    });
                    tokio::time::sleep(delay.min(Duration::from_secs(10))).await;
                }
                Err(error) => return Err(anyhow!(error)),
            }
        }
        unreachable!("request attempt loop always returns")
    }

    async fn send_ok_once(
        &self,
        request: RequestBuilder,
        operation: &str,
    ) -> std::result::Result<(), CfApiFailure> {
        let response = request.send().await.map_err(|source| CfApiFailure {
            operation: operation.into(),
            status: None,
            codes: vec![],
            messages: vec![source.to_string()],
            cf_ray: None,
            retry_after: None,
        })?;
        let status = response.status();
        let cf_ray = response
            .headers()
            .get("cf-ray")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let retry_after = parse_retry_after(response.headers());
        let bytes = response.bytes().await.map_err(|source| CfApiFailure {
            operation: operation.into(),
            status: Some(status),
            codes: vec![],
            messages: vec![source.to_string()],
            cf_ray: cf_ray.clone(),
            retry_after,
        })?;
        let envelope: Envelope<serde_json::Value> =
            serde_json::from_slice(&bytes).map_err(|source| CfApiFailure {
                operation: operation.into(),
                status: Some(status),
                codes: vec![],
                messages: vec![format!(
                    "malformed API response ({source}); body preview: {}",
                    safe_body_preview(&bytes)
                )],
                cf_ray: cf_ray.clone(),
                retry_after,
            })?;
        if status.is_success() && envelope.success {
            return Ok(());
        }
        Err(CfApiFailure {
            operation: operation.into(),
            status: Some(status),
            codes: envelope.errors.iter().map(|error| error.code).collect(),
            messages: envelope
                .errors
                .iter()
                .map(|error| error.message.clone())
                .collect(),
            cf_ray,
            retry_after,
        })
    }

    pub async fn verify_token(&self) -> Result<()> {
        let status: TokenStatus = self
            .send(self.get("/user/tokens/verify"), "verify API token", true)
            .await?;
        if status.status != "active" {
            bail!(
                "verify API token: expected active status, got {:?}",
                status.status
            );
        }
        Ok(())
    }

    pub async fn list_accounts(&self) -> Result<Vec<AccountSummary>> {
        self.send(self.get("/accounts?per_page=50"), "list accounts", true)
            .await
    }

    pub async fn get_workers_subdomain(&self, account_id: &str) -> Result<String> {
        let value: WorkersSubdomain = self
            .send(
                self.get(&format!("/accounts/{account_id}/workers/subdomain")),
                "get workers.dev subdomain",
                true,
            )
            .await?;
        Ok(value.subdomain)
    }

    pub async fn get_workers_dev_state(
        &self,
        account_id: &str,
        script: &str,
    ) -> Result<WorkersDevState> {
        self.send(
            self.get(&format!(
                "/accounts/{account_id}/workers/scripts/{script}/subdomain"
            )),
            "get workers.dev state",
            true,
        )
        .await
    }

    pub async fn set_workers_dev(
        &self,
        account_id: &str,
        script: &str,
        enabled: bool,
    ) -> Result<()> {
        let request = self
            .request(
                Method::POST,
                &format!("/accounts/{account_id}/workers/scripts/{script}/subdomain"),
            )
            .json(&serde_json::json!({ "enabled": enabled }));
        self.send_ok(request, "set workers.dev state", false).await
    }

    pub async fn enable_workers_dev(&self, account_id: &str, script: &str) -> Result<()> {
        self.set_workers_dev(account_id, script, true).await
    }

    pub async fn get_cron_schedules(&self, account_id: &str, script: &str) -> Result<Vec<String>> {
        let result: CronSchedules = self
            .send(
                self.get(&format!(
                    "/accounts/{account_id}/workers/scripts/{script}/schedules"
                )),
                "get Worker Cron Triggers",
                true,
            )
            .await?;
        Ok(result
            .schedules
            .into_iter()
            .map(|schedule| schedule.cron)
            .collect())
    }

    /// Replace all Cron Triggers for a Worker. This PUT is idempotent: retrying
    /// the exact body cannot create duplicate schedules.
    pub async fn set_cron_schedules(
        &self,
        account_id: &str,
        script: &str,
        schedules: &[String],
    ) -> Result<Vec<String>> {
        let body: Vec<serde_json::Value> = schedules
            .iter()
            .map(|cron| serde_json::json!({ "cron": cron }))
            .collect();
        let result: CronSchedules = self
            .send(
                self.request(
                    Method::PUT,
                    &format!("/accounts/{account_id}/workers/scripts/{script}/schedules"),
                )
                .json(&body),
                "update Worker Cron Triggers",
                true,
            )
            .await?;
        Ok(result
            .schedules
            .into_iter()
            .map(|schedule| schedule.cron)
            .collect())
    }

    pub async fn create_kv_namespace(&self, account_id: &str, title: &str) -> Result<String> {
        let namespace: KvNamespace = self
            .send(
                self.request(
                    Method::POST,
                    &format!("/accounts/{account_id}/storage/kv/namespaces"),
                )
                .json(&serde_json::json!({ "title": title })),
                "create KV namespace",
                false,
            )
            .await?;
        Ok(namespace.id)
    }

    pub async fn find_kv_namespace(
        &self,
        account_id: &str,
        title: &str,
    ) -> Result<Option<KvNamespace>> {
        Ok(self
            .list_kv_namespaces(account_id)
            .await?
            .into_iter()
            .find(|namespace| namespace.title == title))
    }

    pub async fn list_kv_namespaces(&self, account_id: &str) -> Result<Vec<KvNamespace>> {
        let mut namespaces = Vec::new();
        for page in 1u32.. {
            let batch: Vec<KvNamespace> = self
                .send(
                    self.get(&format!(
                        "/accounts/{account_id}/storage/kv/namespaces?per_page=100&page={page}"
                    )),
                    "list KV namespaces",
                    true,
                )
                .await?;
            let done = batch.len() < 100;
            namespaces.extend(batch);
            if done {
                return Ok(namespaces);
            }
        }
        unreachable!()
    }

    pub async fn delete_kv_namespace(&self, account_id: &str, namespace_id: &str) -> Result<()> {
        self.send_ok(
            self.request(
                Method::DELETE,
                &format!("/accounts/{account_id}/storage/kv/namespaces/{namespace_id}"),
            ),
            "delete KV namespace",
            true,
        )
        .await
    }

    /// Create a brand-new Worker via the legacy PUT endpoint. The Versions
    /// API (`POST …/versions`) requires the script to already exist, so the
    /// very first deployment must go through PUT which creates the Worker and
    /// its initial version in a single request. After this call the Worker is
    /// live; the caller should then promote (or track) the returned version.
    pub async fn create_worker_initial(
        &self,
        account_id: &str,
        script: &str,
        bundle: &WorkerBundle,
        metadata: serde_json::Value,
    ) -> Result<WorkerVersion> {
        let operation_tag = metadata["annotations"]["workers/tag"]
            .as_str()
            .unwrap_or("veilweave-v2")
            .to_string();
        let mut form = reqwest::multipart::Form::new().part(
            "metadata",
            reqwest::multipart::Part::text(metadata.to_string()).mime_str("application/json")?,
        );
        for module in bundle.modules() {
            let part = reqwest::multipart::Part::bytes(module.contents.clone())
                .file_name(module.path.clone())
                .mime_str(module.kind.content_type())
                .with_context(|| format!("model MIME type for {}", module.path))?;
            form = form.part(module.path.clone(), part);
        }
        self.send_ok(
            self.request(
                Method::PUT,
                &format!("/accounts/{account_id}/workers/scripts/{script}"),
            )
            .multipart(form),
            &format!("create Worker {script:?}"),
            false,
        )
        .await?;
        let versions = self.list_versions(account_id, script).await?;
        versions
            .into_iter()
            .find(|v| v.annotations.get("workers/tag").map(|s| s.as_str()) == Some(&operation_tag))
            .with_context(|| {
                format!(
                    "Worker {script:?} was created but the initial version \
                     carrying tag {operation_tag:?} could not be located"
                )
            })
    }

    /// Upload an inert Worker version. This operation is intentionally not
    /// retried because a timed-out creation can be reconciled by listing
    /// versions and matching the deterministic bundle annotation.
    pub async fn upload_version(
        &self,
        account_id: &str,
        script: &str,
        bundle: &WorkerBundle,
        mut metadata: serde_json::Value,
    ) -> Result<WorkerVersion> {
        let existing_tag = metadata["annotations"]["workers/tag"]
            .as_str()
            .filter(|value| *value != "veilweave-v2")
            .map(str::to_string);
        let operation_tag = existing_tag
            .unwrap_or_else(|| format!("veilweave-v2:{}", uuid::Uuid::new_v4().simple()));
        metadata["annotations"]["workers/tag"] = serde_json::Value::String(operation_tag.clone());
        let mut form = reqwest::multipart::Form::new().part(
            "metadata",
            reqwest::multipart::Part::text(metadata.to_string()).mime_str("application/json")?,
        );
        for module in bundle.modules() {
            let part = reqwest::multipart::Part::bytes(module.contents.clone())
                .file_name(module.path.clone())
                .mime_str(module.kind.content_type())
                .with_context(|| format!("model MIME type for {}", module.path))?;
            form = form.part(module.path.clone(), part);
        }
        let result = self
            .send(
            self.request(
                Method::POST,
                &format!(
                    "/accounts/{account_id}/workers/scripts/{script}/versions?bindings_inherit=strict"
                ),
            )
            .multipart(form),
            &format!("upload Worker version for {script:?}"),
            false,
        )
        .await;
        match result {
            Ok(version) => Ok(version),
            Err(upload_error) if !creation_outcome_ambiguous(&upload_error) => Err(upload_error),
            Err(upload_error) => match self.list_versions(account_id, script).await {
                Ok(versions) => versions
                    .into_iter()
                    .find(|version| {
                        version.annotations.get("workers/tag") == Some(&operation_tag)
                    })
                    .ok_or_else(|| {
                        upload_error.context(format!(
                            "version creation outcome was ambiguous and no version carried operation tag {operation_tag:?}"
                        ))
                    }),
                Err(reconcile_error) => Err(upload_error.context(format!(
                    "version creation outcome was ambiguous and reconciliation failed: {reconcile_error:#}"
                ))),
            },
        }
    }

    pub async fn create_deployment(
        &self,
        account_id: &str,
        script: &str,
        version_id: &str,
        message: &str,
    ) -> Result<WorkerDeployment> {
        let operation_message = if message.contains("[vw-op:") {
            message.to_string()
        } else {
            format!("{message} [vw-op:{}]", uuid::Uuid::new_v4().simple())
        };
        let body = serde_json::json!({
            "strategy": "percentage",
            "versions": [{ "version_id": version_id, "percentage": 100 }],
            "annotations": {
                "workers/message": operation_message
            }
        });
        let result = self
            .send(
                self.request(
                    Method::POST,
                    &format!("/accounts/{account_id}/workers/scripts/{script}/deployments"),
                )
                .json(&body),
                &format!("deploy Worker version {version_id}"),
                false,
            )
            .await;
        match result {
            Ok(deployment) => Ok(deployment),
            Err(deploy_error) if !creation_outcome_ambiguous(&deploy_error) => Err(deploy_error),
            Err(deploy_error) => match self.list_deployments(account_id, script).await {
                Ok(deployments) => deployments
                    .into_iter()
                    .find(|deployment| {
                        deployment.annotations.get("workers/message")
                            == Some(&operation_message)
                    })
                    .ok_or_else(|| {
                        deploy_error.context(
                            "deployment creation outcome was ambiguous and reconciliation found no matching operation",
                        )
                    }),
                Err(reconcile_error) => Err(deploy_error.context(format!(
                    "deployment creation outcome was ambiguous and reconciliation failed: {reconcile_error:#}"
                ))),
            },
        }
    }

    /// Compatibility entry point now implemented as version creation plus a
    /// separate 100% deployment; no multipart request directly mutates live.
    pub async fn upload_worker(
        &self,
        account_id: &str,
        script: &str,
        bundle: WorkerBundle,
        metadata: serde_json::Value,
    ) -> Result<()> {
        let version = self
            .upload_version(account_id, script, &bundle, metadata)
            .await?;
        self.create_deployment(
            account_id,
            script,
            &version.id,
            "Veilweave compatibility deployment",
        )
        .await?;
        Ok(())
    }

    pub async fn list_versions(
        &self,
        account_id: &str,
        script: &str,
    ) -> Result<Vec<WorkerVersion>> {
        let raw: serde_json::Value = self
            .send(
                self.get(&format!(
                    "/accounts/{account_id}/workers/scripts/{script}/versions"
                )),
                "list Worker versions",
                true,
            )
            .await?;
        let items = raw
            .get("items")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut versions = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            match serde_json::from_value::<WorkerVersion>(item.clone()) {
                Ok(version) => versions.push(version),
                Err(e) => {
                    eprintln!("DEBUG: failed to deserialize version[{i}]: {e}");
                    eprintln!(
                        "DEBUG: raw version[{i}] = {}",
                        serde_json::to_string_pretty(item).unwrap_or_default()
                    );
                    return Err(e).context(format!(
                        "deserialize WorkerVersion from versions list at index {i}"
                    ));
                }
            }
        }
        Ok(versions)
    }

    pub async fn list_deployments(
        &self,
        account_id: &str,
        script: &str,
    ) -> Result<Vec<WorkerDeployment>> {
        let raw: serde_json::Value = self
            .send(
                self.get(&format!(
                    "/accounts/{account_id}/workers/scripts/{script}/deployments"
                )),
                "list Worker deployments",
                true,
            )
            .await?;
        let items = raw
            .get("deployments")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut deployments = Vec::with_capacity(items.len());
        for item in items {
            let deployment: WorkerDeployment = serde_json::from_value(item)
                .context("deserialize WorkerDeployment from deployments list")?;
            deployments.push(deployment);
        }
        Ok(deployments)
    }

    pub async fn delete_worker(&self, account_id: &str, script: &str) -> Result<()> {
        self.send_ok(
            self.request(
                Method::DELETE,
                &format!("/accounts/{account_id}/workers/scripts/{script}"),
            ),
            &format!("delete Worker {script:?}"),
            true,
        )
        .await
    }

    /// Retire the Durable Object namespace owned by a Veilweave Worker before
    /// deleting its script. Cloudflare's declarative exports require an
    /// explicit `deleted` tombstone; deleting only the script can orphan the
    /// namespace and its stored data.
    pub async fn delete_managed_worker(
        &self,
        account_id: &str,
        script: &str,
        ownership: WorkerOwnership,
    ) -> Result<()> {
        let class_name = match ownership {
            WorkerOwnership::VeilweaveRelay => "VeilweaveSession",
            WorkerOwnership::VeilweaveSub => "ProxyIpRefresher",
            WorkerOwnership::UnknownVeilweave | WorkerOwnership::Unrelated => {
                bail!("refusing Durable Object retirement for a Worker without a known Veilweave role")
            }
        };
        let operation_tag = format!("veilweave-retire:{}", uuid::Uuid::new_v4().simple());
        let mut metadata = serde_json::json!({
            "main_module": "retire.js",
            "compatibility_date": COMPATIBILITY_DATE,
            "annotations": {
                "workers/message": format!("Veilweave retirement for {class_name}"),
                "workers/tag": operation_tag,
            }
        });
        metadata["exports"] = serde_json::json!({});
        metadata["exports"][class_name] = serde_json::json!({
            "type": "durable-object",
            "state": "deleted"
        });
        let form = reqwest::multipart::Form::new()
            .part(
                "metadata",
                reqwest::multipart::Part::text(metadata.to_string())
                    .mime_str("application/json")?,
            )
            .part(
                "retire.js",
                reqwest::multipart::Part::bytes(
                    b"export default {fetch(){return new Response('retiring',{status:503})}};"
                        .to_vec(),
                )
                .file_name("retire.js")
                .mime_str("application/javascript+module")?,
            );
        let created: Result<WorkerVersion> = self
            .send(
                self.request(
                    Method::POST,
                    &format!("/accounts/{account_id}/workers/scripts/{script}/versions"),
                )
                .multipart(form),
                &format!("create Durable Object retirement version for {script:?}"),
                false,
            )
            .await;
        let version = match created {
            Ok(version) => version,
            Err(upload_error) if !creation_outcome_ambiguous(&upload_error) => {
                return Err(upload_error)
            }
            Err(upload_error) => self
                .list_versions(account_id, script)
                .await
                .ok()
                .and_then(|versions| {
                    versions.into_iter().find(|version| {
                        version.annotations.get("workers/tag") == Some(&operation_tag)
                    })
                })
                .ok_or_else(|| {
                    upload_error.context(
                        "Durable Object retirement version outcome was ambiguous and could not be reconciled",
                    )
                })?,
        };
        self.create_deployment(
            account_id,
            script,
            &version.id,
            "Veilweave Durable Object retirement",
        )
        .await
        .context("promote Durable Object retirement tombstone")?;
        self.delete_worker(account_id, script).await
    }

    pub async fn list_workers(&self, account_id: &str) -> Result<Vec<WorkerScript>> {
        self.send(
            self.get(&format!("/accounts/{account_id}/workers/scripts")),
            "list Workers",
            true,
        )
        .await
    }

    pub async fn get_script_settings(
        &self,
        account_id: &str,
        script: &str,
    ) -> Result<Vec<BindingInfo>> {
        let settings: ScriptSettings = self
            .send(
                self.get(&format!(
                    "/accounts/{account_id}/workers/scripts/{script}/settings"
                )),
                "get Worker settings",
                true,
            )
            .await?;
        Ok(settings.bindings)
    }

    pub async fn worker_ownership(
        &self,
        account_id: &str,
        script: &str,
    ) -> Result<WorkerOwnership> {
        let bindings = self.get_script_settings(account_id, script).await?;
        let marker = bindings
            .iter()
            .find(|binding| binding.name == OWNERSHIP_BINDING);
        Ok(match marker.and_then(|binding| binding.text.as_deref()) {
            Some(OWNERSHIP_RELAY) => WorkerOwnership::VeilweaveRelay,
            Some(OWNERSHIP_SUB) => WorkerOwnership::VeilweaveSub,
            Some(_) => WorkerOwnership::UnknownVeilweave,
            None => WorkerOwnership::Unrelated,
        })
    }

    pub async fn list_domains(&self, account_id: &str) -> Result<Vec<WorkerDomain>> {
        self.send(
            self.get(&format!("/accounts/{account_id}/workers/domains")),
            "list Worker Custom Domains",
            true,
        )
        .await
    }

    pub async fn attach_domain(
        &self,
        account_id: &str,
        request: &AttachDomainRequest,
    ) -> Result<WorkerDomain> {
        self.send(
            self.request(
                Method::PUT,
                &format!("/accounts/{account_id}/workers/domains"),
            )
            .json(request),
            &format!("attach Worker Custom Domain {:?}", request.hostname),
            false,
        )
        .await
    }

    pub async fn detach_domain(&self, account_id: &str, domain_id: &str) -> Result<()> {
        self.send_ok(
            self.request(
                Method::DELETE,
                &format!("/accounts/{account_id}/workers/domains/{domain_id}"),
            ),
            "detach Worker Custom Domain",
            true,
        )
        .await
    }

    pub async fn list_zones(&self, account_id: &str) -> Result<Vec<Zone>> {
        self.send(
            self.get(&format!(
                "/zones?account.id={account_id}&status=active&per_page=50"
            )),
            "list active zones",
            true,
        )
        .await
    }

    pub async fn list_dns_records(&self, zone_id: &str, hostname: &str) -> Result<Vec<DnsRecord>> {
        self.send(
            self.get(&format!(
                "/zones/{zone_id}/dns_records?name={hostname}&per_page=100"
            )),
            "check DNS conflicts",
            true,
        )
        .await
    }

    pub async fn account_usage(&self, account_id: &str) -> Result<Vec<UsageRow>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let from = now - now % 86_400;
        let body = serde_json::json!({
            "query": "query($account: String!, $from: Time!, $to: Time!) { viewer { accounts(filter: {accountTag: $account}) { workersInvocationsAdaptive(limit: 100, filter: {datetime_geq: $from, datetime_leq: $to}) { dimensions { scriptName } sum { requests errors } quantiles { cpuTimeP50 } } } } }",
            "variables": {
                "account": account_id,
                "from": crate::config::format_unix_utc(from),
                "to": crate::config::format_unix_utc(now),
            },
        });
        let response = self
            .request(Method::POST, "/graphql")
            .json(&body)
            .send()
            .await
            .context("account usage request failed")?;
        let status = response.status();
        let value: serde_json::Value = response
            .json()
            .await
            .with_context(|| format!("account usage returned malformed HTTP {status}"))?;
        if let Some(errors) = value["errors"]
            .as_array()
            .filter(|errors| !errors.is_empty())
        {
            let messages = errors
                .iter()
                .filter_map(|error| error["message"].as_str())
                .collect::<Vec<_>>()
                .join("; ");
            bail!("account usage: {messages}");
        }
        Ok(
            value["data"]["viewer"]["accounts"][0]["workersInvocationsAdaptive"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|group| UsageRow {
                    script: group["dimensions"]["scriptName"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    requests: group["sum"]["requests"].as_u64().unwrap_or(0),
                    errors: group["sum"]["errors"].as_u64().unwrap_or(0),
                    cpu_p50_us: group["quantiles"]["cpuTimeP50"].as_f64().unwrap_or(0.0),
                })
                .collect(),
        )
    }
}

#[derive(Debug)]
struct CfApiFailure {
    operation: String,
    status: Option<StatusCode>,
    codes: Vec<i64>,
    messages: Vec<String>,
    cf_ray: Option<String>,
    retry_after: Option<Duration>,
}

impl CfApiFailure {
    fn retryable(&self) -> bool {
        self.status.is_none()
            || self.status == Some(StatusCode::TOO_MANY_REQUESTS)
            || self.status.is_some_and(|status| status.is_server_error())
    }
}

fn creation_outcome_ambiguous(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CfApiFailure>().is_some_and(|failure| {
        failure.status.is_none()
            || failure
                .status
                .is_some_and(|status| status.is_server_error())
    })
}

impl fmt::Display for CfApiFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.operation)?;
        if let Some(status) = self.status {
            write!(formatter, " (HTTP {status})")?;
        }
        if !self.codes.is_empty() {
            write!(formatter, ": codes {:?}", self.codes)?;
        }
        if !self.messages.is_empty() {
            write!(formatter, ": {}", self.messages.join("; "))?;
        }
        if let Some(cf_ray) = &self.cf_ray {
            write!(formatter, " [CF-Ray {cf_ray}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for CfApiFailure {}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

fn safe_body_preview(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]);
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    errors: Vec<ApiError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct TokenStatus {
    status: String,
}

#[derive(Debug, Deserialize)]
struct WorkersSubdomain {
    subdomain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSummary {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkersDevState {
    pub enabled: bool,
    #[serde(default)]
    pub previews_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerScript {
    pub id: String,
    #[serde(default)]
    pub created_on: Option<String>,
    #[serde(default)]
    pub modified_on: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KvNamespace {
    pub id: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerVersion {
    pub id: String,
    #[serde(default)]
    pub number: Option<u64>,
    #[serde(default)]
    pub created_on: Option<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub annotations: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkerDeployment {
    pub id: String,
    #[serde(default)]
    pub created_on: Option<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub versions: Vec<DeploymentVersion>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub annotations: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentVersion {
    pub version_id: String,
    #[serde(default)]
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct BindingInfo {
    pub name: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub namespace_id: Option<String>,
    #[serde(default)]
    pub class_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ScriptSettings {
    #[serde(default)]
    bindings: Vec<BindingInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerOwnership {
    VeilweaveRelay,
    VeilweaveSub,
    UnknownVeilweave,
    Unrelated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerDomain {
    pub id: String,
    pub hostname: String,
    pub service: String,
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub zone_name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachDomainRequest {
    pub hostname: String,
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UsageRow {
    pub script: String,
    pub requests: u64,
    pub errors: u64,
    pub cpu_p50_us: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CronSchedules {
    #[serde(default)]
    schedules: Vec<CronSchedule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CronSchedule {
    cron: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubSettings {
    #[serde(default = "default_max_nodes")]
    pub max_nodes: u16,
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,
    /// Explicit ECH opt-in. `None` emits an empty binding and keeps ECH off.
    #[serde(default)]
    pub ech: Option<String>,
}

impl Default for SubSettings {
    fn default() -> Self {
        Self {
            max_nodes: default_max_nodes(),
            fingerprint: default_fingerprint(),
            ech: None,
        }
    }
}

impl SubSettings {
    pub fn validate(&self) -> Result<()> {
        if self.max_nodes == 0 || self.max_nodes > 200 {
            bail!("MAX_NODES must be between 1 and 200");
        }
        if self.fingerprint.trim().is_empty()
            || !self
                .fingerprint
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
        {
            bail!("FP must be a non-empty alphanumeric preset/custom value");
        }
        if let Some(ech) = &self.ech {
            if ech.trim().is_empty() || ech.len() > 512 || ech.chars().any(char::is_control) {
                bail!("ECH must be absent or a non-empty value of at most 512 characters");
            }
        }
        Ok(())
    }
}

fn default_max_nodes() -> u16 {
    100
}

fn default_fingerprint() -> String {
    "chrome".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionKind {
    Initial,
    Update,
}

fn metadata_base(role: &str, bundle_hash: &str) -> serde_json::Value {
    serde_json::json!({
        "main_module": "index.js",
        "compatibility_date": COMPATIBILITY_DATE,
        "compatibility_flags": ["nodejs_compat"],
        "annotations": {
            "workers/message": format!("Veilweave {role} bundle {bundle_hash}"),
            "workers/tag": "veilweave-v2"
        }
    })
}

pub fn relay_metadata_for(
    kind: VersionKind,
    secret: Option<&str>,
    bundle_hash: &str,
) -> Result<serde_json::Value> {
    let mut metadata = metadata_base("relay", bundle_hash);
    let secret_binding = match kind {
        VersionKind::Initial => serde_json::json!({
            "name": "SECRET_KEY", "type": "secret_text",
            "text": secret.context("initial relay version requires SECRET_KEY")?
        }),
        VersionKind::Update => serde_json::json!({ "name": "SECRET_KEY", "type": "inherit" }),
    };
    metadata["bindings"] = serde_json::json!([
        secret_binding,
        { "name": OWNERSHIP_BINDING, "type": "plain_text", "text": OWNERSHIP_RELAY },
        {
            "name": "VEILWEAVE_SESSION",
            "type": "durable_object_namespace",
            "class_name": "VeilweaveSession"
        }
    ]);
    if kind == VersionKind::Initial {
        // Declarative exports create the free-plan SQLite namespace once. An
        // update omits this block and therefore cannot replay class creation.
        metadata["exports"] = serde_json::json!({
            "VeilweaveSession": {
                "type": "durable-object",
                "storage": "sqlite",
                "state": "created"
            }
        });
    }
    Ok(metadata)
}

pub fn sub_metadata_for(
    kind: VersionKind,
    nodes: Option<&str>,
    subscription_token: Option<&str>,
    kv_binding: &str,
    kv_namespace_id: &str,
    settings: &SubSettings,
    bundle_hash: &str,
) -> Result<serde_json::Value> {
    settings.validate()?;
    if !is_js_identifier(kv_binding) {
        bail!("KV binding must be a valid JavaScript identifier");
    }
    let secret = |name: &str, value: Option<&str>| -> Result<serde_json::Value> {
        Ok(match (kind, value) {
            (VersionKind::Initial, None) => {
                bail!("initial sub version requires {name}")
            }
            (_, Some(text)) => {
                serde_json::json!({ "name": name, "type": "secret_text", "text": text })
            }
            (VersionKind::Update, None) => {
                serde_json::json!({ "name": name, "type": "inherit" })
            }
        })
    };
    let mut metadata = metadata_base("sub", bundle_hash);
    metadata["bindings"] = serde_json::json!([
        secret("VEILWEAVE_NODES", nodes)?,
        secret("SUBSCRIPTION_TOKEN", subscription_token)?,
        { "name": OWNERSHIP_BINDING, "type": "plain_text", "text": OWNERSHIP_SUB },
        { "name": "KV_BINDING", "type": "plain_text", "text": kv_binding },
        { "name": "MAX_NODES", "type": "plain_text", "text": settings.max_nodes.to_string() },
        { "name": "FP", "type": "plain_text", "text": settings.fingerprint },
        { "name": "ECH", "type": "plain_text", "text": settings.ech.clone().unwrap_or_default() },
        { "name": kv_binding, "type": "kv_namespace", "namespace_id": kv_namespace_id },
        {
            "name": "PROXYIP_REFRESHER",
            "type": "durable_object_namespace",
            "class_name": "ProxyIpRefresher"
        }
    ]);
    // Declarative exports are safe on every version: Cloudflare provisions the
    // SQLite namespace when absent (including upgrades from pre-refresher Sub
    // Workers) and matches the existing namespace on later code-only updates.
    metadata["exports"] = serde_json::json!({
        "ProxyIpRefresher": {
            "type": "durable-object",
            "storage": "sqlite",
            "state": "created"
        }
    });
    Ok(metadata)
}

/// Compatibility helpers create secure initial-version metadata.
pub fn relay_metadata(secret: &str) -> serde_json::Value {
    relay_metadata_for(VersionKind::Initial, Some(secret), "legacy-call")
        .expect("static relay metadata is valid")
}

pub fn sub_metadata(
    nodes: &str,
    subscription_token: &str,
    kv_binding: &str,
    kv_namespace_id: &str,
) -> serde_json::Value {
    sub_metadata_for(
        VersionKind::Initial,
        Some(nodes),
        Some(subscription_token),
        kv_binding,
        kv_namespace_id,
        &SubSettings::default(),
        "legacy-call",
    )
    .expect("caller supplied a valid KV binding")
}

fn is_js_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{WorkerBundle, WorkerRole};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn new_bindings_are_secret_and_updates_inherit() {
        let initial = relay_metadata_for(VersionKind::Initial, Some("secret"), "abc").unwrap();
        let secret = initial["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|binding| binding["name"] == "SECRET_KEY")
            .unwrap();
        assert_eq!(secret["type"], "secret_text");
        assert!(initial.get("exports").is_some());
        assert!(initial.get("migrations").is_none());

        let update = relay_metadata_for(VersionKind::Update, None, "def").unwrap();
        let inherited = update["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|binding| binding["name"] == "SECRET_KEY")
            .unwrap();
        assert_eq!(inherited["type"], "inherit");
        assert!(update.get("exports").is_none());
        assert!(!update.to_string().contains("secret"));
    }

    #[test]
    fn sub_settings_are_typed_and_sensitive_values_are_secret_bindings() {
        let metadata = sub_metadata_for(
            VersionKind::Initial,
            Some("relay.example|node-secret"),
            Some("subscription-secret"),
            "VEILWEAVE_KV",
            "namespace-id",
            &SubSettings::default(),
            "hash",
        )
        .unwrap();
        for name in ["VEILWEAVE_NODES", "SUBSCRIPTION_TOKEN"] {
            let binding = metadata["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|binding| binding["name"] == name)
                .unwrap();
            assert_eq!(binding["type"], "secret_text");
        }
        let refresher = metadata["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|binding| binding["name"] == "PROXYIP_REFRESHER")
            .unwrap();
        assert_eq!(refresher["type"], "durable_object_namespace");
        assert_eq!(refresher["class_name"], "ProxyIpRefresher");
        assert_eq!(metadata["exports"]["ProxyIpRefresher"]["storage"], "sqlite");
        assert_eq!(metadata["bindings"][4]["text"], "100");
        assert!(SubSettings {
            max_nodes: 0,
            ..SubSettings::default()
        }
        .validate()
        .is_err());

        let topology_update = sub_metadata_for(
            VersionKind::Update,
            Some("new-relay.example|rotated-secret"),
            None,
            "VEILWEAVE_KV",
            "namespace-id",
            &SubSettings::default(),
            "hash-2",
        )
        .unwrap();
        let binding = |name| {
            topology_update["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|binding| binding["name"] == name)
                .unwrap()
        };
        assert_eq!(binding("VEILWEAVE_NODES")["type"], "secret_text");
        assert_eq!(binding("SUBSCRIPTION_TOKEN")["type"], "inherit");
        assert_eq!(
            topology_update["exports"]["ProxyIpRefresher"]["state"],
            "created"
        );

        let token_rotation = sub_metadata_for(
            VersionKind::Update,
            None,
            Some("new-subscription-token"),
            "VEILWEAVE_KV",
            "namespace-id",
            &SubSettings::default(),
            "hash-3",
        )
        .unwrap();
        let binding = |name| {
            token_rotation["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|binding| binding["name"] == name)
                .unwrap()
        };
        assert_eq!(binding("VEILWEAVE_NODES")["type"], "inherit");
        assert_eq!(binding("SUBSCRIPTION_TOKEN")["type"], "secret_text");
    }

    #[test]
    fn errors_are_actionable_and_never_include_token() {
        let failure = CfApiFailure {
            operation: "upload".into(),
            status: Some(StatusCode::BAD_REQUEST),
            codes: vec![10162],
            messages: vec!["unsupported module".into()],
            cf_ray: Some("abc-SJC".into()),
            retry_after: None,
        };
        let rendered = failure.to_string();
        assert!(rendered.contains("10162"));
        assert!(rendered.contains("CF-Ray abc-SJC"));
    }

    #[derive(Clone)]
    struct MockResponse {
        status: u16,
        headers: Vec<(&'static str, &'static str)>,
        body: String,
    }

    async fn mock_api(
        responses: Vec<MockResponse>,
    ) -> (
        String,
        Arc<Mutex<Vec<Vec<u8>>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let responses = responses.clone();
                let captured = captured.clone();
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let mut buffer = [0u8; 4096];
                    let header_end = loop {
                        let Ok(length) = stream.read(&mut buffer).await else {
                            return;
                        };
                        if length == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&buffer[..length]);
                        if let Some(position) =
                            bytes.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            break position + 4;
                        }
                    };
                    let headers = String::from_utf8_lossy(&bytes[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':').and_then(|(name, value)| {
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                        })
                        .unwrap_or(0);
                    while bytes.len() < header_end + content_length {
                        let Ok(length) = stream.read(&mut buffer).await else {
                            return;
                        };
                        if length == 0 {
                            break;
                        }
                        bytes.extend_from_slice(&buffer[..length]);
                    }
                    captured.lock().unwrap().push(bytes);
                    let response = responses.lock().unwrap().pop_front().unwrap_or(MockResponse {
                        status: 500,
                        headers: Vec::new(),
                        body: r#"{"success":false,"errors":[{"code":999,"message":"missing mock response"}],"result":null}"#.into(),
                    });
                    let reason = match response.status {
                        200 => "OK",
                        400 => "Bad Request",
                        429 => "Too Many Requests",
                        500 => "Internal Server Error",
                        502 => "Bad Gateway",
                        _ => "Response",
                    };
                    let extra_headers = response
                        .headers
                        .iter()
                        .map(|(name, value)| format!("{name}: {value}\r\n"))
                        .collect::<String>();
                    let wire = format!(
                        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        response.status,
                        reason,
                        extra_headers,
                        response.body.len(),
                        response.body
                    );
                    let _ = stream.write_all(wire.as_bytes()).await;
                });
            }
        });
        (format!("http://{address}"), requests, task)
    }

    fn test_bundle(role: WorkerRole) -> WorkerBundle {
        let root = std::env::temp_dir().join(format!(
            "veilweave-cfapi-bundle-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(root.join("worker")).unwrap();
        std::fs::write(root.join("index.js"), b"export default {}").unwrap();
        std::fs::write(root.join("index_bg.wasm"), b"\0asm").unwrap();
        std::fs::write(root.join("worker/shim.mjs"), b"export {}").unwrap();
        std::fs::write(root.join("package.json"), b"{\"private\":true}").unwrap();
        let bundle = WorkerBundle::from_worker_build(&root, role).unwrap();
        std::fs::remove_dir_all(root).unwrap();
        bundle
    }

    #[tokio::test]
    async fn version_multipart_contains_only_manifest_modules_with_modeled_mime() {
        let (base, requests, task) = mock_api(vec![MockResponse {
            status: 200,
            headers: Vec::new(),
            body: r#"{"success":true,"errors":[],"result":{"id":"version-1"}}"#.into(),
        }])
        .await;
        let client = CfClient::new("never-serialized-token")
            .unwrap()
            .with_api_base(base)
            .unwrap();
        let bundle = test_bundle(WorkerRole::Relay);
        let metadata =
            relay_metadata_for(VersionKind::Initial, Some("secret"), "bundle-hash").unwrap();
        let version = client
            .upload_version("account", "relay-worker", &bundle, metadata)
            .await
            .unwrap();
        assert_eq!(version.id, "version-1");
        let request = requests.lock().unwrap()[0].clone();
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with(
            "POST /accounts/account/workers/scripts/relay-worker/versions?bindings_inherit=strict HTTP/1.1"
        ));
        assert!(request.contains("name=\"index.js\""));
        assert!(request.contains("application/javascript+module"));
        assert!(request.contains("name=\"index_bg.wasm\""));
        assert!(request.contains("application/wasm"));
        assert!(request.contains("name=\"worker/shim.mjs\""));
        assert!(!request.contains("package.json"));
        assert!(!request
            .contains("application/json\r\nContent-Disposition: form-data; name=\"package.json\""));
        task.abort();
    }

    #[tokio::test]
    async fn ambiguous_version_creation_is_reconciled_by_operation_tag() {
        let (base, requests, task) = mock_api(vec![
            MockResponse {
                status: 500,
                headers: Vec::new(),
                body: r#"{"success":false,"errors":[{"code":10000,"message":"unknown outcome"}],"result":null}"#.into(),
            },
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: r#"{"success":true,"errors":[],"result":{"items":[{"id":"version-reconciled","annotations":{"workers/tag":"test-operation"}}]}}"#.into(),
            },
        ])
        .await;
        let client = CfClient::new("token").unwrap().with_api_base(base).unwrap();
        let bundle = test_bundle(WorkerRole::Relay);
        let mut metadata =
            relay_metadata_for(VersionKind::Initial, Some("secret"), "hash").unwrap();
        metadata["annotations"]["workers/tag"] = "test-operation".into();
        let version = client
            .upload_version("account", "relay-worker", &bundle, metadata)
            .await
            .unwrap();
        assert_eq!(version.id, "version-reconciled");
        assert_eq!(requests.lock().unwrap().len(), 2);
        task.abort();
    }

    #[tokio::test]
    async fn ambiguous_deployment_creation_is_reconciled_by_operation_message() {
        let (base, requests, task) = mock_api(vec![
            MockResponse {
                status: 500,
                headers: Vec::new(),
                body: r#"{"success":false,"errors":[{"code":10000,"message":"unknown outcome"}],"result":null}"#.into(),
            },
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: r#"{"success":true,"errors":[],"result":{"deployments":[{"id":"deployment-reconciled","versions":[{"version_id":"version-1","percentage":100}],"annotations":{"workers/message":"promote [vw-op:test-operation]"}}]}}"#.into(),
            },
        ])
        .await;
        let client = CfClient::new("token").unwrap().with_api_base(base).unwrap();
        let deployment = client
            .create_deployment(
                "account",
                "relay-worker",
                "version-1",
                "promote [vw-op:test-operation]",
            )
            .await
            .unwrap();
        assert_eq!(deployment.id, "deployment-reconciled");
        assert_eq!(requests.lock().unwrap().len(), 2);
        task.abort();
    }

    #[tokio::test]
    async fn custom_domain_attach_uses_the_domains_api_without_dns_mutation() {
        let (base, requests, task) = mock_api(vec![MockResponse {
            status: 200,
            headers: Vec::new(),
            body: r#"{"success":true,"errors":[],"result":{"id":"domain-1","hostname":"relay.example.com","service":"relay-worker","zone_id":"zone-1","zone_name":"example.com","status":"pending"}}"#.into(),
        }])
        .await;
        let client = CfClient::new("token").unwrap().with_api_base(base).unwrap();
        client
            .attach_domain(
                "account",
                &AttachDomainRequest {
                    hostname: "relay.example.com".into(),
                    service: "relay-worker".into(),
                    zone_id: Some("zone-1".into()),
                    zone_name: Some("example.com".into()),
                },
            )
            .await
            .unwrap();
        let request = String::from_utf8_lossy(&requests.lock().unwrap()[0]).to_string();
        assert!(request.starts_with("PUT /accounts/account/workers/domains HTTP/1.1"));
        assert!(request.contains(r#""hostname":"relay.example.com""#));
        assert!(request.contains(r#""service":"relay-worker""#));
        assert!(!request.contains("dns_records"));
        task.abort();
    }

    #[tokio::test]
    async fn cron_schedules_use_idempotent_bulk_replace_contract() {
        let response =
            r#"{"success":true,"errors":[],"result":{"schedules":[{"cron":"17 */6 * * *"}]}}"#;
        let (base, requests, task) = mock_api(vec![
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: response.into(),
            },
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: response.into(),
            },
        ])
        .await;
        let client = CfClient::new("token").unwrap().with_api_base(base).unwrap();
        assert_eq!(
            client
                .get_cron_schedules("account", "sub-worker")
                .await
                .unwrap(),
            ["17 */6 * * *"]
        );
        assert_eq!(
            client
                .set_cron_schedules("account", "sub-worker", &["17 */6 * * *".into()])
                .await
                .unwrap(),
            ["17 */6 * * *"]
        );
        let requests = requests.lock().unwrap();
        assert!(String::from_utf8_lossy(&requests[0])
            .starts_with("GET /accounts/account/workers/scripts/sub-worker/schedules HTTP/1.1"));
        let update = String::from_utf8_lossy(&requests[1]);
        assert!(update
            .starts_with("PUT /accounts/account/workers/scripts/sub-worker/schedules HTTP/1.1"));
        assert!(update.contains(r#"[{"cron":"17 */6 * * *"}]"#));
        task.abort();
    }

    #[tokio::test]
    async fn managed_worker_delete_promotes_durable_object_tombstone_first() {
        let (base, requests, task) = mock_api(vec![
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: r#"{"success":true,"errors":[],"result":{"id":"retire-version"}}"#.into(),
            },
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: r#"{"success":true,"errors":[],"result":{"id":"retire-deployment","versions":[{"version_id":"retire-version","percentage":100}],"annotations":{}}}"#.into(),
            },
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: r#"{"success":true,"errors":[],"result":{}}"#.into(),
            },
        ])
        .await;
        let client = CfClient::new("token").unwrap().with_api_base(base).unwrap();
        client
            .delete_managed_worker("account", "relay-worker", WorkerOwnership::VeilweaveRelay)
            .await
            .unwrap();

        let requests = requests.lock().unwrap();
        let version = String::from_utf8_lossy(&requests[0]);
        assert!(version
            .starts_with("POST /accounts/account/workers/scripts/relay-worker/versions HTTP/1.1"));
        assert!(version.contains("VeilweaveSession"));
        assert!(version.contains("deleted"));
        assert!(version.contains("name=\"retire.js\""));
        let deployment = String::from_utf8_lossy(&requests[1]);
        assert!(deployment.starts_with(
            "POST /accounts/account/workers/scripts/relay-worker/deployments HTTP/1.1"
        ));
        assert!(deployment.contains(r#""version_id":"retire-version""#));
        assert!(String::from_utf8_lossy(&requests[2])
            .starts_with("DELETE /accounts/account/workers/scripts/relay-worker HTTP/1.1"));
        task.abort();
    }

    #[tokio::test]
    async fn safe_get_retries_429_and_honors_retry_after() {
        let (base, requests, task) = mock_api(vec![
            MockResponse {
                status: 429,
                headers: vec![("Retry-After", "0")],
                body: r#"{"success":false,"errors":[{"code":10000,"message":"rate limited"}],"result":null}"#.into(),
            },
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: r#"{"success":true,"errors":[],"result":{"status":"active"}}"#.into(),
            },
        ])
        .await;
        let client = CfClient::new("token").unwrap().with_api_base(base).unwrap();
        client.verify_token().await.unwrap();
        assert_eq!(requests.lock().unwrap().len(), 2);
        task.abort();
    }

    #[tokio::test]
    async fn non_json_error_reports_http_status_body_preview_and_cf_ray() {
        let (base, _, task) = mock_api(vec![MockResponse {
            status: 502,
            headers: vec![("CF-Ray", "ray-test-SJC")],
            body: "upstream gateway unavailable".into(),
        }])
        .await;
        let mut client = CfClient::new("token").unwrap().with_api_base(base).unwrap();
        client.max_safe_retries = 0;
        let error = client.verify_token().await.unwrap_err().to_string();
        assert!(error.contains("HTTP 502"));
        assert!(error.contains("upstream gateway unavailable"));
        assert!(error.contains("ray-test-SJC"));
        task.abort();
    }

    #[tokio::test]
    async fn deployment_request_is_separate_from_version_creation() {
        let (base, requests, task) = mock_api(vec![
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: r#"{"success":true,"errors":[],"result":{"id":"version-2"}}"#.into(),
            },
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: r#"{"success":true,"errors":[],"result":{"id":"deployment-2","versions":[{"version_id":"version-2","percentage":100}],"annotations":{}}}"#.into(),
            },
        ])
        .await;
        let client = CfClient::new("token").unwrap().with_api_base(base).unwrap();
        client
            .upload_worker(
                "account",
                "sub-worker",
                test_bundle(WorkerRole::Sub),
                sub_metadata_for(
                    VersionKind::Initial,
                    Some("relay.example|secret"),
                    Some("token"),
                    "VEILWEAVE_KV",
                    "kv-id",
                    &SubSettings::default(),
                    "hash",
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let requests = requests.lock().unwrap();
        let first = String::from_utf8_lossy(&requests[0]);
        let second = String::from_utf8_lossy(&requests[1]);
        assert!(first.starts_with(
            "POST /accounts/account/workers/scripts/sub-worker/versions?bindings_inherit=strict"
        ));
        assert!(second.starts_with("POST /accounts/account/workers/scripts/sub-worker/deployments"));
        assert!(second.contains(r#""version_id":"version-2""#));
        assert!(second.contains(r#""percentage":100"#));
        task.abort();
    }

    #[tokio::test]
    async fn kv_listing_follows_pagination() {
        let first = (0..100)
            .map(|index| serde_json::json!({"id": format!("id-{index}"), "title": format!("title-{index}")}))
            .collect::<Vec<_>>();
        let second = vec![serde_json::json!({"id":"id-100","title":"title-100"})];
        let (base, requests, task) = mock_api(vec![
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::json!({"success":true,"errors":[],"result":first}).to_string(),
            },
            MockResponse {
                status: 200,
                headers: Vec::new(),
                body: serde_json::json!({"success":true,"errors":[],"result":second}).to_string(),
            },
        ])
        .await;
        let client = CfClient::new("token").unwrap().with_api_base(base).unwrap();
        assert_eq!(
            client.list_kv_namespaces("account").await.unwrap().len(),
            101
        );
        let requests = requests.lock().unwrap();
        assert!(String::from_utf8_lossy(&requests[0]).contains("page=1"));
        assert!(String::from_utf8_lossy(&requests[1]).contains("page=2"));
        task.abort();
    }
}
