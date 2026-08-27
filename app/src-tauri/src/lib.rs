//! Tauri command adapter over the shared Veilweave v2 control plane.

mod bundle;

use anyhow::Context;
use bundle::embedded_bundle;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};
use veilweave_core::cfapi::{CfClient, SubSettings, FREE_TIER_DAILY_REQUESTS};
use veilweave_core::config::{Account, Config, Deployment, ExposureMode, PrimaryEndpoint, Role};
use veilweave_core::credentials::{CredentialManager, SecretValue};
use veilweave_core::deploy::{
    BundleSource, DeployPlan, EndpointSpec, LogKind, LogLine, RelaySpec, SubSpec,
};
use veilweave_core::network::{
    HttpProxyScheme, NetworkConfig, NetworkManager, NetworkMode, ProxyConfig,
};
use veilweave_core::util;

struct AppState {
    config: Mutex<Config>,
    credentials: CredentialManager,
    network: NetworkManager,
    deployment_active: AtomicBool,
}

fn load_state(app: &AppHandle) -> anyhow::Result<()> {
    let credentials = CredentialManager::system();
    let config = Config::load()?;
    let network = NetworkManager::new(config.network.clone(), credentials.clone())?;
    app.manage(AppState {
        config: Mutex::new(config),
        credentials,
        network,
        deployment_active: AtomicBool::new(false),
    });
    Ok(())
}

fn with_config<R>(state: &State<'_, AppState>, function: impl FnOnce(&mut Config) -> R) -> R {
    let mut guard = state.config.lock().expect("config mutex poisoned");
    function(&mut guard)
}

struct OperationGuard<'a>(&'a AtomicBool);

impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn acquire_operation(state: &AppState) -> Result<OperationGuard<'_>, String> {
    state
        .deployment_active
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "another deployment transaction is already running".to_string())?;
    Ok(OperationGuard(&state.deployment_active))
}

#[derive(Serialize, Clone)]
struct AccountView {
    name: String,
    account_id: String,
    workers_dev_subdomain: Option<String>,
    deployment_count: usize,
}

#[derive(Serialize, Clone)]
struct DeploymentView {
    id: String,
    role: Role,
    name: String,
    account: String,
    account_id: String,
    domain: Option<String>,
    exposure_mode: ExposureMode,
    primary_endpoint: PrimaryEndpoint,
    workers_dev_enabled: bool,
    custom_domains: Vec<DomainView>,
    created_at: String,
    updated_at: Option<String>,
    stable_version_id: Option<String>,
    previous_version_id: Option<String>,
    sub: Option<SubDeploymentView>,
}

#[derive(Serialize, Clone)]
struct DomainView {
    hostname: String,
    zone_name: String,
    primary: bool,
    status: veilweave_core::config::DomainStatus,
}

#[derive(Serialize, Clone)]
struct SubDeploymentView {
    kv_namespace_id: String,
    kv_title: String,
    kv_binding: String,
    max_nodes: u16,
    fingerprint: String,
    ech: Option<String>,
}

#[derive(Serialize)]
struct ConfigView {
    accounts: Vec<AccountView>,
    deployments: Vec<DeploymentView>,
    network: NetworkView,
    ui_language: Option<String>,
    recovery_notice: Option<String>,
}

#[derive(Serialize)]
struct NetworkView {
    mode: NetworkMode,
    proxy_endpoint: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    remote_dns: Option<bool>,
    allow_direct_fallback: Option<bool>,
    bypass: Vec<String>,
    request_timeout_secs: u64,
    http_scheme: Option<HttpProxyScheme>,
    generation: u64,
}

fn account_views(config: &Config) -> Vec<AccountView> {
    config
        .accounts
        .iter()
        .map(|account| AccountView {
            name: account.name.clone(),
            account_id: account.account_id.clone(),
            workers_dev_subdomain: account.workers_dev_subdomain.clone(),
            deployment_count: config
                .deployments
                .iter()
                .filter(|deployment| deployment.account_id == account.account_id)
                .count(),
        })
        .collect()
}

fn deployment_view(config: &Config, deployment: &Deployment) -> DeploymentView {
    let account = config
        .account(&deployment.account_id)
        .map(|value| value.name.clone())
        .unwrap_or_else(|| deployment.account_id.clone());
    DeploymentView {
        id: deployment.id.to_string(),
        role: deployment.role,
        name: deployment.name.clone(),
        account,
        account_id: deployment.account_id.clone(),
        domain: deployment.primary_domain().map(str::to_string),
        exposure_mode: deployment.endpoint.mode,
        primary_endpoint: deployment.endpoint.primary,
        workers_dev_enabled: deployment.endpoint.workers_dev_enabled,
        custom_domains: deployment
            .endpoint
            .custom_domains
            .iter()
            .map(|domain| DomainView {
                hostname: domain.hostname.clone(),
                zone_name: domain.zone_name.clone(),
                primary: domain.primary,
                status: domain.status,
            })
            .collect(),
        created_at: deployment.created_at.clone(),
        updated_at: deployment.updated_at.clone(),
        stable_version_id: deployment.stable_version_id.clone(),
        previous_version_id: deployment.previous_version_id.clone(),
        sub: deployment.sub.as_ref().map(|sub| SubDeploymentView {
            kv_namespace_id: sub.kv_namespace_id.clone(),
            kv_title: sub.kv_title.clone(),
            kv_binding: sub.kv_binding.clone(),
            max_nodes: sub.max_nodes,
            fingerprint: sub.fingerprint.clone(),
            ech: sub.ech.clone(),
        }),
    }
}

fn config_view(config: &Config, network: &NetworkManager) -> ConfigView {
    let snapshot = network.snapshot();
    let summary = snapshot.config().summary();
    ConfigView {
        accounts: account_views(config),
        deployments: config
            .deployments
            .iter()
            .map(|deployment| deployment_view(config, deployment))
            .collect(),
        network: NetworkView {
            mode: summary.mode,
            proxy_endpoint: summary.proxy_endpoint,
            host: snapshot
                .config()
                .proxy
                .as_ref()
                .map(|proxy| proxy.host.clone()),
            port: snapshot.config().proxy.as_ref().map(|proxy| proxy.port),
            username: snapshot
                .config()
                .proxy
                .as_ref()
                .and_then(|proxy| proxy.username.clone()),
            remote_dns: summary.remote_dns,
            allow_direct_fallback: summary.allow_direct_fallback,
            bypass: summary.bypass,
            request_timeout_secs: snapshot.config().request_timeout_secs,
            http_scheme: snapshot
                .config()
                .proxy
                .as_ref()
                .map(|proxy| proxy.http_scheme),
            generation: snapshot.generation(),
        },
        ui_language: config.ui_language.clone(),
        recovery_notice: config.recovery_notice.clone(),
    }
}

#[derive(Serialize)]
struct UsageRowView {
    script: String,
    requests: u64,
    errors: u64,
    cpu_p50_us: f64,
}

#[derive(Serialize)]
struct UsageResult {
    rows: Vec<UsageRowView>,
    analytics_error: Option<String>,
    free_tier_daily_requests: u64,
}

#[derive(Serialize, Clone)]
struct DeployDone {
    ok: bool,
    relays: Vec<RelayDone>,
    sub_deployment_id: Option<String>,
    subscription_url: Option<String>,
    completed: Vec<String>,
    error: Option<String>,
}

#[derive(Serialize, Clone)]
struct RelayDone {
    name: String,
    domain: String,
}

#[derive(Serialize, Clone)]
struct DeployLogEvent {
    kind: String,
    stage: veilweave_core::deploy::DeployStage,
    message: String,
}

impl From<&LogLine> for DeployLogEvent {
    fn from(line: &LogLine) -> Self {
        Self {
            kind: match line.kind {
                LogKind::Step => "step",
                LogKind::Info => "info",
                LogKind::Warn => "warn",
                LogKind::Error => "error",
            }
            .into(),
            stage: line.stage,
            message: line.message.clone(),
        }
    }
}

#[tauri::command]
fn get_config(state: State<'_, AppState>) -> ConfigView {
    with_config(&state, |config| config_view(config, &state.network))
}

#[tauri::command]
fn set_ui_language(state: State<'_, AppState>, language: Option<String>) -> Result<(), String> {
    if !matches!(language.as_deref(), None | Some("en") | Some("zh")) {
        return Err("language must be en, zh, or absent".into());
    }
    let mut candidate = with_config(&state, |config| config.clone());
    candidate.ui_language = language;
    candidate.save().map_err(|error| format!("{error:#}"))?;
    with_config(&state, |config| *config = candidate);
    Ok(())
}

#[derive(Serialize)]
struct AccountCandidateView {
    account_id: String,
    name: String,
}

#[tauri::command]
async fn discover_accounts(
    state: State<'_, AppState>,
    token: String,
) -> Result<Vec<AccountCandidateView>, String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("token is empty".into());
    }
    let client = CfClient::with_network(token, state.network.clone())
        .map_err(|error| format!("{error:#}"))?;
    client
        .verify_token()
        .await
        .map_err(|error| format!("{error:#}"))?;
    client
        .list_accounts()
        .await
        .map(|accounts| {
            accounts
                .into_iter()
                .map(|account| AccountCandidateView {
                    account_id: account.id,
                    name: account.name,
                })
                .collect()
        })
        .map_err(|error| format!("{error:#}"))
}

#[tauri::command]
async fn add_account(
    state: State<'_, AppState>,
    label: Option<String>,
    token: String,
    account_id: Option<String>,
) -> Result<AccountView, String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("token is empty".into());
    }
    let client = CfClient::with_network(token, state.network.clone())
        .map_err(|error| format!("{error:#}"))?;
    client
        .verify_token()
        .await
        .map_err(|error| format!("{error:#}"))?;
    let accounts = client
        .list_accounts()
        .await
        .map_err(|error| format!("{error:#}"))?;
    let picked = match account_id {
        Some(account_id) => accounts
            .iter()
            .find(|account| account.id == account_id)
            .cloned()
            .ok_or_else(|| "selected account is not visible to this token".to_string())?,
        None if accounts.len() == 1 => accounts[0].clone(),
        None => {
            return Err(
                "this token sees multiple accounts; select the exact Cloudflare account ID".into(),
            )
        }
    };
    let subdomain = client
        .get_workers_subdomain(&picked.id)
        .await
        .map_err(|error| format!("{error:#}"))?;
    let label = label
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|| picked.name.clone());
    let reference =
        CredentialManager::keyring_reference(&format!("account/{}/api-token", picked.id));
    let mut candidate = with_config(&state, |config| config.clone());
    if candidate.account(&picked.id).is_some() || candidate.account(&label).is_some() {
        return Err("this account ID or display label is already configured".into());
    }
    state
        .credentials
        .store_verified(&reference, token)
        .map_err(|error| format!("{error:#}"))?;
    candidate.accounts.push(Account {
        name: label.clone(),
        account_id: picked.id.clone(),
        credential_ref: reference.clone(),
        workers_dev_subdomain: Some(subdomain.clone()),
    });
    if let Err(error) = candidate.save() {
        let rollback = state.credentials.delete(&reference);
        return match rollback {
            Ok(()) => Err(format!("{error:#}")),
            Err(rollback_error) => Err(format!(
                "{error:#}; API token credential rollback also failed: {rollback_error:#}"
            )),
        };
    }
    with_config(&state, |config| *config = candidate);
    Ok(AccountView {
        name: label,
        account_id: picked.id,
        workers_dev_subdomain: Some(subdomain),
        deployment_count: 0,
    })
}

#[tauri::command]
fn delete_account(state: State<'_, AppState>, name: String) -> Result<(), String> {
    let mut candidate = with_config(&state, |config| config.clone());
    let account = candidate
        .account(&name)
        .cloned()
        .ok_or_else(|| format!("account {name:?} not found"))?;
    let count = candidate
        .deployments
        .iter()
        .filter(|deployment| deployment.account_id == account.account_id)
        .count();
    if count > 0 {
        return Err(format!(
            "account {name:?} still has {count} deployment(s); delete them first"
        ));
    }
    candidate
        .accounts
        .retain(|item| item.account_id != account.account_id);
    let previous = if account.credential_ref.starts_with("keyring:") {
        Some(
            state
                .credentials
                .resolve(&account.credential_ref)
                .map_err(|error| format!("read account credential before deletion: {error:#}"))?,
        )
    } else {
        None
    };
    if previous.is_some() {
        state
            .credentials
            .delete(&account.credential_ref)
            .map_err(|error| format!("delete account credential: {error:#}"))?;
    }
    if let Err(error) = candidate.save() {
        if let Some(previous) = previous {
            state
                .credentials
                .store_verified(&account.credential_ref, previous.expose())
                .map_err(|rollback_error| {
                    format!(
                        "{error:#}; account credential rollback also failed: {rollback_error:#}"
                    )
                })?;
        }
        return Err(format!("{error:#}"));
    }
    with_config(&state, |config| *config = candidate);
    Ok(())
}

#[derive(Serialize)]
struct RecoverView {
    added: usize,
    summary: Vec<String>,
    candidates: Vec<veilweave_core::recover::RecoveryCandidate>,
}

#[tauri::command]
async fn recover(state: State<'_, AppState>, name: String) -> Result<RecoverView, String> {
    let account = with_config(&state, |config| config.account(&name).cloned())
        .ok_or_else(|| format!("account {name:?} not found"))?;
    let token = state
        .credentials
        .resolve(&account.credential_ref)
        .map_err(|error| format!("{error:#}"))?;
    let client = CfClient::with_network(token.expose(), state.network.clone())
        .map_err(|error| format!("{error:#}"))?;
    let mut outcome = veilweave_core::recover::recover_account(
        &client,
        &account.account_id,
        account.workers_dev_subdomain.as_deref(),
    )
    .await
    .map_err(|error| format!("{error:#}"))?;
    let local_deployments = with_config(&state, |config| config.deployments.clone());
    veilweave_core::recover::reconcile_local(&mut outcome, &local_deployments, &state.credentials);
    Ok(RecoverView {
        added: 0,
        summary: outcome.summary,
        candidates: outcome.candidates,
    })
}

#[tauri::command]
async fn usage(state: State<'_, AppState>, name: String) -> Result<UsageResult, String> {
    let account = with_config(&state, |config| config.account(&name).cloned())
        .ok_or_else(|| format!("account {name:?} not found"))?;
    let token = state
        .credentials
        .resolve(&account.credential_ref)
        .map_err(|error| format!("{error:#}"))?;
    let client = CfClient::with_network(token.expose(), state.network.clone())
        .map_err(|error| format!("{error:#}"))?;
    match client.account_usage(&account.account_id).await {
        Ok(rows) => Ok(UsageResult {
            rows: rows
                .into_iter()
                .map(|row| UsageRowView {
                    script: row.script,
                    requests: row.requests,
                    errors: row.errors,
                    cpu_p50_us: row.cpu_p50_us,
                })
                .collect(),
            analytics_error: None,
            free_tier_daily_requests: FREE_TIER_DAILY_REQUESTS,
        }),
        Err(error) => Ok(UsageResult {
            rows: Vec::new(),
            analytics_error: Some(format!("{error:#}")),
            free_tier_daily_requests: FREE_TIER_DAILY_REQUESTS,
        }),
    }
}

#[tauri::command]
async fn list_zones(
    state: State<'_, AppState>,
    name: String,
) -> Result<Vec<veilweave_core::cfapi::Zone>, String> {
    let account = with_config(&state, |config| config.account(&name).cloned())
        .ok_or_else(|| format!("account {name:?} not found"))?;
    let token = state
        .credentials
        .resolve(&account.credential_ref)
        .map_err(|error| format!("{error:#}"))?;
    let client = CfClient::with_network(token.expose(), state.network.clone())
        .map_err(|error| format!("{error:#}"))?;
    client
        .list_zones(&account.account_id)
        .await
        .map(|zones| {
            zones
                .into_iter()
                .filter(|zone| zone.status.eq_ignore_ascii_case("active"))
                .collect()
        })
        .map_err(|error| format!("{error:#}"))
}

#[tauri::command]
fn random_worker_name() -> String {
    util::random_worker_name()
}

#[tauri::command]
fn random_kv_binding() -> String {
    util::random_kv_binding()
}

#[tauri::command]
fn start_deploy(app: AppHandle, plan: DeployPlanWire) -> Result<(), String> {
    let state = app.state::<AppState>();
    if state
        .deployment_active
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("another deployment transaction is already running".into());
    }
    let config = with_config(&state, |config| config.clone());
    let credentials = state.credentials.clone();
    let network = state.network.clone();
    let plan = plan.into_core()?;
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                app.state::<AppState>()
                    .deployment_active
                    .store(false, Ordering::Release);
                let _ = app.emit(
                    "deploy-done",
                    DeployDone {
                        ok: false,
                        relays: Vec::new(),
                        sub_deployment_id: None,
                        subscription_url: None,
                        completed: Vec::new(),
                        error: Some(format!("could not start deployment runtime: {error}")),
                    },
                );
                return;
            }
        };
        runtime.block_on(run_deploy(app, config, credentials, network, plan));
    });
    Ok(())
}

async fn run_deploy(
    app: AppHandle,
    mut config: Config,
    credentials: CredentialManager,
    network: NetworkManager,
    plan: DeployPlan,
) {
    let source = BundleSource::Embedded(embedded_bundle());
    let event_app = app.clone();
    let result = veilweave_core::deploy::execute_with(
        &plan,
        &source,
        &mut config,
        &credentials,
        network,
        true,
        &mut |line| {
            let _ = event_app.emit("deploy-log", DeployLogEvent::from(&line));
        },
    )
    .await;
    let state = app.state::<AppState>();
    let done = match result {
        Ok(outcome) => {
            with_config(&state, |shared| *shared = config);
            DeployDone {
                ok: true,
                relays: outcome
                    .relays
                    .iter()
                    .map(|relay| RelayDone {
                        name: relay.name.clone(),
                        domain: relay.domain.clone(),
                    })
                    .collect(),
                // A subscription URL is available only through the dedicated
                // privileged command; it is not retained in WebView state.
                subscription_url: None,
                sub_deployment_id: outcome
                    .sub
                    .as_ref()
                    .map(|sub| sub.deployment_id.to_string()),
                completed: outcome
                    .journal
                    .iter()
                    .map(|record| format!("{}: {}", record.resource, record.detail))
                    .collect(),
                error: None,
            }
        }
        Err(error) => {
            if let Ok(saved) = Config::load() {
                with_config(&state, |shared| *shared = saved);
            }
            DeployDone {
                ok: false,
                relays: Vec::new(),
                sub_deployment_id: None,
                subscription_url: None,
                completed: Vec::new(),
                error: Some(format!("{error:#}")),
            }
        }
    };
    state.deployment_active.store(false, Ordering::Release);
    let _ = app.emit("deploy-done", done);
}

#[tauri::command]
fn get_subscription_url(
    state: State<'_, AppState>,
    deployment_id: String,
) -> Result<String, String> {
    let id = uuid::Uuid::parse_str(&deployment_id).map_err(|_| "invalid deployment UUID")?;
    with_config(&state, |config| {
        config
            .deployments
            .iter()
            .find(|deployment| deployment.id == id)
            .ok_or_else(|| "deployment not found".to_string())?
            .subscription_url(&state.credentials)
            .map_err(|error| format!("{error:#}"))?
            .ok_or_else(|| "only a sub deployment has a subscription URL".to_string())
    })
}

#[tauri::command]
async fn get_proxyip_cache_status(
    state: State<'_, AppState>,
    deployment_id: String,
) -> Result<veilweave_core::deploy::ProxyIpCacheStatus, String> {
    let deployment_id =
        uuid::Uuid::parse_str(&deployment_id).map_err(|_| "invalid deployment UUID")?;
    let config = with_config(&state, |config| config.clone());
    veilweave_core::deploy::proxyip_cache_status(
        deployment_id,
        &config,
        &state.credentials,
        state.network.clone(),
    )
    .await
    .map_err(|error| format!("{error:#}"))
}

#[tauri::command]
async fn refresh_proxyip_cache(
    state: State<'_, AppState>,
    deployment_id: String,
) -> Result<veilweave_core::deploy::ProxyIpRefreshReport, String> {
    let _guard = acquire_operation(&state)?;
    let deployment_id =
        uuid::Uuid::parse_str(&deployment_id).map_err(|_| "invalid deployment UUID")?;
    let config = with_config(&state, |config| config.clone());
    veilweave_core::deploy::refresh_proxyip_cache(
        deployment_id,
        &config,
        &state.credentials,
        state.network.clone(),
    )
    .await
    .map_err(|error| format!("{error:#}"))
}

#[derive(Deserialize)]
struct DeployPlanWire {
    sub: SubSpecWire,
    relays: Vec<RelaySpecWire>,
    #[serde(default)]
    encryption: bool,
}

impl DeployPlanWire {
    fn into_core(self) -> Result<DeployPlan, String> {
        Ok(DeployPlan {
            sub: SubSpec {
                account: self.sub.account,
                worker_name: self.sub.worker_name,
                kv_title: self.sub.kv_title,
                kv_binding: self.sub.kv_binding,
                endpoint: self.sub.endpoint,
                settings: self.sub.settings,
            },
            relays: self
                .relays
                .into_iter()
                .map(|relay| RelaySpec {
                    account: relay.account,
                    worker_name: relay.worker_name,
                    endpoint: relay.endpoint,
                })
                .collect(),
            encryption: self.encryption,
        })
    }
}

#[derive(Deserialize)]
struct SubSpecWire {
    account: String,
    worker_name: String,
    kv_title: String,
    kv_binding: String,
    #[serde(default)]
    endpoint: EndpointSpec,
    #[serde(default)]
    settings: SubSettings,
}

#[derive(Deserialize)]
struct RelaySpecWire {
    account: String,
    worker_name: String,
    #[serde(default)]
    endpoint: EndpointSpec,
}

#[tauri::command]
async fn delete_deployment(
    state: State<'_, AppState>,
    name: String,
    account: String,
) -> Result<(), String> {
    let _guard = acquire_operation(&state)?;
    let (cloudflare_account, deployment) = with_config(&state, |config| {
        let cloudflare_account = config.account(&account).cloned();
        let account_id = cloudflare_account
            .as_ref()
            .map(|value| value.account_id.as_str())
            .unwrap_or(account.as_str());
        let deployment = config
            .deployments
            .iter()
            .find(|deployment| deployment.account_id == account_id && deployment.name == name)
            .cloned();
        (cloudflare_account, deployment)
    });
    let cloudflare_account =
        cloudflare_account.ok_or_else(|| format!("account {account:?} not found"))?;
    let deployment = deployment.ok_or_else(|| format!("deployment {name:?} not found"))?;
    let token = state
        .credentials
        .resolve(&cloudflare_account.credential_ref)
        .map_err(|error| format!("{error:#}"))?;
    let client = CfClient::with_network(token.expose(), state.network.clone())
        .map_err(|error| format!("{error:#}"))?;
    let expected = match deployment.role {
        Role::Relay => veilweave_core::cfapi::WorkerOwnership::VeilweaveRelay,
        Role::Sub => veilweave_core::cfapi::WorkerOwnership::VeilweaveSub,
    };
    let ownership = client
        .worker_ownership(&cloudflare_account.account_id, &name)
        .await
        .map_err(|error| format!("{error:#}"))?;
    if ownership != expected {
        return Err("remote Worker ownership no longer matches this local deployment".into());
    }
    for domain in &deployment.endpoint.custom_domains {
        client
            .detach_domain(&cloudflare_account.account_id, &domain.domain_id)
            .await
            .map_err(|error| {
                format!(
                    "failed to detach managed Custom Domain {} before Worker deletion: {error:#}",
                    domain.hostname
                )
            })?;
    }
    client
        .delete_managed_worker(&cloudflare_account.account_id, &name, expected)
        .await
        .map_err(|error| format!("retire Durable Object and delete Worker failed: {error:#}"))?;
    if let Some(sub) = &deployment.sub {
        client
            .delete_kv_namespace(&cloudflare_account.account_id, &sub.kv_namespace_id)
            .await
            .map_err(|error| {
                format!("Worker was deleted, but its managed KV namespace remains: {error:#}")
            })?;
    }
    let mut candidate = with_config(&state, |config| config.clone());
    candidate
        .deployments
        .retain(|item| item.id != deployment.id);
    candidate.save().map_err(|error| {
        format!("remote resources were deleted, but local metadata could not be saved: {error}")
    })?;
    with_config(&state, |config| *config = candidate);
    state
        .credentials
        .delete(&deployment.secret_ref)
        .map_err(|error| format!("{error:#}"))?;
    if let Some(reference) = &deployment.node_secret_ref {
        state
            .credentials
            .delete(reference)
            .map_err(|error| format!("{error:#}"))?;
    }
    if let Some(sub) = &deployment.sub {
        state
            .credentials
            .delete(&sub.subscription_token_ref)
            .map_err(|error| format!("{error:#}"))?;
    }
    Ok(())
}

#[tauri::command]
async fn update_deployment(
    state: State<'_, AppState>,
    name: String,
    account: String,
) -> Result<(), String> {
    let _guard = acquire_operation(&state)?;
    let mut config = with_config(&state, |config| config.clone());
    let cloudflare_account = config
        .account(&account)
        .cloned()
        .ok_or_else(|| format!("account {account:?} not found"))?;
    let deployment_id = config
        .deployments
        .iter()
        .find(|deployment| {
            deployment.account_id == cloudflare_account.account_id && deployment.name == name
        })
        .map(|deployment| deployment.id)
        .ok_or_else(|| format!("deployment {name:?} not found"))?;
    veilweave_core::deploy::update_code(
        deployment_id,
        &BundleSource::Embedded(embedded_bundle()),
        &mut config,
        &state.credentials,
        state.network.clone(),
        true,
        &mut |_| {},
    )
    .await
    .map_err(|error| format!("{error:#}"))?;
    with_config(&state, |shared| *shared = config);
    Ok(())
}

#[tauri::command]
async fn rollback_deployment(
    state: State<'_, AppState>,
    deployment_id: String,
) -> Result<String, String> {
    let _guard = acquire_operation(&state)?;
    let deployment_id =
        uuid::Uuid::parse_str(&deployment_id).map_err(|_| "invalid deployment UUID")?;
    let mut config = with_config(&state, |config| config.clone());
    let remote_id = veilweave_core::deploy::rollback(
        deployment_id,
        &mut config,
        &state.credentials,
        state.network.clone(),
        true,
    )
    .await
    .map_err(|error| format!("{error:#}"))?;
    with_config(&state, |shared| *shared = config);
    Ok(remote_id)
}

#[tauri::command]
async fn rotate_subscription_token(
    state: State<'_, AppState>,
    deployment_id: String,
) -> Result<String, String> {
    let _guard = acquire_operation(&state)?;
    let deployment_id =
        uuid::Uuid::parse_str(&deployment_id).map_err(|_| "invalid deployment UUID")?;
    let mut config = with_config(&state, |config| config.clone());
    let remote_id = veilweave_core::deploy::rotate_subscription_token(
        deployment_id,
        &BundleSource::Embedded(embedded_bundle()),
        &mut config,
        &state.credentials,
        state.network.clone(),
        true,
    )
    .await
    .map_err(|error| format!("{error:#}"))?;
    with_config(&state, |shared| *shared = config);
    Ok(remote_id)
}

#[derive(Deserialize)]
struct NetworkConfigWire {
    mode: NetworkMode,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default = "default_true")]
    remote_dns: bool,
    #[serde(default)]
    allow_direct_fallback: bool,
    #[serde(default)]
    bypass: Vec<String>,
    #[serde(default = "default_connect_timeout")]
    connect_timeout_secs: u64,
    #[serde(default = "default_request_timeout")]
    request_timeout_secs: u64,
    #[serde(default)]
    http_scheme: HttpProxyScheme,
}

fn default_true() -> bool {
    true
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_request_timeout() -> u64 {
    45
}

impl NetworkConfigWire {
    fn into_config(
        self,
        current: &NetworkConfig,
        credentials: &CredentialManager,
    ) -> Result<NetworkConfig, String> {
        let proxy = match self.mode {
            NetworkMode::Direct | NetworkMode::System => None,
            NetworkMode::Socks5 | NetworkMode::HttpProxy => {
                let username = self
                    .username
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| value.trim().to_string());
                let credential_ref = if let Some(username_value) = &username {
                    let reference = CredentialManager::keyring_reference("network/proxy/default");
                    if let Some(password) = self.password.filter(|value| !value.is_empty()) {
                        credentials
                            .store_verified(&reference, &password)
                            .map_err(|error| format!("{error:#}"))?;
                    } else {
                        let reusable = current.proxy.as_ref().is_some_and(|proxy| {
                            proxy.username.as_ref() == Some(username_value)
                                && proxy.credential_ref.as_ref() == Some(&reference)
                        });
                        if !reusable {
                            return Err(
                                "a proxy password is required when adding or changing authentication"
                                    .into(),
                            );
                        }
                    }
                    Some(reference)
                } else {
                    None
                };
                Some(ProxyConfig {
                    host: self
                        .host
                        .context("proxy host is required")
                        .map_err(|error| error.to_string())?,
                    port: self
                        .port
                        .context("proxy port is required")
                        .map_err(|error| error.to_string())?,
                    username,
                    credential_ref,
                    remote_dns: self.remote_dns,
                    allow_direct_fallback: self.allow_direct_fallback,
                    connect_timeout_secs: self.connect_timeout_secs,
                    http_scheme: self.http_scheme,
                })
            }
        };
        let config = NetworkConfig {
            mode: self.mode,
            proxy,
            bypass: self.bypass,
            request_timeout_secs: self.request_timeout_secs,
        };
        config.validate().map_err(|error| format!("{error:#}"))?;
        Ok(config)
    }
}

#[tauri::command]
fn save_network(
    state: State<'_, AppState>,
    settings: NetworkConfigWire,
) -> Result<NetworkView, String> {
    let current = with_config(&state, |config| config.network.clone());
    let proxy_reference = CredentialManager::keyring_reference("network/proxy/default");
    let stages_proxy_password =
        matches!(settings.mode, NetworkMode::Socks5 | NetworkMode::HttpProxy)
            && settings
                .username
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            && settings
                .password
                .as_deref()
                .is_some_and(|value| !value.is_empty());
    let previous_proxy_password: Option<SecretValue> = if stages_proxy_password
        && current
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.credential_ref.as_ref())
            == Some(&proxy_reference)
    {
        Some(
            state
                .credentials
                .resolve(&proxy_reference)
                .map_err(|error| {
                    format!("read existing proxy credential before update: {error:#}")
                })?,
        )
    } else {
        None
    };

    let prepared = (|| {
        let replacement = settings.into_config(&current, &state.credentials)?;
        // Build generation N+1 completely before touching persisted or active
        // state. Installing this prepared generation is an infallible swap.
        let prepared = state
            .network
            .prepare_replacement(replacement.clone())
            .map_err(|error| format!("{error:#}"))?;
        let mut candidate = with_config(&state, |config| config.clone());
        candidate.network = replacement;
        candidate.save().map_err(|error| format!("{error:#}"))?;
        Ok::<_, String>((prepared, candidate))
    })();
    let (prepared, candidate) = match prepared {
        Ok(value) => value,
        Err(error) => {
            if stages_proxy_password {
                let rollback = match previous_proxy_password {
                    Some(previous) => state
                        .credentials
                        .store_verified(&proxy_reference, previous.expose()),
                    None => state.credentials.delete(&proxy_reference),
                };
                if let Err(rollback_error) = rollback {
                    return Err(format!(
                        "{error}; proxy credential rollback also failed: {rollback_error:#}"
                    ));
                }
            }
            return Err(error);
        }
    };
    let generation = state.network.install_prepared(prepared);
    with_config(&state, |config| *config = candidate);
    let snapshot = state.network.snapshot();
    let summary = snapshot.config().summary();
    Ok(NetworkView {
        mode: summary.mode,
        proxy_endpoint: summary.proxy_endpoint,
        host: snapshot
            .config()
            .proxy
            .as_ref()
            .map(|proxy| proxy.host.clone()),
        port: snapshot.config().proxy.as_ref().map(|proxy| proxy.port),
        username: snapshot
            .config()
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.username.clone()),
        remote_dns: summary.remote_dns,
        allow_direct_fallback: summary.allow_direct_fallback,
        bypass: summary.bypass,
        request_timeout_secs: snapshot.config().request_timeout_secs,
        http_scheme: snapshot
            .config()
            .proxy
            .as_ref()
            .map(|proxy| proxy.http_scheme),
        generation,
    })
}

#[tauri::command]
async fn test_network(
    state: State<'_, AppState>,
) -> Result<veilweave_core::network::NetworkTestReport, String> {
    Ok(state.network.test_connection().await)
}

#[tauri::command]
async fn open_url(url: String) -> Result<(), String> {
    tauri_plugin_opener::open_url(&url, None::<&str>).map_err(|error| error.to_string())
}

#[tauri::command]
fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn updater(app: &AppHandle) -> Result<tauri_plugin_updater::Updater, String> {
    use tauri_plugin_updater::UpdaterExt;
    let state = app.state::<AppState>();
    let snapshot = state.network.snapshot();
    let mut builder = app.updater_builder();
    match snapshot.config().mode {
        NetworkMode::Direct => builder = builder.no_proxy(),
        NetworkMode::System => {}
        NetworkMode::Socks5 | NetworkMode::HttpProxy => {
            let url = snapshot
                .updater_proxy_url()
                .ok_or_else(|| "explicit updater proxy is missing".to_string())?;
            let bypass = snapshot.config().bypass.join(",");
            let mut proxy = reqwest::Proxy::all(url.as_str())
                .map_err(|error| format!("build updater proxy: {error}"))?;
            if !bypass.is_empty() {
                proxy = proxy.no_proxy(reqwest::NoProxy::from_string(&bypass));
            }
            // no_proxy first prevents system/environment proxy mixing. The
            // single explicit all-destinations rule is feature-unified with
            // reqwest 0.13.4 + socks for SOCKS5/SOCKS5H.
            builder = builder
                .no_proxy()
                .configure_client(move |client| client.proxy(proxy.clone()));
        }
    }
    builder
        .build()
        .map_err(|error| format!("updater unavailable: {error}"))
}

#[tauri::command]
async fn check_update(app: AppHandle) -> Result<String, String> {
    match updater(&app)?.check().await {
        Ok(Some(update)) => Ok(format!("update available: v{}", update.version)),
        Ok(None) => Ok("up to date".into()),
        Err(error) => Err(format!("update check failed: {error}")),
    }
}

#[tauri::command]
async fn install_update(app: AppHandle) -> Result<String, String> {
    let Some(update) = updater(&app)?
        .check()
        .await
        .map_err(|error| format!("update check failed: {error}"))?
    else {
        return Ok("up to date".into());
    };
    let version = update.version.clone();
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|error| format!("signed update download/install failed: {error}"))?;
    Ok(format!("installed v{version}"))
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            load_state(app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_config,
            set_ui_language,
            discover_accounts,
            add_account,
            delete_account,
            recover,
            usage,
            list_zones,
            random_worker_name,
            random_kv_binding,
            start_deploy,
            get_subscription_url,
            get_proxyip_cache_status,
            refresh_proxyip_cache,
            delete_deployment,
            update_deployment,
            rollback_deployment,
            rotate_subscription_token,
            save_network,
            test_network,
            open_url,
            app_version,
            check_update,
            install_update,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Veilweave");
}

#[cfg(test)]
mod tests {
    use super::*;
    use veilweave_core::config::{EndpointConfig, SubDetails};

    #[test]
    fn frontend_config_view_never_serializes_credentials_or_secret_references() {
        let account = Account {
            name: "personal".into(),
            account_id: "account-id".into(),
            credential_ref: "keyring:account/sensitive-token-ref".into(),
            workers_dev_subdomain: Some("alice".into()),
        };
        let deployment = Deployment {
            id: uuid::Uuid::new_v4(),
            role: Role::Sub,
            name: "sub-worker".into(),
            account_id: account.account_id.clone(),
            secret_ref: "keyring:deployment/sensitive-nodes-ref".into(),
            node_secret_ref: None,
            endpoint: EndpointConfig {
                mode: ExposureMode::WorkersDev,
                primary: PrimaryEndpoint::WorkersDev,
                workers_dev_enabled: true,
                workers_dev_hostname: Some("sub-worker.alice.workers.dev".into()),
                custom_domains: Vec::new(),
            },
            created_at: "2026-08-22T00:00:00Z".into(),
            updated_at: None,
            stable_version_id: Some("version-id".into()),
            stable_deployment_id: Some("deployment-id".into()),
            previous_version_id: None,
            previous_deployment_id: None,
            bundle_hash: Some("bundle-hash".into()),
            sub: Some(SubDetails {
                kv_namespace_id: "kv-id".into(),
                kv_title: "kv-title".into(),
                kv_binding: "VEILWEAVE_KV".into(),
                subscription_token_ref: "keyring:deployment/sensitive-subscription-token-ref"
                    .into(),
                max_nodes: 100,
                fingerprint: "chrome".into(),
                ech: None,
            }),
        };
        let config = Config {
            accounts: vec![account],
            deployments: vec![deployment],
            ..Config::default()
        };
        let network = NetworkManager::direct().unwrap();
        let serialized = serde_json::to_string(&config_view(&config, &network)).unwrap();
        assert!(!serialized.contains("keyring:"));
        assert!(!serialized.contains("sensitive"));
        assert!(!serialized.contains("subscription_token_ref"));
        assert!(!serialized.contains("credential_ref"));
    }
}
