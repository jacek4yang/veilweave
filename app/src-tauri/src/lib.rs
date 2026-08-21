//! veilweave desktop — Tauri command layer over `veilweave-core`.
//!
//! All Cloudflare API work happens in async commands on tauri's tokio runtime;
//! the frontend talks to this file via `invoke` and listens for `deploy-log` /
//! `deploy-done` events during a deploy.

mod bundle;

use bundle::embedded_bundle;
use serde::Serialize;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};
use veilweave_core::cfapi::{self, CfClient, FREE_TIER_DAILY_REQUESTS};
use veilweave_core::config::{Account, Config, Deployment, Role};
use veilweave_core::deploy::{BundleSource, DeployPlan, LogKind, LogLine, RelaySpec, SubSpec};
use veilweave_core::util;

/// Shared app state: the persisted config, guarded by a mutex. Commands lock
/// it only briefly — never across an `.await` (deploy works on a clone and
/// swaps the result back in).
struct AppState(Mutex<Config>);

fn load_state(app: &AppHandle) {
    let cfg = Config::load().unwrap_or_else(|e| {
        eprintln!("warning: could not load config ({e:#}); starting empty");
        Config::default()
    });
    app.manage(AppState(Mutex::new(cfg)));
}

fn with_config<R>(state: &State<'_, AppState>, f: impl FnOnce(&mut Config) -> R) -> R {
    let mut guard = state.0.lock().expect("config mutex poisoned");
    f(&mut guard)
}

fn save_config(state: &State<'_, AppState>) -> Result<(), String> {
    with_config(state, |cfg| cfg.save()).map_err(|e| format!("{e:#}"))
}

// ─── frontend-facing DTOs ────────────────────────────────────────────────────

/// Account as the UI sees it — the API token never leaves the backend.
#[derive(Serialize, Clone)]
struct AccountView {
    name: String,
    account_id: String,
    workers_dev_subdomain: Option<String>,
    deployment_count: usize,
}

fn account_views(cfg: &Config) -> Vec<AccountView> {
    cfg.accounts
        .iter()
        .map(|a| AccountView {
            name: a.name.clone(),
            account_id: a.account_id.clone(),
            workers_dev_subdomain: a.workers_dev_subdomain.clone(),
            deployment_count: cfg
                .deployments
                .iter()
                .filter(|d| d.account == a.name)
                .count(),
        })
        .collect()
}

#[derive(Serialize)]
struct ConfigView {
    accounts: Vec<AccountView>,
    deployments: Vec<Deployment>,
    ui_language: Option<String>,
}

fn config_view(cfg: &Config) -> ConfigView {
    ConfigView {
        accounts: account_views(cfg),
        deployments: cfg.deployments.clone(),
        ui_language: cfg.ui_language.clone(),
    }
}

// UsageRow has no Serialize derive in core; wrap it.
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
    message: String,
}

impl From<&LogLine> for DeployLogEvent {
    fn from(l: &LogLine) -> Self {
        let kind = match l.kind {
            LogKind::Step => "step",
            LogKind::Info => "info",
            LogKind::Warn => "warn",
            LogKind::Error => "error",
        };
        Self {
            kind: kind.to_string(),
            message: l.message.clone(),
        }
    }
}

// ─── commands ────────────────────────────────────────────────────────────────

#[tauri::command]
fn get_config(state: State<'_, AppState>) -> ConfigView {
    with_config(&state, |cfg| config_view(cfg))
}

#[tauri::command]
fn set_ui_language(state: State<'_, AppState>, language: Option<String>) -> Result<(), String> {
    with_config(&state, |cfg| cfg.ui_language = language);
    save_config(&state)
}

#[tauri::command]
async fn add_account(
    state: State<'_, AppState>,
    label: Option<String>,
    token: String,
) -> Result<AccountView, String> {
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err("token is empty".into());
    }
    let client = CfClient::new(&token).map_err(|e| format!("{e:#}"))?;
    client.verify_token().await.map_err(|e| format!("{e:#}"))?;
    let accounts = client.list_accounts().await.map_err(|e| format!("{e:#}"))?;
    if accounts.is_empty() {
        return Err("this token can see no Cloudflare accounts".into());
    }
    // Single-account tokens are the common case; with several, match the label
    // against the Cloudflare account name, else take the first.
    let picked = match (&label, accounts.len()) {
        (Some(l), n) if n > 1 && !l.is_empty() => accounts
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(l))
            .cloned()
            .unwrap_or_else(|| accounts[0].clone()),
        _ => accounts[0].clone(),
    };
    let subdomain = client
        .get_workers_subdomain(&picked.id)
        .await
        .map_err(|e| format!("{e:#}"))?;

    let label = label
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| picked.name.clone());

    let view = with_config(&state, |cfg| {
        if cfg.account(&label).is_some() {
            return Err(format!("account {label:?} already exists"));
        }
        cfg.accounts.push(Account {
            name: label.clone(),
            token,
            account_id: picked.id.clone(),
            workers_dev_subdomain: Some(subdomain.clone()),
        });
        Ok(AccountView {
            name: label,
            account_id: picked.id,
            workers_dev_subdomain: Some(subdomain),
            deployment_count: 0,
        })
    })?;
    save_config(&state)?;
    Ok(view)
}

#[tauri::command]
fn delete_account(state: State<'_, AppState>, name: String) -> Result<(), String> {
    with_config(&state, |cfg| {
        let refs = cfg.deployments.iter().filter(|d| d.account == name).count();
        if refs > 0 {
            return Err(format!(
                "account {name:?} still has {refs} deployment(s) — delete them first"
            ));
        }
        let before = cfg.accounts.len();
        cfg.accounts.retain(|a| a.name != name);
        if cfg.accounts.len() == before {
            return Err(format!("account {name:?} not found"));
        }
        Ok(())
    })?;
    save_config(&state)
}

#[derive(Serialize)]
struct RecoverView {
    added: usize,
    summary: Vec<String>,
}

#[tauri::command]
async fn recover(state: State<'_, AppState>, name: String) -> Result<RecoverView, String> {
    let account = with_config(&state, |cfg| cfg.account(&name).cloned())
        .ok_or_else(|| format!("account {name:?} not found"))?;
    let client = CfClient::new(&account.token).map_err(|e| format!("{e:#}"))?;
    let subdomain = match &account.workers_dev_subdomain {
        Some(s) => s.clone(),
        None => client
            .get_workers_subdomain(&account.account_id)
            .await
            .map_err(|e| format!("{e:#}"))?,
    };
    let outcome = veilweave_core::recover::recover_account(
        &client,
        &account.account_id,
        &account.name,
        &subdomain,
    )
    .await
    .map_err(|e| format!("{e:#}"))?;

    let added = with_config(&state, |cfg| {
        let mut added = 0;
        for dep in outcome.deployments {
            let exists = cfg
                .deployments
                .iter()
                .any(|d| d.account == dep.account && d.name == dep.name);
            if !exists {
                cfg.deployments.push(dep);
                added += 1;
            }
        }
        added
    });
    save_config(&state)?;
    Ok(RecoverView {
        added,
        summary: outcome.summary,
    })
}

#[tauri::command]
async fn usage(state: State<'_, AppState>, name: String) -> Result<UsageResult, String> {
    let account = with_config(&state, |cfg| cfg.account(&name).cloned())
        .ok_or_else(|| format!("account {name:?} not found"))?;
    let client = CfClient::new(&account.token).map_err(|e| format!("{e:#}"))?;
    match client.account_usage(&account.account_id).await {
        Ok(rows) => Ok(UsageResult {
            rows: rows
                .into_iter()
                .map(|r| UsageRowView {
                    script: r.script,
                    requests: r.requests,
                    errors: r.errors,
                    cpu_p50_us: r.cpu_p50_us,
                })
                .collect(),
            analytics_error: None,
            free_tier_daily_requests: FREE_TIER_DAILY_REQUESTS,
        }),
        Err(e) => Ok(UsageResult {
            rows: vec![],
            analytics_error: Some(format!("{e:#}")),
            free_tier_daily_requests: FREE_TIER_DAILY_REQUESTS,
        }),
    }
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
    // core::execute takes `&mut dyn FnMut(LogLine)` (not Send), so its future
    // can't live on tauri's multithreaded runtime. Run it on a dedicated
    // thread with a current-thread runtime; progress is streamed to the
    // frontend as `deploy-log` events, and the end as `deploy-done`.
    let cfg = with_config(&app.state::<AppState>(), |c| c.clone());
    let plan = DeployPlan {
        sub: SubSpec {
            account: plan.sub.account,
            worker_name: plan.sub.worker_name,
            kv_title: plan.sub.kv_title,
            kv_binding: plan.sub.kv_binding,
        },
        relays: plan
            .relays
            .into_iter()
            .map(|r| RelaySpec {
                account: r.account,
                worker_name: r.worker_name,
            })
            .collect(),
        encryption: plan.encryption,
    };

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = app.emit(
                    "deploy-done",
                    DeployDone {
                        ok: false,
                        relays: vec![],
                        subscription_url: None,
                        completed: vec![],
                        error: Some(format!("could not start deploy runtime: {e}")),
                    },
                );
                return;
            }
        };
        rt.block_on(run_deploy(app, cfg, plan));
    });
    Ok(())
}

async fn run_deploy(app: AppHandle, mut cfg: Config, plan: DeployPlan) {
    let source = BundleSource::Embedded(embedded_bundle());
    let app2 = app.clone();
    let result = veilweave_core::deploy::execute(&plan, &source, &mut cfg, &mut |line| {
        let _ = app2.emit("deploy-log", DeployLogEvent::from(&line));
    })
    .await;

    let state = app.state::<AppState>();
    let done = match result {
        Ok(outcome) => {
            with_config(&state, |c| *c = cfg);
            DeployDone {
                ok: true,
                relays: outcome
                    .relays
                    .iter()
                    .map(|r| RelayDone {
                        name: r.name.clone(),
                        domain: r.domain.clone(),
                    })
                    .collect(),
                subscription_url: outcome.subscription_url().map(str::to_string),
                completed: outcome.completed,
                error: None,
            }
        }
        Err(e) => {
            // Partial progress was already saved to disk by execute — reload it
            // into shared state so manage/overview reflect what exists.
            if let Ok(saved) = Config::load() {
                with_config(&state, |c| *c = saved);
            }
            DeployDone {
                ok: false,
                relays: vec![],
                subscription_url: None,
                completed: vec![],
                error: Some(format!("{e:#}")),
            }
        }
    };
    let _ = app.emit("deploy-done", done);
}

#[tauri::command]
async fn delete_deployment(
    state: State<'_, AppState>,
    name: String,
    account: String,
) -> Result<(), String> {
    let (acc, dep) = with_config(&state, |cfg| {
        let acc = cfg.account(&account).cloned();
        let dep = cfg
            .deployments
            .iter()
            .find(|d| d.account == account && d.name == name)
            .cloned();
        (acc, dep)
    });
    let acc = acc.ok_or_else(|| format!("account {account:?} not found"))?;
    let dep = dep.ok_or_else(|| format!("deployment {name:?} not found"))?;

    let client = CfClient::new(&acc.token).map_err(|e| format!("{e:#}"))?;
    let worker_err = client
        .delete_worker(&acc.account_id, &name)
        .await
        .err()
        .map(|e| format!("{e:#}"));
    // For subs, also remove the KV namespace. A missing namespace (already
    // deleted manually) should not block the record removal.
    let kv_err = match &dep.sub {
        Some(sub) if !sub.kv_namespace_id.is_empty() => client
            .delete_kv_namespace(&acc.account_id, &sub.kv_namespace_id)
            .await
            .err()
            .map(|e| format!("{e:#}")),
        _ => None,
    };
    if let Some(e) = worker_err {
        return Err(format!("delete worker failed: {e}"));
    }
    with_config(&state, |cfg| {
        cfg.deployments
            .retain(|d| !(d.account == account && d.name == name));
    });
    save_config(&state)?;
    if let Some(e) = kv_err {
        return Err(format!(
            "worker deleted, but KV namespace removal failed: {e}"
        ));
    }
    Ok(())
}

#[tauri::command]
async fn update_deployment(
    state: State<'_, AppState>,
    name: String,
    account: String,
) -> Result<(), String> {
    let (acc, dep) = with_config(&state, |cfg| {
        let acc = cfg.account(&account).cloned();
        let dep = cfg
            .deployments
            .iter()
            .find(|d| d.account == account && d.name == name)
            .cloned();
        (acc, dep)
    });
    let acc = acc.ok_or_else(|| format!("account {account:?} not found"))?;
    let dep = dep.ok_or_else(|| format!("deployment {name:?} not found"))?;

    // Rebuild upload metadata from the values stored in config — secrets and
    // KV bindings are preserved; only the worker code is refreshed.
    let (unit, metadata) = match dep.role {
        Role::Relay => ("relay", cfapi::relay_metadata(&dep.secret)),
        Role::Sub => {
            let sub = dep
                .sub
                .as_ref()
                .ok_or("sub deployment is missing its KV details")?;
            (
                "sub",
                cfapi::sub_metadata(
                    &dep.secret,
                    &sub.subscription_token,
                    &sub.kv_binding,
                    &sub.kv_namespace_id,
                ),
            )
        }
    };
    let files = bundle::upload_files(unit).map_err(|e| format!("{e:#}"))?;

    let client = CfClient::new(&acc.token).map_err(|e| format!("{e:#}"))?;
    client
        .upload_worker(&acc.account_id, &name, files, metadata)
        .await
        .map_err(|e| format!("{e:#}"))?;
    Ok(())
}

#[tauri::command]
async fn open_url(url: String) -> Result<(), String> {
    tauri_plugin_opener::open_url(&url, None::<&str>).map_err(|e| e.to_string())
}

#[tauri::command]
fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Check GitHub releases for a newer build. Until the real updater pubkey is
/// injected this returns a graceful "unavailable" string instead of failing.
#[tauri::command]
async fn check_update(app: AppHandle) -> Result<String, String> {
    use tauri_plugin_updater::UpdaterExt;
    let updater = app
        .updater()
        .map_err(|e| format!("updater unavailable: {e}"))?;
    match updater.check().await {
        Ok(Some(update)) => Ok(format!("update available: v{}", update.version)),
        Ok(None) => Ok("up to date".to_string()),
        Err(e) => Err(format!("update check failed: {e}")),
    }
}

// ─── wire types from the frontend ────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct DeployPlanWire {
    sub: SubSpecWire,
    relays: Vec<RelaySpecWire>,
    #[serde(default)]
    encryption: bool,
}

#[derive(serde::Deserialize)]
struct SubSpecWire {
    account: String,
    worker_name: String,
    kv_title: String,
    kv_binding: String,
}

#[derive(serde::Deserialize)]
struct RelaySpecWire {
    account: String,
    worker_name: String,
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            load_state(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_config,
            set_ui_language,
            add_account,
            delete_account,
            recover,
            usage,
            random_worker_name,
            random_kv_binding,
            start_deploy,
            delete_deployment,
            update_deployment,
            open_url,
            app_version,
            check_update,
        ])
        .run(tauri::generate_context!())
        .expect("error while running veilweave app");
}
