//! UI-agnostic deploy orchestration. The CLI wizard (and later the GUI) build
//! a `DeployPlan`, then call `execute` with a log callback. Nothing in here
//! prints or prompts.

use crate::cfapi::{self, CfClient};
use crate::config::{Account, Config, Deployment, Role, SubDetails};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DeployPlan {
    pub sub: SubSpec,
    pub relays: Vec<RelaySpec>,
    /// false = plaintext VLESS (encryption=none, shared raw secret per relay).
    /// true = EXPERIMENTAL blob pair (UUID secret + X25519 keypair per relay).
    pub encryption: bool,
}

#[derive(Debug, Clone)]
pub struct SubSpec {
    /// `Account.name` hosting the sub worker.
    pub account: String,
    pub worker_name: String,
    pub kv_title: String,
    /// KV binding name (valid JS identifier); also set as the KV_BINDING var.
    pub kv_binding: String,
}

#[derive(Debug, Clone)]
pub struct RelaySpec {
    /// `Account.name` hosting this relay.
    pub account: String,
    pub worker_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    Step,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub kind: LogKind,
    pub message: String,
}

impl LogLine {
    fn new(kind: LogKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RelayOutcome {
    pub name: String,
    pub domain: String,
    /// The secret the sub uses for this node (raw secret or sub blob).
    pub node_secret: String,
}

#[derive(Debug, Clone)]
pub struct SubOutcome {
    pub name: String,
    pub domain: String,
    pub kv_namespace_id: String,
    /// Also embedded in `subscription_url`; kept separate for UIs that want
    /// to display/store the token on its own.
    #[allow(dead_code)]
    pub subscription_token: String,
    pub subscription_url: String,
}

#[derive(Debug, Default)]
pub struct DeployOutcome {
    pub relays: Vec<RelayOutcome>,
    pub sub: Option<SubOutcome>,
    /// Human-readable list of what succeeded, for partial-failure reports.
    pub completed: Vec<String>,
}

impl DeployOutcome {
    pub fn subscription_url(&self) -> Option<&str> {
        self.sub.as_ref().map(|s| s.subscription_url.as_str())
    }
}

/// `bundle/` next to the executable (as shipped in the release archive),
/// unless overridden.
pub fn locate_bundle_dir(override_dir: Option<&str>) -> PathBuf {
    match override_dir {
        Some(d) => PathBuf::from(d),
        None => std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("bundle")))
            .unwrap_or_else(|| PathBuf::from("bundle")),
    }
}

/// Assemble the sub's VEILWEAVE_NODES value: `domain|secret`, comma-joined.
pub fn build_nodes_value(nodes: &[(String, String)]) -> String {
    nodes
        .iter()
        .map(|(domain, secret)| format!("{domain}|{secret}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Run the plan against the Cloudflare API. Updates `cfg.deployments` with
/// everything that was created and saves the config — including on partial
/// failure, so a half-finished deploy is still visible to `manage`.
pub async fn execute(
    plan: &DeployPlan,
    bundle_dir: &Path,
    cfg: &mut Config,
    log: &mut dyn FnMut(LogLine),
) -> Result<DeployOutcome> {
    if plan.relays.is_empty() {
        bail!("deploy plan has no relays — a sub without nodes is useless");
    }
    let relay_build = bundle_dir.join("relay").join("build");
    let sub_build = bundle_dir.join("sub").join("build");
    for (unit, dir) in [("relay", &relay_build), ("sub", &sub_build)] {
        if !dir.join("index.js").is_file() {
            bail!(
                "prebuilt {unit} worker not found at {} — download the full \
                 release archive (it contains bundle/{unit}/)",
                dir.display()
            );
        }
    }

    // One client + workers.dev subdomain per distinct account in the plan.
    let mut clients: HashMap<String, CfClient> = HashMap::new();
    let mut subdomains: HashMap<String, String> = HashMap::new();
    for account_name in plan
        .relays
        .iter()
        .map(|r| &r.account)
        .chain(std::iter::once(&plan.sub.account))
    {
        if clients.contains_key(account_name) {
            continue;
        }
        let account = resolve_account(cfg, account_name)?;
        let client = CfClient::new(&account.token)?;
        let subdomain = match &account.workers_dev_subdomain {
            Some(s) => s.clone(),
            None => client.get_workers_subdomain(&account.account_id).await?,
        };
        clients.insert(account_name.clone(), client);
        subdomains.insert(account_name.clone(), subdomain);
    }

    let mut outcome = DeployOutcome::default();

    // ── Relays first: the sub needs their domains. ─────────────────────────
    for spec in &plan.relays {
        let result = deploy_relay(
            spec,
            plan.encryption,
            &clients,
            &subdomains,
            cfg,
            &relay_build,
            log,
        )
        .await;
        match result {
            Ok(relay) => {
                outcome
                    .completed
                    .push(format!("relay {:?} → https://{}", relay.name, relay.domain));
                outcome.relays.push(relay);
            }
            Err(e) => {
                log(LogLine::new(
                    LogKind::Error,
                    format!("relay {:?} failed: {e:#}", spec.worker_name),
                ));
                report_partial(&outcome, log);
                save_config(cfg, log);
                return Err(e);
            }
        }
    }

    // ── Then the sub. ──────────────────────────────────────────────────────
    match deploy_sub(
        &plan.sub,
        &outcome.relays,
        &clients,
        &subdomains,
        cfg,
        &sub_build,
        log,
    )
    .await
    {
        Ok(sub) => {
            outcome.completed.push(format!(
                "sub {:?} → {}  (KV {})",
                sub.name, sub.domain, sub.kv_namespace_id
            ));
            outcome.sub = Some(sub);
        }
        Err(e) => {
            log(LogLine::new(
                LogKind::Error,
                format!("sub {:?} failed: {e:#}", plan.sub.worker_name),
            ));
            report_partial(&outcome, log);
            save_config(cfg, log);
            return Err(e);
        }
    }

    save_config(cfg, log);
    Ok(outcome)
}

async fn deploy_relay(
    spec: &RelaySpec,
    encryption: bool,
    clients: &HashMap<String, CfClient>,
    subdomains: &HashMap<String, String>,
    cfg: &mut Config,
    build_dir: &Path,
    log: &mut dyn FnMut(LogLine),
) -> Result<RelayOutcome> {
    let name = &spec.worker_name;
    log(LogLine::new(
        LogKind::Step,
        format!("relay {name}: preparing secrets"),
    ));
    // Each relay gets its OWN independently generated secret.
    let (relay_secret, node_secret) = if encryption {
        crate::gen_secret_pair()
    } else {
        let raw = crate::gen_raw_secret();
        (raw.clone(), raw)
    };

    log(LogLine::new(
        LogKind::Step,
        format!("relay {name}: uploading worker"),
    ));
    let files = build_files_with_nonce(build_dir)?;
    clients[&spec.account]
        .upload_worker(
            &account_id(cfg, &spec.account)?,
            name,
            files,
            cfapi::relay_metadata(&relay_secret),
        )
        .await?;

    log(LogLine::new(
        LogKind::Step,
        format!("relay {name}: enabling workers.dev"),
    ));
    clients[&spec.account]
        .enable_workers_dev(&account_id(cfg, &spec.account)?, name)
        .await?;

    let domain = format!("{name}.{}.workers.dev", subdomains[&spec.account]);
    log(LogLine::new(
        LogKind::Info,
        format!("relay {name}: live at {domain}"),
    ));

    cfg.deployments.push(Deployment {
        role: Role::Relay,
        name: name.clone(),
        account: spec.account.clone(),
        domain: domain.clone(),
        secret: relay_secret,
        created_at: crate::config::now_utc_string(),
        sub: None,
    });

    Ok(RelayOutcome {
        name: name.clone(),
        domain,
        node_secret,
    })
}

async fn deploy_sub(
    spec: &SubSpec,
    relays: &[RelayOutcome],
    clients: &HashMap<String, CfClient>,
    subdomains: &HashMap<String, String>,
    cfg: &mut Config,
    build_dir: &Path,
    log: &mut dyn FnMut(LogLine),
) -> Result<SubOutcome> {
    let name = &spec.worker_name;
    let account_id = account_id(cfg, &spec.account)?;
    let client = &clients[&spec.account];

    log(LogLine::new(
        LogKind::Step,
        format!("sub {name}: creating KV namespace {:?}", spec.kv_title),
    ));
    let kv_namespace_id = client
        .create_kv_namespace(&account_id, &spec.kv_title)
        .await?;

    let nodes = build_nodes_value(
        &relays
            .iter()
            .map(|r| (r.domain.clone(), r.node_secret.clone()))
            .collect::<Vec<_>>(),
    );
    let token = crate::generate_hex_id(32);

    log(LogLine::new(
        LogKind::Step,
        format!("sub {name}: uploading worker"),
    ));
    let files = build_files_with_nonce(build_dir)?;
    client
        .upload_worker(
            &account_id,
            name,
            files,
            cfapi::sub_metadata(&nodes, &token, &spec.kv_binding, &kv_namespace_id),
        )
        .await?;

    log(LogLine::new(
        LogKind::Step,
        format!("sub {name}: enabling workers.dev"),
    ));
    client.enable_workers_dev(&account_id, name).await?;

    let domain = format!("{name}.{}.workers.dev", subdomains[&spec.account]);
    let subscription_url = format!("https://{domain}/sub?token={token}");
    log(LogLine::new(
        LogKind::Info,
        format!("sub {name}: live at {domain}"),
    ));

    cfg.deployments.push(Deployment {
        role: Role::Sub,
        name: name.clone(),
        account: spec.account.clone(),
        domain: domain.clone(),
        // The sub has no secret of its own; record the nodes value it serves.
        secret: nodes,
        created_at: crate::config::now_utc_string(),
        sub: Some(SubDetails {
            kv_namespace_id: kv_namespace_id.clone(),
            kv_title: spec.kv_title.clone(),
            kv_binding: spec.kv_binding.clone(),
            subscription_token: token.clone(),
        }),
    });

    Ok(SubOutcome {
        name: name.clone(),
        domain,
        kv_namespace_id,
        subscription_token: token,
        subscription_url,
    })
}

/// Read the prebuilt worker and inject the per-run nonce comment into
/// `index.js` (shared with the `bundle` command via `crate::inject_nonce`).
fn build_files_with_nonce(build_dir: &Path) -> Result<Vec<cfapi::UploadFile>> {
    let mut files = cfapi::collect_build_files(build_dir)?;
    for f in &mut files {
        if f.name == "index.js" {
            let js = String::from_utf8(std::mem::take(&mut f.contents))
                .context("build/index.js is not valid UTF-8")?;
            f.contents = crate::inject_nonce(&js).into_bytes();
        }
    }
    Ok(files)
}

fn resolve_account(cfg: &Config, name: &str) -> Result<Account> {
    cfg.account(name)
        .cloned()
        .ok_or_else(|| anyhow!("account {name:?} not found in config — add it first"))
}

fn account_id(cfg: &Config, name: &str) -> Result<String> {
    Ok(resolve_account(cfg, name)?.account_id)
}

fn report_partial(outcome: &DeployOutcome, log: &mut dyn FnMut(LogLine)) {
    if outcome.completed.is_empty() {
        log(LogLine::new(
            LogKind::Warn,
            "nothing was deployed before the failure",
        ));
        return;
    }
    log(LogLine::new(
        LogKind::Warn,
        "deploy stopped partway — these already exist on Cloudflare (see `veilweave-tools manage`):",
    ));
    for step in &outcome.completed {
        log(LogLine::new(LogKind::Warn, format!("  · {step}")));
    }
}

fn save_config(cfg: &Config, log: &mut dyn FnMut(LogLine)) {
    if let Err(e) = cfg.save() {
        log(LogLine::new(
            LogKind::Warn,
            format!("could not save local config: {e:#} (deployments are NOT recorded locally)"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodes_value_assembly() {
        let nodes = vec![
            (
                "edge-a.user.workers.dev".to_string(),
                "raw-secret-1".to_string(),
            ),
            (
                "gate-b.user.workers.dev".to_string(),
                "VW1Bblob".to_string(),
            ),
        ];
        assert_eq!(
            build_nodes_value(&nodes),
            "edge-a.user.workers.dev|raw-secret-1,gate-b.user.workers.dev|VW1Bblob"
        );
        assert_eq!(build_nodes_value(&[]), "");
        let single = vec![("d".to_string(), "s".to_string())];
        assert_eq!(build_nodes_value(&single), "d|s");
    }
}
