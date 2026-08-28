//! Transactional, UI-agnostic topology deployment.
//!
//! The CLI and desktop provide plans and render log events; this module alone
//! owns Cloudflare mutations, compensation, version promotion, and rollback.

use crate::bundle::{WorkerBundle, WorkerRole};
use crate::cfapi::{
    self, AttachDomainRequest, CfClient, SubSettings, VersionKind, WorkerDomain, WorkerOwnership,
};
use crate::config::{
    Account, Config, Deployment, DomainBinding, DomainStatus, EndpointConfig, ExposureMode,
    PrimaryEndpoint, Role, SubDetails,
};
use crate::credentials::{CredentialManager, SecretValue};
use crate::network::NetworkManager;
use crate::subscription;
use anyhow::{bail, Context, Result};
use reqwest::header::CONTENT_TYPE;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use uuid::Uuid;

const PROXYIP_REFRESH_CRON: &str = "17 */6 * * *";

#[derive(Debug, Clone)]
pub enum BundleSource {
    Dir(PathBuf),
    Embedded(EmbeddedBundle),
}

#[derive(Debug, Clone, Default)]
pub struct EmbeddedBundle {
    pub relay: EmbeddedWorkerBundle,
    pub sub: EmbeddedWorkerBundle,
}

#[derive(Debug, Clone, Default)]
pub struct EmbeddedWorkerBundle {
    pub manifest_json: Vec<u8>,
    pub modules: Vec<(String, Vec<u8>)>,
}

impl BundleSource {
    pub fn worker_bundle(&self, role: WorkerRole) -> Result<WorkerBundle> {
        match self {
            BundleSource::Dir(root) => {
                WorkerBundle::from_directory(&root.join(role.as_str()), role).with_context(|| {
                    format!(
                        "load canonical {} bundle from {}",
                        role.as_str(),
                        root.join(role.as_str()).display()
                    )
                })
            }
            BundleSource::Embedded(bundle) => {
                let embedded = match role {
                    WorkerRole::Relay => &bundle.relay,
                    WorkerRole::Sub => &bundle.sub,
                };
                WorkerBundle::from_embedded(&embedded.manifest_json, embedded.modules.clone(), role)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeployPlan {
    pub sub: SubSpec,
    pub relays: Vec<RelaySpec>,
    pub encryption: bool,
}

#[derive(Debug, Clone)]
pub struct SubSpec {
    pub account: String,
    pub worker_name: String,
    pub kv_title: String,
    pub kv_binding: String,
    pub endpoint: EndpointSpec,
    pub settings: SubSettings,
}

#[derive(Debug, Clone)]
pub struct RelaySpec {
    pub account: String,
    pub worker_name: String,
    pub endpoint: EndpointSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointSpec {
    #[serde(default)]
    pub mode: ExposureMode,
    #[serde(default)]
    pub primary: PrimaryEndpoint,
    #[serde(default)]
    pub custom_domain: Option<CustomDomainSpec>,
}

impl Default for EndpointSpec {
    fn default() -> Self {
        Self {
            mode: ExposureMode::WorkersDev,
            primary: PrimaryEndpoint::WorkersDev,
            custom_domain: None,
        }
    }
}

impl EndpointSpec {
    pub fn validate(&self) -> Result<()> {
        let custom_enabled = matches!(self.mode, ExposureMode::CustomDomain | ExposureMode::Both);
        let workers_enabled = matches!(self.mode, ExposureMode::WorkersDev | ExposureMode::Both);
        if custom_enabled != self.custom_domain.is_some() {
            bail!("custom-domain exposure must include exactly one Custom Domain specification");
        }
        if self.primary == PrimaryEndpoint::CustomDomain && !custom_enabled {
            bail!("custom domain cannot be primary when it is disabled");
        }
        if self.primary == PrimaryEndpoint::WorkersDev && !workers_enabled {
            bail!("workers.dev cannot be primary when it is disabled");
        }
        if let Some(domain) = &self.custom_domain {
            domain.validate()?;
        }
        Ok(())
    }

    fn workers_dev_enabled(&self) -> bool {
        matches!(self.mode, ExposureMode::WorkersDev | ExposureMode::Both)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomDomainSpec {
    pub hostname: String,
    pub zone_id: String,
    pub zone_name: String,
}

impl CustomDomainSpec {
    fn validate(&self) -> Result<()> {
        let hostname = crate::config::validate_hostname(&self.hostname)?;
        let zone = crate::config::validate_hostname(&self.zone_name)?;
        if hostname != zone && !hostname.ends_with(&format!(".{zone}")) {
            bail!(
                "Custom Domain {:?} is outside selected zone {:?}",
                self.hostname,
                self.zone_name
            );
        }
        if self.zone_id.trim().is_empty() {
            bail!("Custom Domain zone ID is empty");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogKind {
    Step,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub kind: LogKind,
    pub stage: DeployStage,
    pub message: String,
}

impl LogLine {
    fn new(kind: LogKind, stage: DeployStage, message: impl Into<String>) -> Self {
        Self {
            kind,
            stage,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeployStage {
    Preflight,
    Preparing,
    UploadingVersion,
    Deploying,
    BindingDomain,
    WaitingForEndpoint,
    Verifying,
    Persisting,
    RollingBack,
    Complete,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayOutcome {
    pub deployment_id: Uuid,
    pub name: String,
    pub domain: String,
    pub version_id: String,
    pub cloudflare_deployment_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubOutcome {
    pub deployment_id: Uuid,
    pub name: String,
    pub domain: String,
    pub kv_namespace_id: String,
    pub version_id: String,
    pub cloudflare_deployment_id: String,
}

#[derive(Debug, Default, Serialize)]
pub struct DeployOutcome {
    pub transaction_id: Uuid,
    pub relays: Vec<RelayOutcome>,
    pub sub: Option<SubOutcome>,
    pub journal: Vec<JournalRecord>,
}

impl DeployOutcome {
    pub fn subscription_url(
        &self,
        config: &Config,
        credentials: &CredentialManager,
    ) -> Result<Option<String>> {
        let Some(sub) = &self.sub else {
            return Ok(None);
        };
        config
            .deployments
            .iter()
            .find(|deployment| deployment.id == sub.deployment_id)
            .context("sub deployment is missing from committed config")?
            .subscription_url(credentials)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JournalRecord {
    pub resource: String,
    pub disposition: ResourceDisposition,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceDisposition {
    PreExisting,
    Created,
    Updated,
    Compensated,
    Retained,
}

#[derive(Debug)]
enum Compensation {
    Credential {
        reference: String,
    },
    CredentialRestore {
        reference: String,
        previous: SecretValue,
    },
    Kv {
        account_id: String,
        namespace_id: String,
    },
    Worker {
        account_id: String,
        script: String,
        ownership: crate::cfapi::WorkerOwnership,
    },
    Deployment {
        account_id: String,
        script: String,
        previous_version_id: Option<String>,
    },
    WorkersDev {
        account_id: String,
        script: String,
        previous: bool,
    },
    CronSchedules {
        account_id: String,
        script: String,
        previous: Vec<String>,
    },
    Domain {
        account_id: String,
        domain_id: String,
    },
}

struct Transaction {
    id: Uuid,
    records: Vec<JournalRecord>,
    compensations: Vec<Compensation>,
}

impl Transaction {
    fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            records: Vec::new(),
            compensations: Vec::new(),
        }
    }

    fn record(
        &mut self,
        resource: impl Into<String>,
        disposition: ResourceDisposition,
        detail: impl Into<String>,
        compensation: Option<Compensation>,
    ) {
        self.records.push(JournalRecord {
            resource: resource.into(),
            disposition,
            detail: detail.into(),
        });
        if let Some(compensation) = compensation {
            self.compensations.push(compensation);
        }
    }

    async fn compensate(
        &mut self,
        clients: &HashMap<String, CfClient>,
        credentials: &CredentialManager,
        log: &mut (dyn FnMut(LogLine) + Send),
    ) -> Vec<String> {
        let mut failures = Vec::new();
        while let Some(action) = self.compensations.pop() {
            let (resource, result) = match action {
                Compensation::Credential { reference } => {
                    let result = credentials.delete(&reference);
                    (format!("credential {reference}"), result)
                }
                Compensation::CredentialRestore {
                    reference,
                    previous,
                } => {
                    let result = credentials.store_verified(&reference, previous.expose());
                    (format!("credential {reference}"), result)
                }
                Compensation::Kv {
                    account_id,
                    namespace_id,
                } => {
                    let result = clients[&account_id]
                        .delete_kv_namespace(&account_id, &namespace_id)
                        .await;
                    (format!("KV namespace {namespace_id}"), result)
                }
                Compensation::Worker {
                    account_id,
                    script,
                    ownership,
                } => {
                    let result = clients[&account_id]
                        .delete_managed_worker(&account_id, &script, ownership)
                        .await;
                    (format!("Worker {script}"), result)
                }
                Compensation::Deployment {
                    account_id,
                    script,
                    previous_version_id,
                } => {
                    let result = match previous_version_id {
                        Some(version) => clients[&account_id]
                            .create_deployment(
                                &account_id,
                                &script,
                                &version,
                                "Veilweave automatic rollback",
                            )
                            .await
                            .map(|_| ()),
                        None => Ok(()),
                    };
                    (format!("deployment for {script}"), result)
                }
                Compensation::WorkersDev {
                    account_id,
                    script,
                    previous,
                } => {
                    let result = clients[&account_id]
                        .set_workers_dev(&account_id, &script, previous)
                        .await;
                    (format!("workers.dev state for {script}"), result)
                }
                Compensation::CronSchedules {
                    account_id,
                    script,
                    previous,
                } => {
                    let result = clients[&account_id]
                        .set_cron_schedules(&account_id, &script, &previous)
                        .await
                        .map(|_| ());
                    (format!("Cron Triggers for {script}"), result)
                }
                Compensation::Domain {
                    account_id,
                    domain_id,
                } => {
                    let result = clients[&account_id]
                        .detach_domain(&account_id, &domain_id)
                        .await;
                    (format!("Custom Domain {domain_id}"), result)
                }
            };
            match result {
                Ok(()) => {
                    log(LogLine::new(
                        LogKind::Info,
                        DeployStage::RollingBack,
                        format!("compensated {resource}"),
                    ));
                    self.records.push(JournalRecord {
                        resource,
                        disposition: ResourceDisposition::Compensated,
                        detail: "rolled back after failed transaction".into(),
                    });
                }
                Err(error) => {
                    let detail = format!("could not compensate {resource}: {error:#}");
                    failures.push(detail.clone());
                    self.records.push(JournalRecord {
                        resource,
                        disposition: ResourceDisposition::Retained,
                        detail,
                    });
                }
            }
        }
        failures
    }
}

impl fmt::Debug for Transaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Transaction")
            .field("id", &self.id)
            .field("records", &self.records)
            .field("pending_compensations", &self.compensations.len())
            .finish()
    }
}

struct PreparedRelay {
    outcome: RelayOutcome,
    deployment: Deployment,
    node_secret: SecretValue,
}

pub async fn execute(
    plan: &DeployPlan,
    source: &BundleSource,
    config: &mut Config,
    log: &mut (dyn FnMut(LogLine) + Send),
) -> Result<DeployOutcome> {
    let credentials = CredentialManager::system();
    let network = NetworkManager::new(config.network.clone(), credentials.clone())?;
    execute_with(plan, source, config, &credentials, network, true, log).await
}

pub async fn execute_with(
    plan: &DeployPlan,
    source: &BundleSource,
    config: &mut Config,
    credentials: &CredentialManager,
    network: NetworkManager,
    persist: bool,
    log: &mut (dyn FnMut(LogLine) + Send),
) -> Result<DeployOutcome> {
    log(LogLine::new(
        LogKind::Step,
        DeployStage::Preflight,
        "validating topology, credentials, bundles, and remote ownership",
    ));
    validate_plan(plan)?;
    let relay_bundle = source.worker_bundle(WorkerRole::Relay)?;
    let sub_bundle = source.worker_bundle(WorkerRole::Sub)?;

    let accounts = resolve_plan_accounts(config, plan)?;
    let mut clients = HashMap::new();
    for account in accounts.values() {
        let token = credentials
            .resolve(&account.credential_ref)
            .with_context(|| format!("resolve API token for account {:?}", account.name))?;
        let client = CfClient::with_network(token.expose(), network.clone())?;
        client.verify_token().await?;
        clients.insert(account.account_id.clone(), client);
    }
    preflight_ownership(plan, config, &accounts, &clients).await?;

    let original_deployments = config.deployments.clone();
    let mut pending_deployments = original_deployments.clone();
    let mut transaction = Transaction::new();
    let mut relay_outcomes = Vec::new();
    let mut prepared_relays = Vec::new();

    let attempt: Result<SubOutcome> = async {
        for relay in &plan.relays {
            let account = &accounts[&relay.account];
            let prepared = apply_relay(
                relay,
                plan.encryption,
                account,
                &clients[&account.account_id],
                &relay_bundle,
                &original_deployments,
                credentials,
                &mut transaction,
                network.clone(),
                log,
            )
            .await?;
            upsert_deployment(&mut pending_deployments, prepared.deployment.clone());
            relay_outcomes.push(prepared.outcome.clone());
            prepared_relays.push(prepared);
        }
        let account = &accounts[&plan.sub.account];
        let prepared_sub = apply_sub(
            &plan.sub,
            account,
            &clients[&account.account_id],
            &sub_bundle,
            &prepared_relays,
            &original_deployments,
            credentials,
            &mut transaction,
            network,
            log,
        )
        .await?;
        upsert_deployment(&mut pending_deployments, prepared_sub.1);
        Ok(prepared_sub.0)
    }
    .await;

    let sub_outcome = match attempt {
        Ok(outcome) => outcome,
        Err(error) => {
            log(LogLine::new(
                LogKind::Error,
                DeployStage::RollingBack,
                format!("transaction {} failed: {error:#}", transaction.id),
            ));
            let failures = transaction.compensate(&clients, credentials, log).await;
            let retained = if failures.is_empty() {
                "all resources created by this transaction were compensated".to_string()
            } else {
                format!("manual cleanup required: {}", failures.join("; "))
            };
            return Err(error).context(format!(
                "deployment transaction {} failed; {retained}",
                transaction.id
            ));
        }
    };

    config.deployments = pending_deployments;
    log(LogLine::new(
        LogKind::Step,
        DeployStage::Persisting,
        "committing redacted local state",
    ));
    if persist {
        if let Err(error) = config.save() {
            for record in &mut transaction.records {
                if matches!(
                    record.disposition,
                    ResourceDisposition::Created | ResourceDisposition::Updated
                ) {
                    record.disposition = ResourceDisposition::Retained;
                }
            }
            return Err(error).context(format!(
                "remote transaction {} succeeded but local metadata could not be saved; remote resources were intentionally retained and can be recovered by ownership markers",
                transaction.id
            ));
        }
    }
    log(LogLine::new(
        LogKind::Info,
        DeployStage::Complete,
        format!("transaction {} complete", transaction.id),
    ));
    Ok(DeployOutcome {
        transaction_id: transaction.id,
        relays: relay_outcomes,
        sub: Some(sub_outcome),
        journal: transaction.records,
    })
}

#[allow(clippy::too_many_arguments)]
async fn apply_relay(
    spec: &RelaySpec,
    encryption: bool,
    account: &Account,
    client: &CfClient,
    bundle: &WorkerBundle,
    existing_deployments: &[Deployment],
    credentials: &CredentialManager,
    transaction: &mut Transaction,
    network: NetworkManager,
    log: &mut (dyn FnMut(LogLine) + Send),
) -> Result<PreparedRelay> {
    let existing = find_deployment(
        existing_deployments,
        &account.account_id,
        &spec.worker_name,
        Role::Relay,
    )
    .cloned();
    let is_update = existing.is_some();
    let id = existing
        .as_ref()
        .map_or_else(Uuid::new_v4, |value| value.id);

    let (secret_ref, node_secret_ref, relay_secret, node_secret) = if let Some(existing) = &existing
    {
        let node_reference = existing.node_secret_ref.as_ref().context(
                "relay node secret is unavailable locally; re-link or rotate topology secrets before update",
            )?;
        (
            existing.secret_ref.clone(),
            node_reference.clone(),
            None,
            credentials.resolve(node_reference)?,
        )
    } else {
        log(LogLine::new(
            LogKind::Step,
            DeployStage::Preparing,
            format!(
                "relay {}: generating and securing credentials",
                spec.worker_name
            ),
        ));
        let (worker_value, node_value) = if encryption {
            crate::util::gen_secret_pair()
        } else {
            let value = crate::util::gen_raw_secret();
            (value.clone(), value)
        };
        let worker_reference =
            CredentialManager::keyring_reference(&format!("deployment/{id}/worker-secret"));
        let node_reference =
            CredentialManager::keyring_reference(&format!("deployment/{id}/node-secret"));
        credentials.store_verified(&worker_reference, &worker_value)?;
        transaction.record(
            "relay Worker credential",
            ResourceDisposition::Created,
            format!("secure reference for deployment {id}"),
            Some(Compensation::Credential {
                reference: worker_reference.clone(),
            }),
        );
        credentials.store_verified(&node_reference, &node_value)?;
        transaction.record(
            "relay node credential",
            ResourceDisposition::Created,
            format!("secure reference for deployment {id}"),
            Some(Compensation::Credential {
                reference: node_reference.clone(),
            }),
        );
        (
            worker_reference,
            node_reference,
            Some(SecretValue::new(worker_value)),
            SecretValue::new(node_value),
        )
    };

    let previous = if is_update {
        current_stable(client, &account.account_id, &spec.worker_name).await?
    } else {
        None
    };
    let metadata = cfapi::relay_metadata_for(
        if is_update {
            VersionKind::Update
        } else {
            VersionKind::Initial
        },
        relay_secret.as_ref().map(SecretValue::expose),
        &bundle.manifest().bundle_sha256,
    )?;
    let version = if is_update {
        log(LogLine::new(
            LogKind::Step,
            DeployStage::UploadingVersion,
            format!("relay {}: uploading inert Worker version", spec.worker_name),
        ));
        client
            .upload_version(&account.account_id, &spec.worker_name, bundle, metadata)
            .await?
    } else {
        log(LogLine::new(
            LogKind::Step,
            DeployStage::UploadingVersion,
            format!(
                "relay {}: creating Worker and uploading initial version",
                spec.worker_name
            ),
        ));
        client
            .create_worker_initial(&account.account_id, &spec.worker_name, bundle, metadata)
            .await?
    };
    if !is_update {
        transaction.record(
            format!("Worker {}", spec.worker_name),
            ResourceDisposition::Created,
            format!("version {} created", version.id),
            Some(Compensation::Worker {
                account_id: account.account_id.clone(),
                script: spec.worker_name.clone(),
                ownership: crate::cfapi::WorkerOwnership::VeilweaveRelay,
            }),
        );
    } else {
        transaction.record(
            format!("Worker version {}", version.id),
            ResourceDisposition::Created,
            "inert version retained if promotion is never attempted",
            None,
        );
    }

    log(LogLine::new(
        LogKind::Step,
        DeployStage::Deploying,
        format!(
            "relay {}: promoting version {}",
            spec.worker_name, version.id
        ),
    ));
    let promoted = client
        .create_deployment(
            &account.account_id,
            &spec.worker_name,
            &version.id,
            "Veilweave v2 relay deployment",
        )
        .await?;
    transaction.record(
        format!("deployment {}", promoted.id),
        if is_update {
            ResourceDisposition::Updated
        } else {
            ResourceDisposition::Created
        },
        format!("100% of traffic promoted to version {}", version.id),
        Some(Compensation::Deployment {
            account_id: account.account_id.clone(),
            script: spec.worker_name.clone(),
            previous_version_id: previous.as_ref().map(|state| state.0.clone()),
        }),
    );
    let endpoint = apply_endpoint(
        client,
        account,
        &spec.worker_name,
        &spec.endpoint,
        transaction,
        log,
    )
    .await?;
    verify_endpoint(
        &network,
        endpoint
            .primary_hostname()
            .context("relay has no primary endpoint")?,
        EndpointRole::Relay,
        endpoint.primary == PrimaryEndpoint::CustomDomain
            && endpoint
                .custom_domains
                .iter()
                .any(|domain| domain.status == DomainStatus::Provisioning),
        log,
    )
    .await?;

    let now = crate::config::now_utc_string();
    let deployment = Deployment {
        id,
        role: Role::Relay,
        name: spec.worker_name.clone(),
        account_id: account.account_id.clone(),
        secret_ref,
        node_secret_ref: Some(node_secret_ref),
        endpoint,
        created_at: existing
            .as_ref()
            .map_or_else(|| now.clone(), |value| value.created_at.clone()),
        updated_at: Some(now),
        stable_version_id: Some(version.id.clone()),
        stable_deployment_id: Some(promoted.id.clone()),
        previous_version_id: previous.as_ref().map(|state| state.0.clone()),
        previous_deployment_id: previous.as_ref().map(|state| state.1.clone()),
        bundle_hash: Some(bundle.manifest().bundle_sha256.clone()),
        sub: None,
    };
    Ok(PreparedRelay {
        outcome: RelayOutcome {
            deployment_id: id,
            name: spec.worker_name.clone(),
            domain: deployment
                .primary_domain()
                .context("relay primary hostname missing")?
                .to_string(),
            version_id: version.id,
            cloudflare_deployment_id: promoted.id,
        },
        deployment,
        node_secret,
    })
}

#[allow(clippy::too_many_arguments)]
async fn apply_sub(
    spec: &SubSpec,
    account: &Account,
    client: &CfClient,
    bundle: &WorkerBundle,
    relays: &[PreparedRelay],
    existing_deployments: &[Deployment],
    credentials: &CredentialManager,
    transaction: &mut Transaction,
    network: NetworkManager,
    log: &mut (dyn FnMut(LogLine) + Send),
) -> Result<(SubOutcome, Deployment)> {
    let existing = find_deployment(
        existing_deployments,
        &account.account_id,
        &spec.worker_name,
        Role::Sub,
    )
    .cloned();
    let is_update = existing.is_some();
    let id = existing
        .as_ref()
        .map_or_else(Uuid::new_v4, |value| value.id);

    let kv_namespace_id = if let Some(existing) = &existing {
        existing
            .sub
            .as_ref()
            .context("existing sub deployment has no KV metadata")?
            .kv_namespace_id
            .clone()
    } else if let Some(namespace) = client
        .find_kv_namespace(&account.account_id, &spec.kv_title)
        .await?
    {
        transaction.record(
            format!("KV namespace {}", namespace.id),
            ResourceDisposition::PreExisting,
            format!("reusing exact title {:?}", namespace.title),
            None,
        );
        namespace.id
    } else {
        log(LogLine::new(
            LogKind::Step,
            DeployStage::Preparing,
            format!("sub {}: creating KV namespace", spec.worker_name),
        ));
        let namespace_id = client
            .create_kv_namespace(&account.account_id, &spec.kv_title)
            .await?;
        transaction.record(
            format!("KV namespace {namespace_id}"),
            ResourceDisposition::Created,
            format!("title {:?}", spec.kv_title),
            Some(Compensation::Kv {
                account_id: account.account_id.clone(),
                namespace_id: namespace_id.clone(),
            }),
        );
        namespace_id
    };

    let nodes_value = build_nodes_value(
        &relays
            .iter()
            .map(|relay| {
                (
                    relay.outcome.domain.clone(),
                    relay.node_secret.expose().to_string(),
                )
            })
            .collect::<Vec<_>>(),
    );
    let nodes = SecretValue::new(nodes_value);
    let (secret_ref, token_ref, token, previous_nodes) = if let Some(existing) = &existing {
        let sub = existing
            .sub
            .as_ref()
            .context("existing sub deployment has no sub settings")?;
        let target_reference = if existing.secret_ref.starts_with("keyring:") {
            existing.secret_ref.clone()
        } else {
            CredentialManager::keyring_reference(&format!("deployment/{id}/worker-secret"))
        };
        let previous = if target_reference == existing.secret_ref {
            Some(credentials.resolve(&existing.secret_ref)?)
        } else {
            None
        };
        (
            target_reference,
            sub.subscription_token_ref.clone(),
            credentials.resolve(&sub.subscription_token_ref)?,
            previous,
        )
    } else {
        let token_value = crate::util::generate_hex_id(32);
        let nodes_reference =
            CredentialManager::keyring_reference(&format!("deployment/{id}/worker-secret"));
        let token_reference =
            CredentialManager::keyring_reference(&format!("deployment/{id}/subscription-token"));
        credentials.store_verified(&nodes_reference, nodes.expose())?;
        transaction.record(
            "sub node topology credential",
            ResourceDisposition::Created,
            format!("secure reference for deployment {id}"),
            Some(Compensation::Credential {
                reference: nodes_reference.clone(),
            }),
        );
        credentials.store_verified(&token_reference, &token_value)?;
        transaction.record(
            "subscription credential",
            ResourceDisposition::Created,
            format!("secure reference for deployment {id}"),
            Some(Compensation::Credential {
                reference: token_reference.clone(),
            }),
        );
        (
            nodes_reference,
            token_reference,
            SecretValue::new(token_value),
            None,
        )
    };

    let previous = if is_update {
        current_stable(client, &account.account_id, &spec.worker_name).await?
    } else {
        None
    };
    let metadata = cfapi::sub_metadata_for(
        if is_update {
            VersionKind::Update
        } else {
            VersionKind::Initial
        },
        Some(nodes.expose()),
        if is_update {
            None
        } else {
            Some(token.expose())
        },
        &spec.kv_binding,
        &kv_namespace_id,
        &spec.settings,
        &bundle.manifest().bundle_sha256,
    )?;
    let version = if is_update {
        log(LogLine::new(
            LogKind::Step,
            DeployStage::UploadingVersion,
            format!("sub {}: uploading inert Worker version", spec.worker_name),
        ));
        client
            .upload_version(&account.account_id, &spec.worker_name, bundle, metadata)
            .await?
    } else {
        log(LogLine::new(
            LogKind::Step,
            DeployStage::UploadingVersion,
            format!(
                "sub {}: creating Worker and uploading initial version",
                spec.worker_name
            ),
        ));
        client
            .create_worker_initial(&account.account_id, &spec.worker_name, bundle, metadata)
            .await?
    };
    if !is_update {
        transaction.record(
            format!("Worker {}", spec.worker_name),
            ResourceDisposition::Created,
            format!("version {} created", version.id),
            Some(Compensation::Worker {
                account_id: account.account_id.clone(),
                script: spec.worker_name.clone(),
                ownership: crate::cfapi::WorkerOwnership::VeilweaveSub,
            }),
        );
    } else {
        transaction.record(
            format!("Worker version {}", version.id),
            ResourceDisposition::Created,
            "inert version retained if promotion is never attempted",
            None,
        );
    }
    log(LogLine::new(
        LogKind::Step,
        DeployStage::Deploying,
        format!("sub {}: promoting version {}", spec.worker_name, version.id),
    ));
    let promoted = client
        .create_deployment(
            &account.account_id,
            &spec.worker_name,
            &version.id,
            "Veilweave v2 subscription deployment",
        )
        .await?;
    transaction.record(
        format!("deployment {}", promoted.id),
        if is_update {
            ResourceDisposition::Updated
        } else {
            ResourceDisposition::Created
        },
        format!("100% of traffic promoted to version {}", version.id),
        Some(Compensation::Deployment {
            account_id: account.account_id.clone(),
            script: spec.worker_name.clone(),
            previous_version_id: previous.as_ref().map(|state| state.0.clone()),
        }),
    );
    let previous_schedules = client
        .get_cron_schedules(&account.account_id, &spec.worker_name)
        .await?;
    let refresh_schedules = vec![PROXYIP_REFRESH_CRON.to_string()];
    if previous_schedules != refresh_schedules {
        client
            .set_cron_schedules(&account.account_id, &spec.worker_name, &refresh_schedules)
            .await?;
        transaction.record(
            format!("Cron Triggers for {}", spec.worker_name),
            ResourceDisposition::Updated,
            format!("automatic proxyIP refresh: {PROXYIP_REFRESH_CRON}"),
            Some(Compensation::CronSchedules {
                account_id: account.account_id.clone(),
                script: spec.worker_name.clone(),
                previous: previous_schedules,
            }),
        );
    }
    let endpoint = apply_endpoint(
        client,
        account,
        &spec.worker_name,
        &spec.endpoint,
        transaction,
        log,
    )
    .await?;
    verify_endpoint(
        &network,
        endpoint
            .primary_hostname()
            .context("sub has no primary endpoint")?,
        EndpointRole::Subscription {
            token: token.expose(),
        },
        endpoint.primary == PrimaryEndpoint::CustomDomain
            && endpoint
                .custom_domains
                .iter()
                .any(|domain| domain.status == DomainStatus::Provisioning),
        log,
    )
    .await?;

    if is_update {
        credentials.store_verified(&secret_ref, nodes.expose())?;
        transaction.record(
            "sub node topology credential",
            ResourceDisposition::Updated,
            format!("rotated secure relay topology for deployment {id}"),
            Some(match previous_nodes {
                Some(previous) => Compensation::CredentialRestore {
                    reference: secret_ref.clone(),
                    previous,
                },
                None => Compensation::Credential {
                    reference: secret_ref.clone(),
                },
            }),
        );
    }

    let now = crate::config::now_utc_string();
    let deployment = Deployment {
        id,
        role: Role::Sub,
        name: spec.worker_name.clone(),
        account_id: account.account_id.clone(),
        secret_ref,
        node_secret_ref: None,
        endpoint,
        created_at: existing
            .as_ref()
            .map_or_else(|| now.clone(), |value| value.created_at.clone()),
        updated_at: Some(now),
        stable_version_id: Some(version.id.clone()),
        stable_deployment_id: Some(promoted.id.clone()),
        previous_version_id: previous.as_ref().map(|state| state.0.clone()),
        previous_deployment_id: previous.as_ref().map(|state| state.1.clone()),
        bundle_hash: Some(bundle.manifest().bundle_sha256.clone()),
        sub: Some(SubDetails {
            kv_namespace_id: kv_namespace_id.clone(),
            kv_title: spec.kv_title.clone(),
            kv_binding: spec.kv_binding.clone(),
            subscription_token_ref: token_ref,
            max_nodes: spec.settings.max_nodes,
            fingerprint: spec.settings.fingerprint.clone(),
            ech: spec.settings.ech.clone(),
        }),
    };
    Ok((
        SubOutcome {
            deployment_id: id,
            name: spec.worker_name.clone(),
            domain: deployment
                .primary_domain()
                .context("sub primary hostname missing")?
                .to_string(),
            kv_namespace_id,
            version_id: version.id,
            cloudflare_deployment_id: promoted.id,
        },
        deployment,
    ))
}

async fn apply_endpoint(
    client: &CfClient,
    account: &Account,
    script: &str,
    spec: &EndpointSpec,
    transaction: &mut Transaction,
    log: &mut (dyn FnMut(LogLine) + Send),
) -> Result<EndpointConfig> {
    let workers_dev_enabled = spec.workers_dev_enabled();
    let previous_workers_dev = client
        .get_workers_dev_state(&account.account_id, script)
        .await
        .map(|state| state.enabled)
        .unwrap_or(false);
    if previous_workers_dev != workers_dev_enabled {
        client
            .set_workers_dev(&account.account_id, script, workers_dev_enabled)
            .await?;
        transaction.record(
            format!("workers.dev for {script}"),
            ResourceDisposition::Updated,
            format!("enabled={workers_dev_enabled}"),
            Some(Compensation::WorkersDev {
                account_id: account.account_id.clone(),
                script: script.to_string(),
                previous: previous_workers_dev,
            }),
        );
    } else {
        transaction.record(
            format!("workers.dev for {script}"),
            ResourceDisposition::PreExisting,
            format!("enabled={workers_dev_enabled}"),
            None,
        );
    }
    let workers_dev_hostname = if workers_dev_enabled {
        let subdomain = match &account.workers_dev_subdomain {
            Some(value) => value.clone(),
            None => client.get_workers_subdomain(&account.account_id).await?,
        };
        Some(format!("{script}.{subdomain}.workers.dev"))
    } else {
        None
    };

    let mut custom_domains = Vec::new();
    if let Some(domain) = &spec.custom_domain {
        log(LogLine::new(
            LogKind::Step,
            DeployStage::BindingDomain,
            format!("{script}: validating Custom Domain {}", domain.hostname),
        ));
        let hostname = crate::config::validate_hostname(&domain.hostname)?;
        match client.list_zones(&account.account_id).await {
            Ok(zones) => {
                if !zones.iter().any(|zone| {
                    zone.id == domain.zone_id && zone.name.eq_ignore_ascii_case(&domain.zone_name)
                }) {
                    bail!(
                        "zone ID/name does not belong to selected Cloudflare account or is not active"
                    );
                }
            }
            Err(error) => log(LogLine::new(
                LogKind::Warn,
                DeployStage::BindingDomain,
                format!("Zone Read unavailable; attach API will validate ownership: {error:#}"),
            )),
        }
        let domains = client.list_domains(&account.account_id).await?;
        let existing = domains
            .iter()
            .find(|existing| existing.hostname.eq_ignore_ascii_case(&hostname));
        let remote = if let Some(existing) = existing {
            if existing.service != script {
                bail!(
                    "Custom Domain {hostname:?} is already attached to unrelated Worker {:?}",
                    existing.service
                );
            }
            transaction.record(
                format!("Custom Domain {hostname}"),
                ResourceDisposition::PreExisting,
                format!("already attached to {script}"),
                None,
            );
            existing.clone()
        } else {
            match client.list_dns_records(&domain.zone_id, &hostname).await {
                Ok(records) if !records.is_empty() => bail!(
                    "DNS record conflict for {hostname:?}: {} existing record(s); remove the conflict before attaching a Worker Custom Domain",
                    records.len()
                ),
                Ok(_) => {}
                Err(error) => log(LogLine::new(
                    LogKind::Warn,
                    DeployStage::BindingDomain,
                    format!("DNS Read unavailable; Domains API will validate conflicts: {error:#}"),
                )),
            }
            let attached = client
                .attach_domain(
                    &account.account_id,
                    &AttachDomainRequest {
                        hostname: hostname.clone(),
                        service: script.to_string(),
                        zone_id: Some(domain.zone_id.clone()),
                        zone_name: Some(domain.zone_name.clone()),
                    },
                )
                .await?;
            transaction.record(
                format!("Custom Domain {hostname}"),
                ResourceDisposition::Created,
                format!("attached to {script}; certificate may still be provisioning"),
                Some(Compensation::Domain {
                    account_id: account.account_id.clone(),
                    domain_id: attached.id.clone(),
                }),
            );
            attached
        };
        custom_domains.push(domain_binding(remote, domain, spec.primary));
    }
    let endpoint = EndpointConfig {
        mode: spec.mode,
        primary: spec.primary,
        workers_dev_enabled,
        workers_dev_hostname,
        custom_domains,
    };
    endpoint.validate()?;
    Ok(endpoint)
}

fn domain_binding(
    remote: WorkerDomain,
    requested: &CustomDomainSpec,
    primary: PrimaryEndpoint,
) -> DomainBinding {
    let status = match remote.status.as_deref() {
        Some("active" | "ready") => DomainStatus::Ready,
        Some("error" | "failed") => DomainStatus::Error,
        Some(_) | None => DomainStatus::Provisioning,
    };
    DomainBinding {
        domain_id: remote.id,
        hostname: remote.hostname,
        zone_id: remote.zone_id.unwrap_or_else(|| requested.zone_id.clone()),
        zone_name: remote
            .zone_name
            .unwrap_or_else(|| requested.zone_name.clone()),
        service: remote.service,
        primary: primary == PrimaryEndpoint::CustomDomain,
        status,
    }
}

/// Maximum time to wait for Custom Domain TLS provisioning.
const CUSTOM_DOMAIN_TIMEOUT: Duration = Duration::from_secs(180);

/// Interval between policy-aware HTTPS checks during provisioning.
const CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// A newly enabled workers.dev route can briefly return Cloudflare's 404 even
/// after the deployment API has promoted the Worker version.
#[cfg(not(test))]
const WORKERS_DEV_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(test)]
const WORKERS_DEV_TIMEOUT: Duration = Duration::from_millis(50);
#[cfg(not(test))]
const WORKERS_DEV_CHECK_INTERVAL: Duration = Duration::from_secs(2);
#[cfg(test)]
const WORKERS_DEV_CHECK_INTERVAL: Duration = Duration::from_millis(5);

const MAX_MANAGEMENT_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_RELAY_READINESS_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy)]
enum EndpointRole<'a> {
    Relay,
    Subscription { token: &'a str },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyIpCacheStatus {
    pub source: String,
    pub validation: String,
    pub revision: Option<String>,
    pub last_success_ms: Option<u64>,
    pub age_ms: Option<u64>,
    pub stale: bool,
    pub accepted_count: Option<usize>,
    pub rejected_count: Option<usize>,
    pub stored_count: Option<usize>,
    pub country_count: Option<usize>,
    pub last_failure: Option<ProxyIpRefreshFailure>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyIpRefreshFailure {
    pub at_ms: u64,
    pub code: String,
    pub message: String,
}

impl ProxyIpCacheStatus {
    fn is_usable(&self) -> bool {
        self.source == "https://zip.cm.edu.kg/all.json"
            && self.validation == "valid"
            && self
                .revision
                .as_deref()
                .is_some_and(|revision| !revision.is_empty())
            && self.accepted_count.is_some_and(|count| count > 0)
            && self.stored_count.is_some_and(|count| count > 0)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyIpRefreshReport {
    pub source: String,
    pub revision: String,
    pub accepted_count: usize,
    pub rejected_count: usize,
    pub stored_count: usize,
    pub country_count: usize,
}

async fn verify_endpoint(
    network: &NetworkManager,
    hostname: &str,
    role: EndpointRole<'_>,
    certificate_provisioning: bool,
    log: &mut (dyn FnMut(LogLine) + Send),
) -> Result<()> {
    log(LogLine::new(
        LogKind::Step,
        DeployStage::Verifying,
        format!("verifying https://{hostname}"),
    ));

    // DNS sockets would bypass explicit SOCKS/HTTP proxy policy. Poll HTTPS
    // through the configured transport instead; both Custom Domains and newly
    // enabled workers.dev routes can lag behind a successful deployment API
    // response and briefly return Cloudflare's generic 404.
    let (timeout, interval, readiness_kind) = if certificate_provisioning {
        (CUSTOM_DOMAIN_TIMEOUT, CHECK_INTERVAL, "DNS/TLS/Worker")
    } else {
        (
            WORKERS_DEV_TIMEOUT,
            WORKERS_DEV_CHECK_INTERVAL,
            "workers.dev routing/Worker",
        )
    };
    poll_endpoint_readiness(hostname, timeout, interval, readiness_kind, log, || {
        probe_endpoint(network, hostname, role)
    })
    .await
    .with_context(|| format!("endpoint {hostname} failed role-aware readiness verification"))?;

    match role {
        EndpointRole::Relay => {
            log(LogLine::new(
                LogKind::Info,
                DeployStage::Verifying,
                format!(
                    "relay {hostname}: camouflage route is ready; VLESS transport requires the protected live E2E gate"
                ),
            ));
            Ok(())
        }
        EndpointRole::Subscription { token } => {
            ensure_proxyip_dataset(network, hostname, token, log).await?;
            verify_subscription_endpoint(network, hostname, token, log).await
        }
    }
}

async fn poll_endpoint_readiness<Probe, ProbeFuture>(
    hostname: &str,
    timeout: Duration,
    interval: Duration,
    readiness_kind: &str,
    log: &mut (dyn FnMut(LogLine) + Send),
    mut probe: Probe,
) -> Result<()>
where
    Probe: FnMut() -> ProbeFuture,
    ProbeFuture: std::future::Future<Output = Result<()>>,
{
    let started = Instant::now();
    let deadline = started + timeout;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match probe().await {
            Ok(()) => {
                if attempt > 1 {
                    log(LogLine::new(
                        LogKind::Info,
                        DeployStage::Verifying,
                        format!(
                            "endpoint {hostname} became ready after {}s (attempt {attempt})",
                            started.elapsed().as_secs()
                        ),
                    ));
                }
                return Ok(());
            }
            Err(error) if Instant::now() >= deadline => {
                return Err(error).with_context(|| {
                    format!(
                        "{hostname} did not become healthy within {} seconds ({readiness_kind})",
                        timeout.as_secs()
                    )
                });
            }
            Err(_) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                log(LogLine::new(
                    LogKind::Step,
                    DeployStage::WaitingForEndpoint,
                    format!(
                        "{hostname}: waiting for {readiness_kind} readiness ({}s remaining, attempt {attempt})",
                        remaining.as_secs()
                    ),
                ));
                tokio::time::sleep(interval.min(remaining)).await;
            }
        }
    }
}

async fn probe_endpoint(
    network: &NetworkManager,
    hostname: &str,
    role: EndpointRole<'_>,
) -> Result<()> {
    match role {
        EndpointRole::Relay => verify_relay_readiness(network, hostname).await,
        EndpointRole::Subscription { token } => {
            proxyip_status(network, hostname, token).await.map(|_| ())
        }
    }
}

async fn verify_relay_readiness(network: &NetworkManager, hostname: &str) -> Result<()> {
    let response = network
        .snapshot()
        .client()
        .get(format!("https://{hostname}/"))
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!("relay {hostname} is unreachable"))?;
    if response.status() != StatusCode::OK {
        bail!(
            "relay {hostname} returned HTTP {}; expected HTTP 200",
            response.status()
        );
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .context("relay readiness response is missing a valid Content-Type")?;
    if !content_type.to_ascii_lowercase().starts_with("text/html") {
        bail!("relay readiness response is not HTML");
    }
    let body = response
        .bytes()
        .await
        .map_err(reqwest::Error::without_url)
        .context("read relay readiness response")?;
    if body.len() > MAX_RELAY_READINESS_BYTES {
        bail!("relay readiness response is unexpectedly large");
    }
    let body = std::str::from_utf8(&body).context("relay readiness response is not UTF-8")?;
    if !body.contains("Apache2 Debian Default Page") {
        bail!("relay readiness response is not the expected Veilweave camouflage page");
    }
    Ok(())
}

async fn proxyip_status(
    network: &NetworkManager,
    hostname: &str,
    token: &str,
) -> Result<ProxyIpCacheStatus> {
    let response = network
        .snapshot()
        .client()
        .get(format!("https://{hostname}/_veilweave/proxyip/status"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!("subscription management endpoint {hostname} is unreachable"))?;
    parse_management_response(response, "proxyIP status").await
}

async fn ensure_proxyip_dataset(
    network: &NetworkManager,
    hostname: &str,
    token: &str,
    log: &mut (dyn FnMut(LogLine) + Send),
) -> Result<()> {
    let status = proxyip_status(network, hostname, token).await?;
    if status.source != "https://zip.cm.edu.kg/all.json" {
        bail!("subscription Worker reported an unexpected proxyIP source");
    }
    if status.is_usable() {
        log(LogLine::new(
            if status.stale {
                LogKind::Warn
            } else {
                LogKind::Info
            },
            DeployStage::Verifying,
            format!(
                "proxyIP cache ready: revision {}, {} stored endpoints{}",
                status.revision.as_deref().unwrap_or("unknown"),
                status.stored_count.unwrap_or(0),
                if status.stale {
                    " (stale known-good)"
                } else {
                    ""
                }
            ),
        ));
        return Ok(());
    }

    log(LogLine::new(
        LogKind::Step,
        DeployStage::Verifying,
        "proxyIP cache is empty; initializing it from zip.cm.edu.kg/all.json",
    ));
    let refreshed = refresh_proxyip_dataset(network, hostname, token).await?;
    log(LogLine::new(
        LogKind::Info,
        DeployStage::Verifying,
        format!(
            "proxyIP cache initialized: revision {}, {} stored endpoints",
            refreshed.revision, refreshed.stored_count
        ),
    ));
    Ok(())
}

async fn refresh_proxyip_dataset(
    network: &NetworkManager,
    hostname: &str,
    token: &str,
) -> Result<ProxyIpRefreshReport> {
    let response = network
        .snapshot()
        .client()
        .post(format!("https://{hostname}/_veilweave/proxyip/refresh"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!("proxyIP dataset refresh failed for {hostname}"))?;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let response_is_json = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.to_ascii_lowercase().starts_with("application/json"));
        let direct_failure = response
            .bytes()
            .await
            .ok()
            .and_then(|body| parse_proxyip_refresh_failure(response_is_json, &body));
        let failure = match direct_failure {
            Some(failure) => Some(failure),
            None => proxyip_status(network, hostname, token)
                .await
                .ok()
                .and_then(|status| status.last_failure),
        };
        bail!(
            "{}",
            proxyip_refresh_failure_message(status, failure.as_ref())
        );
    }
    let refreshed: ProxyIpRefreshReport =
        parse_management_response(response, "proxyIP refresh").await?;
    if refreshed.source != "https://zip.cm.edu.kg/all.json"
        || refreshed.revision.is_empty()
        || refreshed.accepted_count == 0
        || refreshed.stored_count == 0
        || refreshed.country_count == 0
    {
        bail!("proxyIP refresh returned an unusable dataset summary");
    }
    let confirmed = proxyip_status(network, hostname, token).await?;
    if !confirmed.is_usable() || confirmed.revision.as_deref() != Some(&refreshed.revision) {
        bail!("proxyIP refresh completed but the promoted known-good cache could not be verified");
    }
    Ok(refreshed)
}

fn parse_proxyip_refresh_failure(
    response_is_json: bool,
    body: &[u8],
) -> Option<ProxyIpRefreshFailure> {
    if !response_is_json || body.is_empty() || body.len() > MAX_MANAGEMENT_RESPONSE_BYTES {
        return None;
    }
    let failure = serde_json::from_slice::<ProxyIpRefreshFailure>(body).ok()?;
    if failure.code.is_empty() || failure.message.is_empty() {
        return None;
    }
    Some(failure)
}

fn proxyip_refresh_failure_message(
    status: StatusCode,
    failure: Option<&ProxyIpRefreshFailure>,
) -> String {
    match failure {
        Some(failure) => format!(
            "proxyIP refresh endpoint returned HTTP {status}; Worker diagnostic {}: {}",
            failure.code,
            failure.message.replace(['\r', '\n'], " ")
        ),
        None => format!(
            "proxyIP refresh endpoint returned HTTP {status}; no structured Worker diagnostic was recorded"
        ),
    }
}

async fn parse_management_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    operation: &str,
) -> Result<T> {
    if response.status() != StatusCode::OK {
        bail!(
            "{operation} endpoint returned HTTP {}; expected HTTP 200",
            response.status()
        );
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .context("management response is missing a valid Content-Type")?;
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/json")
    {
        bail!("{operation} endpoint did not return JSON");
    }
    let body = response
        .bytes()
        .await
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!("read {operation} response"))?;
    if body.is_empty() || body.len() > MAX_MANAGEMENT_RESPONSE_BYTES {
        bail!("{operation} response has an invalid size");
    }
    serde_json::from_slice(&body).with_context(|| format!("parse {operation} response"))
}

async fn verify_subscription_endpoint(
    network: &NetworkManager,
    hostname: &str,
    token: &str,
    log: &mut (dyn FnMut(LogLine) + Send),
) -> Result<()> {
    let response = network
        .snapshot()
        .client()
        .get(format!("https://{hostname}/sub"))
        .query(&[("token", token), ("format", "raw")])
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!("subscription endpoint {hostname} is unreachable"))?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .map_err(reqwest::Error::without_url)
        .context("read subscription verification response")?;
    let verified = subscription::verify_response(status, &headers, &body)
        .with_context(|| format!("subscription endpoint {hostname} is not usable"))?;
    log(LogLine::new(
        LogKind::Info,
        DeployStage::Verifying,
        format!(
            "subscription {hostname}: HTTP 200, {} structurally valid VLESS nodes",
            verified.node_count
        ),
    ));
    Ok(())
}

async fn preflight_ownership(
    plan: &DeployPlan,
    config: &Config,
    accounts: &HashMap<String, Account>,
    clients: &HashMap<String, CfClient>,
) -> Result<()> {
    let desired = plan
        .relays
        .iter()
        .map(|relay| (&relay.account, &relay.worker_name, Role::Relay))
        .chain(std::iter::once((
            &plan.sub.account,
            &plan.sub.worker_name,
            Role::Sub,
        )));
    let mut workers_by_account: HashMap<String, HashSet<String>> = HashMap::new();
    for (account_key, worker_name, role) in desired {
        let account = &accounts[account_key];
        if !workers_by_account.contains_key(&account.account_id) {
            let workers = clients[&account.account_id]
                .list_workers(&account.account_id)
                .await?
                .into_iter()
                .map(|worker| worker.id)
                .collect();
            workers_by_account.insert(account.account_id.clone(), workers);
        }
        let workers = &workers_by_account[&account.account_id];
        if !workers.contains(worker_name) {
            continue;
        }
        if find_deployment(&config.deployments, &account.account_id, worker_name, role).is_some() {
            continue;
        }
        let ownership = clients[&account.account_id]
            .worker_ownership(&account.account_id, worker_name)
            .await?;
        match (role, ownership) {
            (Role::Relay, WorkerOwnership::VeilweaveRelay)
            | (Role::Sub, WorkerOwnership::VeilweaveSub) => bail!(
                "Worker {worker_name:?} is Veilweave-managed but not linked locally; recover/adopt it before applying"
            ),
            _ => bail!(
                "refusing to overwrite existing Worker {worker_name:?}; it is not linked as this Veilweave deployment"
            ),
        }
    }
    Ok(())
}

fn validate_plan(plan: &DeployPlan) -> Result<()> {
    if plan.relays.is_empty() {
        bail!("deploy plan must contain at least one relay");
    }
    plan.sub.endpoint.validate()?;
    plan.sub.settings.validate()?;
    validate_worker_name(&plan.sub.worker_name)?;
    if plan.sub.kv_title.trim().is_empty() {
        bail!("sub KV namespace title cannot be empty");
    }
    let mut names = HashSet::new();
    names.insert((plan.sub.account.as_str(), plan.sub.worker_name.as_str()));
    for relay in &plan.relays {
        relay.endpoint.validate()?;
        validate_worker_name(&relay.worker_name)?;
        if !names.insert((relay.account.as_str(), relay.worker_name.as_str())) {
            bail!(
                "duplicate Worker name {:?} in one account",
                relay.worker_name
            );
        }
    }
    Ok(())
}

fn validate_worker_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 63
        && name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        && !name.starts_with('-')
        && !name.ends_with('-');
    if !valid {
        bail!("invalid Worker name {name:?}");
    }
    Ok(())
}

fn resolve_plan_accounts(config: &Config, plan: &DeployPlan) -> Result<HashMap<String, Account>> {
    let mut accounts = HashMap::new();
    for key in plan
        .relays
        .iter()
        .map(|relay| &relay.account)
        .chain(std::iter::once(&plan.sub.account))
    {
        if accounts.contains_key(key) {
            continue;
        }
        let account = config
            .account(key)
            .cloned()
            .with_context(|| format!("Cloudflare account {key:?} is not configured"))?;
        accounts.insert(key.clone(), account);
    }
    Ok(accounts)
}

fn find_deployment<'a>(
    deployments: &'a [Deployment],
    account_id: &str,
    worker_name: &str,
    role: Role,
) -> Option<&'a Deployment> {
    deployments.iter().find(|deployment| {
        deployment.account_id == account_id
            && deployment.name == worker_name
            && deployment.role == role
    })
}

fn upsert_deployment(deployments: &mut Vec<Deployment>, replacement: Deployment) {
    if let Some(existing) = deployments
        .iter_mut()
        .find(|deployment| deployment.id == replacement.id)
    {
        *existing = replacement;
    } else {
        deployments.push(replacement);
    }
}

async fn current_stable(
    client: &CfClient,
    account_id: &str,
    script: &str,
) -> Result<Option<(String, String)>> {
    let mut deployments = client.list_deployments(account_id, script).await?;
    deployments.sort_by(|left, right| right.created_on.cmp(&left.created_on));
    Ok(deployments.into_iter().find_map(|deployment| {
        deployment
            .versions
            .iter()
            .find(|version| version.percentage >= 99.999)
            .map(|version| (version.version_id.clone(), deployment.id.clone()))
    }))
}

pub async fn rollback(
    deployment_id: Uuid,
    config: &mut Config,
    credentials: &CredentialManager,
    network: NetworkManager,
    persist: bool,
) -> Result<String> {
    let index = config
        .deployments
        .iter()
        .position(|deployment| deployment.id == deployment_id)
        .context("deployment UUID not found")?;
    let deployment = config.deployments[index].clone();
    let previous = deployment
        .previous_version_id
        .clone()
        .context("no previous stable version is recorded")?;
    let account = config
        .account(&deployment.account_id)
        .cloned()
        .context("deployment account is missing")?;
    let token = credentials.resolve(&account.credential_ref)?;
    let client = CfClient::with_network(token.expose(), network)?;
    let promoted = client
        .create_deployment(
            &account.account_id,
            &deployment.name,
            &previous,
            "Veilweave explicit rollback",
        )
        .await?;
    let current_version = config.deployments[index]
        .stable_version_id
        .replace(previous);
    config.deployments[index].previous_version_id = current_version;
    let current_deployment = config.deployments[index]
        .stable_deployment_id
        .replace(promoted.id.clone());
    config.deployments[index].previous_deployment_id = current_deployment;
    config.deployments[index].updated_at = Some(crate::config::now_utc_string());
    if persist {
        config.save().context(
            "rollback succeeded remotely but local metadata save failed; recover remote deployment state",
        )?;
    }
    Ok(promoted.id)
}

/// Read the authenticated, non-secret proxyIP cache summary for a managed Sub.
pub async fn proxyip_cache_status(
    deployment_id: Uuid,
    config: &Config,
    credentials: &CredentialManager,
    network: NetworkManager,
) -> Result<ProxyIpCacheStatus> {
    let deployment = config
        .deployments
        .iter()
        .find(|deployment| deployment.id == deployment_id)
        .context("deployment UUID not found")?;
    if deployment.role != Role::Sub {
        bail!("proxyIP cache management is available only for a Sub Worker");
    }
    let sub = deployment
        .sub
        .as_ref()
        .context("sub deployment has no settings")?;
    let token = credentials.resolve(&sub.subscription_token_ref)?;
    let hostname = deployment
        .primary_domain()
        .context("Sub primary endpoint is missing")?;
    let status = proxyip_status(&network, hostname, token.expose()).await?;
    if status.source != "https://zip.cm.edu.kg/all.json" {
        bail!("subscription Worker reported an unexpected proxyIP source");
    }
    Ok(status)
}

/// Force one serialized refresh and verify the promoted KV generation.
pub async fn refresh_proxyip_cache(
    deployment_id: Uuid,
    config: &Config,
    credentials: &CredentialManager,
    network: NetworkManager,
) -> Result<ProxyIpRefreshReport> {
    let deployment = config
        .deployments
        .iter()
        .find(|deployment| deployment.id == deployment_id)
        .context("deployment UUID not found")?;
    if deployment.role != Role::Sub {
        bail!("proxyIP cache management is available only for a Sub Worker");
    }
    let sub = deployment
        .sub
        .as_ref()
        .context("sub deployment has no settings")?;
    let token = credentials.resolve(&sub.subscription_token_ref)?;
    let hostname = deployment
        .primary_domain()
        .context("Sub primary endpoint is missing")?;
    refresh_proxyip_dataset(&network, hostname, token.expose()).await
}

/// Code-only update for one managed Worker. Secrets are inherited by binding
/// name; this path never reads or regenerates Worker secret values.
pub async fn update_code(
    deployment_id: Uuid,
    source: &BundleSource,
    config: &mut Config,
    credentials: &CredentialManager,
    network: NetworkManager,
    persist: bool,
    log: &mut (dyn FnMut(LogLine) + Send),
) -> Result<String> {
    let index = config
        .deployments
        .iter()
        .position(|deployment| deployment.id == deployment_id)
        .context("deployment UUID not found")?;
    let existing = config.deployments[index].clone();
    let account = config
        .account(&existing.account_id)
        .cloned()
        .context("deployment account is missing")?;
    let token = credentials.resolve(&account.credential_ref)?;
    let client = CfClient::with_network(token.expose(), network.clone())?;
    let expected = match existing.role {
        Role::Relay => WorkerOwnership::VeilweaveRelay,
        Role::Sub => WorkerOwnership::VeilweaveSub,
    };
    let ownership = client
        .worker_ownership(&account.account_id, &existing.name)
        .await?;
    if ownership != expected {
        bail!(
            "refusing to update Worker {:?}: remote ownership marker does not match local role",
            existing.name
        );
    }
    let role = match existing.role {
        Role::Relay => WorkerRole::Relay,
        Role::Sub => WorkerRole::Sub,
    };
    let bundle = source.worker_bundle(role)?;
    let metadata = match existing.role {
        Role::Relay => {
            cfapi::relay_metadata_for(VersionKind::Update, None, &bundle.manifest().bundle_sha256)?
        }
        Role::Sub => {
            let sub = existing
                .sub
                .as_ref()
                .context("sub deployment has no settings")?;
            cfapi::sub_metadata_for(
                VersionKind::Update,
                None,
                None,
                &sub.kv_binding,
                &sub.kv_namespace_id,
                &SubSettings {
                    max_nodes: sub.max_nodes,
                    fingerprint: sub.fingerprint.clone(),
                    ech: sub.ech.clone(),
                },
                &bundle.manifest().bundle_sha256,
            )?
        }
    };
    let previous = current_stable(&client, &account.account_id, &existing.name)
        .await?
        .or_else(|| {
            existing
                .stable_version_id
                .clone()
                .zip(existing.stable_deployment_id.clone())
        })
        .context("no current stable deployment is available for safe rollback")?;
    let previous_schedules = if existing.role == Role::Sub {
        Some(
            client
                .get_cron_schedules(&account.account_id, &existing.name)
                .await?,
        )
    } else {
        None
    };
    log(LogLine::new(
        LogKind::Step,
        DeployStage::UploadingVersion,
        format!("{}: uploading code-only version", existing.name),
    ));
    let version = client
        .upload_version(&account.account_id, &existing.name, &bundle, metadata)
        .await?;
    log(LogLine::new(
        LogKind::Step,
        DeployStage::Deploying,
        format!("{}: promoting version {}", existing.name, version.id),
    ));
    let promoted = client
        .create_deployment(
            &account.account_id,
            &existing.name,
            &version.id,
            "Veilweave v2 code-only update",
        )
        .await?;
    let schedule_changed = previous_schedules
        .as_ref()
        .is_some_and(|schedules| schedules.as_slice() != [PROXYIP_REFRESH_CRON]);
    if schedule_changed {
        if let Err(schedule_error) = client
            .set_cron_schedules(
                &account.account_id,
                &existing.name,
                &[PROXYIP_REFRESH_CRON.to_string()],
            )
            .await
        {
            client
                .create_deployment(
                    &account.account_id,
                    &existing.name,
                    &previous.0,
                    "Veilweave rollback after Cron Trigger update failure",
                )
                .await
                .context("Cron Trigger update failed and the Worker rollback also failed")?;
            return Err(schedule_error)
                .context("automatic proxyIP Cron Trigger update failed; previous Worker restored");
        }
    }
    let subscription_token = match &existing.sub {
        Some(sub) => Some(credentials.resolve(&sub.subscription_token_ref)?),
        None => None,
    };
    let provisioning = existing.endpoint.primary == PrimaryEndpoint::CustomDomain
        && existing
            .endpoint
            .custom_domains
            .iter()
            .any(|domain| domain.status == DomainStatus::Provisioning);
    let endpoint_role = match (&existing.role, &subscription_token) {
        (Role::Relay, None) => EndpointRole::Relay,
        (Role::Sub, Some(token)) => EndpointRole::Subscription {
            token: token.expose(),
        },
        _ => bail!("deployment role and subscription credentials are inconsistent"),
    };
    if let Err(health_error) = verify_endpoint(
        &network,
        existing
            .primary_domain()
            .context("deployment has no primary endpoint")?,
        endpoint_role,
        provisioning,
        log,
    )
    .await
    {
        let deployment_rollback = client
            .create_deployment(
                &account.account_id,
                &existing.name,
                &previous.0,
                "Veilweave automatic rollback after failed update health check",
            )
            .await;
        let schedule_rollback = if schedule_changed {
            client
                .set_cron_schedules(
                    &account.account_id,
                    &existing.name,
                    previous_schedules.as_deref().unwrap_or(&[]),
                )
                .await
                .map(|_| ())
        } else {
            Ok(())
        };
        deployment_rollback
            .context("new version failed health check and automatic rollback also failed")?;
        schedule_rollback.context(
            "new version failed health check; Worker restored but Cron Triggers could not be restored",
        )?;
        return Err(health_error).context(
            "new version failed health check; previous Worker and Cron Triggers restored",
        );
    }
    config.deployments[index].previous_version_id = Some(previous.0);
    config.deployments[index].previous_deployment_id = Some(previous.1);
    config.deployments[index].stable_version_id = Some(version.id.clone());
    config.deployments[index].stable_deployment_id = Some(promoted.id.clone());
    config.deployments[index].bundle_hash = Some(bundle.manifest().bundle_sha256.clone());
    config.deployments[index].updated_at = Some(crate::config::now_utc_string());
    if persist {
        config.save().context(
            "update succeeded remotely but local metadata save failed; remote version was retained",
        )?;
    }
    Ok(promoted.id)
}

/// Rotate only a Sub Worker's subscription token. Relay-node secrets are
/// inherited strictly, and a failed health check or secure-store write restores
/// the previous Cloudflare deployment and local credential.
pub async fn rotate_subscription_token(
    deployment_id: Uuid,
    source: &BundleSource,
    config: &mut Config,
    credentials: &CredentialManager,
    network: NetworkManager,
    persist: bool,
) -> Result<String> {
    let index = config
        .deployments
        .iter()
        .position(|deployment| deployment.id == deployment_id)
        .context("deployment UUID not found")?;
    let existing = config.deployments[index].clone();
    if existing.role != Role::Sub {
        bail!("subscription-token rotation is available only for a Sub Worker");
    }
    let sub = existing
        .sub
        .as_ref()
        .context("sub deployment has no settings")?;
    let account = config
        .account(&existing.account_id)
        .cloned()
        .context("deployment account is missing")?;
    let api_token = credentials.resolve(&account.credential_ref)?;
    let old_token = credentials.resolve(&sub.subscription_token_ref)?;
    let client = CfClient::with_network(api_token.expose(), network.clone())?;
    if client
        .worker_ownership(&account.account_id, &existing.name)
        .await?
        != WorkerOwnership::VeilweaveSub
    {
        bail!("refusing token rotation: remote Sub ownership marker does not match");
    }
    let previous = current_stable(&client, &account.account_id, &existing.name)
        .await?
        .or_else(|| {
            existing
                .stable_version_id
                .clone()
                .zip(existing.stable_deployment_id.clone())
        })
        .context("no current stable deployment is available for safe rollback")?;
    let bundle = source.worker_bundle(WorkerRole::Sub)?;
    let new_token = SecretValue::new(crate::util::generate_hex_id(32));
    let metadata = cfapi::sub_metadata_for(
        VersionKind::Update,
        None,
        Some(new_token.expose()),
        &sub.kv_binding,
        &sub.kv_namespace_id,
        &SubSettings {
            max_nodes: sub.max_nodes,
            fingerprint: sub.fingerprint.clone(),
            ech: sub.ech.clone(),
        },
        &bundle.manifest().bundle_sha256,
    )?;
    let version = client
        .upload_version(&account.account_id, &existing.name, &bundle, metadata)
        .await?;
    let promoted = client
        .create_deployment(
            &account.account_id,
            &existing.name,
            &version.id,
            "Veilweave subscription-token rotation",
        )
        .await?;
    if let Err(error) = verify_endpoint(
        &network,
        existing
            .endpoint
            .primary_hostname()
            .context("Sub primary endpoint is missing")?,
        EndpointRole::Subscription {
            token: new_token.expose(),
        },
        false,
        &mut |_| {},
    )
    .await
    {
        client
            .create_deployment(
                &account.account_id,
                &existing.name,
                &previous.0,
                "Veilweave rollback after failed token-rotation health check",
            )
            .await
            .context("token rotation failed and previous version could not be restored")?;
        return Err(error).context("new subscription token failed health verification");
    }
    if let Err(error) = credentials.store_verified(&sub.subscription_token_ref, new_token.expose())
    {
        let _ = credentials.store_verified(&sub.subscription_token_ref, old_token.expose());
        client
            .create_deployment(
                &account.account_id,
                &existing.name,
                &previous.0,
                "Veilweave rollback after failed secure token write",
            )
            .await
            .context("secure token write failed and previous version could not be restored")?;
        return Err(error).context("new token was not committed to the secure credential store");
    }
    config.deployments[index].previous_version_id = Some(previous.0);
    config.deployments[index].previous_deployment_id = Some(previous.1);
    config.deployments[index].stable_version_id = Some(version.id);
    config.deployments[index].stable_deployment_id = Some(promoted.id.clone());
    config.deployments[index].updated_at = Some(crate::config::now_utc_string());
    if persist {
        config.save().context(
            "token rotation succeeded remotely and in the secure store but local version metadata save failed",
        )?;
    }
    Ok(promoted.id)
}

pub fn locate_bundle_dir(override_directory: Option<&str>) -> PathBuf {
    match override_directory {
        Some(directory) => PathBuf::from(directory),
        None => std::env::current_exe()
            .ok()
            .and_then(|executable| executable.parent().map(|parent| parent.join("bundle")))
            .unwrap_or_else(|| PathBuf::from("bundle")),
    }
}

pub fn build_nodes_value(nodes: &[(String, String)]) -> String {
    nodes
        .iter()
        .map(|(domain, secret)| format!("{domain}|{secret}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CredentialManager, MemoryCredentialStore};
    use crate::network::NetworkConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn nodes_use_primary_domains_without_transforming_wire_secrets() {
        let nodes = vec![
            ("edge.example.com".into(), "raw-secret".into()),
            ("edge-b.example.net".into(), "VW1Bblob".into()),
        ];
        assert_eq!(
            build_nodes_value(&nodes),
            "edge.example.com|raw-secret,edge-b.example.net|VW1Bblob"
        );
    }

    #[test]
    fn endpoint_modes_require_a_valid_primary() {
        EndpointSpec::default().validate().unwrap();
        assert!(EndpointSpec {
            mode: ExposureMode::CustomDomain,
            primary: PrimaryEndpoint::WorkersDev,
            custom_domain: Some(CustomDomainSpec {
                hostname: "sub.example.com".into(),
                zone_id: "zone".into(),
                zone_name: "example.com".into(),
            }),
        }
        .validate()
        .is_err());
        assert!(EndpointSpec {
            mode: ExposureMode::CustomDomain,
            primary: PrimaryEndpoint::CustomDomain,
            custom_domain: Some(CustomDomainSpec {
                hostname: "*.example.com".into(),
                zone_id: "zone".into(),
                zone_name: "example.com".into(),
            }),
        }
        .validate()
        .is_err());
    }

    #[test]
    fn embedded_and_directory_sources_share_bundle_validation() {
        let build = std::env::temp_dir().join(format!(
            "vw-source-test-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(build.join("worker")).unwrap();
        std::fs::write(build.join("index.js"), b"export default {}").unwrap();
        std::fs::write(build.join("index_bg.wasm"), b"\0asm").unwrap();
        std::fs::write(build.join("worker/shim.mjs"), b"import 0").unwrap();
        let canonical = WorkerBundle::from_worker_build(&build, WorkerRole::Relay).unwrap();
        let source = BundleSource::Embedded(EmbeddedBundle {
            relay: EmbeddedWorkerBundle {
                manifest_json: serde_json::to_vec(canonical.manifest()).unwrap(),
                modules: canonical
                    .modules()
                    .iter()
                    .map(|module| (module.path.clone(), module.contents.clone()))
                    .collect(),
            },
            sub: EmbeddedWorkerBundle::default(),
        });
        let relay = source.worker_bundle(WorkerRole::Relay).unwrap();
        assert_eq!(relay.manifest(), canonical.manifest());
        assert!(relay
            .modules()
            .iter()
            .all(|module| module.path != "package.json"));
        std::fs::remove_dir_all(build).unwrap();
    }

    #[test]
    fn transaction_journal_distinguishes_existing_and_created_resources() {
        let mut transaction = Transaction::new();
        transaction.record(
            "existing KV",
            ResourceDisposition::PreExisting,
            "reused",
            None,
        );
        transaction.record(
            "new KV",
            ResourceDisposition::Created,
            "created",
            Some(Compensation::Kv {
                account_id: "account".into(),
                namespace_id: "namespace".into(),
            }),
        );
        assert_eq!(transaction.records.len(), 2);
        assert_eq!(transaction.compensations.len(), 1);
        assert_eq!(
            transaction.records[0].disposition,
            ResourceDisposition::PreExisting
        );
    }

    #[tokio::test]
    async fn endpoint_readiness_retries_transient_cloudflare_404() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let probe_attempts = Arc::clone(&attempts);
        let mut logs = Vec::new();
        poll_endpoint_readiness(
            "relay.example.workers.dev",
            Duration::from_millis(50),
            Duration::from_millis(1),
            "workers.dev routing/Worker",
            &mut |line| logs.push(line),
            move || {
                let attempt = probe_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                async move {
                    if attempt < 3 {
                        Err(anyhow::anyhow!("HTTP 404 Not Found"))
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert!(format!("{logs:?}").contains("WaitingForEndpoint"));
    }

    #[tokio::test]
    async fn endpoint_readiness_preserves_persistent_failure() {
        let mut logs = Vec::new();
        let error = poll_endpoint_readiness(
            "relay.example.workers.dev",
            Duration::ZERO,
            Duration::ZERO,
            "workers.dev routing/Worker",
            &mut |line| logs.push(line),
            || async { Err(anyhow::anyhow!("HTTP 404 Not Found")) },
        )
        .await
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("did not become healthy"));
        assert!(rendered.contains("HTTP 404 Not Found"));
    }

    #[test]
    fn proxyip_refresh_failure_reports_only_structured_worker_diagnostic() {
        let failure = ProxyIpRefreshFailure {
            at_ms: 1,
            code: "ProxyIpFetchHttpStatus".into(),
            message: "source returned HTTP 403\r\nsecond line".into(),
        };
        assert_eq!(
            proxyip_refresh_failure_message(StatusCode::SERVICE_UNAVAILABLE, Some(&failure)),
            "proxyIP refresh endpoint returned HTTP 503 Service Unavailable; Worker diagnostic ProxyIpFetchHttpStatus: source returned HTTP 403  second line"
        );
        assert_eq!(
            proxyip_refresh_failure_message(StatusCode::SERVICE_UNAVAILABLE, None),
            "proxyIP refresh endpoint returned HTTP 503 Service Unavailable; no structured Worker diagnostic was recorded"
        );

        let parsed = parse_proxyip_refresh_failure(
            true,
            br#"{"at_ms":1,"code":"ProxyIpDatasetInvalid","message":"bad source"}"#,
        )
        .unwrap();
        assert_eq!(parsed.code, "ProxyIpDatasetInvalid");
        assert_eq!(parsed.message, "bad source");
        assert!(parse_proxyip_refresh_failure(false, b"{}").is_none());
        assert!(parse_proxyip_refresh_failure(
            true,
            &vec![b'x'; MAX_MANAGEMENT_RESPONSE_BYTES + 1]
        )
        .is_none());
    }

    #[tokio::test]
    async fn endpoint_transport_errors_never_expose_subscription_urls() {
        let network = NetworkManager::new(
            NetworkConfig {
                request_timeout_secs: 1,
                ..NetworkConfig::default()
            },
            CredentialManager::with_store(Arc::new(MemoryCredentialStore::default())),
        )
        .unwrap();
        let mut logs = Vec::new();
        let error = verify_endpoint(
            &network,
            "does-not-resolve.invalid",
            EndpointRole::Subscription {
                token: "subscription-token-must-not-leak",
            },
            false,
            &mut |line| logs.push(line),
        )
        .await
        .unwrap_err();
        let rendered = format!("{error:#} {logs:?}");
        assert!(!rendered.contains("subscription-token-must-not-leak"));
        assert!(!rendered.contains("/sub?token="));
    }
}
