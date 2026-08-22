//! Discovery and safe adoption of remote Veilweave resources.
//!
//! Cloudflare secret bindings are intentionally unreadable. Recovery therefore
//! inventories types and identifiers, then requires the operator to re-link
//! local credential references (or rotate/import secrets) before adoption.

use crate::cfapi::{BindingInfo, CfClient, OWNERSHIP_BINDING, OWNERSHIP_RELAY, OWNERSHIP_SUB};
use crate::config::{
    Deployment, DomainBinding, DomainStatus, EndpointConfig, ExposureMode, PrimaryEndpoint, Role,
    SubDetails,
};
use crate::credentials::CredentialManager;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryState {
    FullyManaged,
    Adoptable,
    SecretMaterialUnavailable,
    Broken,
    Unrelated,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryCandidate {
    pub account_id: String,
    pub name: String,
    pub role: Option<Role>,
    pub state: RecoveryState,
    pub created_at: String,
    pub active_version_id: Option<String>,
    pub active_deployment_id: Option<String>,
    pub workers_dev_enabled: bool,
    pub workers_dev_hostname: Option<String>,
    pub custom_domains: Vec<DomainBinding>,
    pub kv_namespace_id: Option<String>,
    pub kv_title: Option<String>,
    pub kv_binding: Option<String>,
    pub required_secret_names: Vec<String>,
    pub diagnostic: String,
}

#[derive(Debug, Default, Serialize)]
pub struct RecoverOutcome {
    pub candidates: Vec<RecoveryCandidate>,
    pub summary: Vec<String>,
}

pub async fn recover_account(
    client: &CfClient,
    account_id: &str,
    subdomain: Option<&str>,
) -> Result<RecoverOutcome> {
    let workers = client.list_workers(account_id).await?;
    let mut outcome = RecoverOutcome::default();
    let domains = match client.list_domains(account_id).await {
        Ok(domains) => domains,
        Err(error) => {
            outcome.summary.push(format!(
                "Custom Domain inventory unavailable; candidates may be incomplete: {error:#}"
            ));
            Vec::new()
        }
    };
    let namespaces = match client.list_kv_namespaces(account_id).await {
        Ok(namespaces) => namespaces,
        Err(error) => {
            outcome.summary.push(format!(
                "KV inventory unavailable; Sub candidates may be incomplete: {error:#}"
            ));
            Vec::new()
        }
    };
    for worker in workers {
        let bindings = client.get_script_settings(account_id, &worker.id).await?;
        let role = classify_role(&bindings);
        let marker = plain_text(&bindings, OWNERSHIP_BINDING);
        let expected_marker = match role {
            Some(Role::Relay) => Some(OWNERSHIP_RELAY),
            Some(Role::Sub) => Some(OWNERSHIP_SUB),
            None => None,
        };
        let required_secret_names = match role {
            Some(Role::Relay) => vec!["SECRET_KEY".into()],
            Some(Role::Sub) => vec!["VEILWEAVE_NODES".into(), "SUBSCRIPTION_TOKEN".into()],
            None => Vec::new(),
        };
        let secret_types_secure = required_secret_names.iter().all(|name| {
            bindings
                .iter()
                .any(|binding| binding.name == *name && binding.kind == "secret_text")
        });
        let state = match role {
            None => RecoveryState::Unrelated,
            Some(_) if marker.as_deref() == expected_marker && secret_types_secure => {
                RecoveryState::SecretMaterialUnavailable
            }
            Some(_) if marker.as_deref() == expected_marker => RecoveryState::Broken,
            Some(_) => RecoveryState::Adoptable,
        };
        let workers_dev = client
            .get_workers_dev_state(account_id, &worker.id)
            .await
            .ok();
        let workers_dev_enabled = workers_dev.as_ref().is_some_and(|state| state.enabled);
        let workers_dev_hostname = if workers_dev_enabled {
            subdomain.map(|value| format!("{}.{}.workers.dev", worker.id, value))
        } else {
            None
        };
        let custom_domains = domains
            .iter()
            .filter(|domain| domain.service == worker.id)
            .map(|domain| DomainBinding {
                domain_id: domain.id.clone(),
                hostname: domain.hostname.clone(),
                zone_id: domain.zone_id.clone().unwrap_or_default(),
                zone_name: domain.zone_name.clone().unwrap_or_default(),
                service: domain.service.clone(),
                primary: false,
                status: match domain.status.as_deref() {
                    Some("active" | "ready") => DomainStatus::Ready,
                    Some("error" | "failed") => DomainStatus::Error,
                    Some(_) | None => DomainStatus::Provisioning,
                },
            })
            .collect::<Vec<_>>();
        let (active_version_id, active_deployment_id) =
            active_remote_state(client, account_id, &worker.id).await?;
        let kv = bindings
            .iter()
            .find(|binding| binding.kind == "kv_namespace");
        let kv_namespace_id = kv.and_then(|binding| binding.namespace_id.clone());
        let diagnostic = match state {
            RecoveryState::SecretMaterialUnavailable => {
                "Remote metadata is complete; re-link local credentials, import a secure backup, or rotate secrets before adoption"
            }
            RecoveryState::Adoptable => {
                "Legacy Veilweave structure detected without v2 ownership metadata; review and explicitly adopt"
            }
            RecoveryState::Broken => {
                "Veilweave ownership exists but required secure binding types are incomplete"
            }
            RecoveryState::Unrelated => "No Veilweave ownership or structural signature detected",
            RecoveryState::FullyManaged => "Linked local metadata and credentials are available",
        }
        .to_string();
        outcome.summary.push(format!(
            "{}: {} ({state:?})",
            worker.id,
            role.map_or("unrelated".into(), |value| value.to_string())
        ));
        outcome.candidates.push(RecoveryCandidate {
            account_id: account_id.into(),
            name: worker.id,
            role,
            state,
            created_at: worker
                .created_on
                .unwrap_or_else(crate::config::now_utc_string),
            active_version_id,
            active_deployment_id,
            workers_dev_enabled,
            workers_dev_hostname,
            custom_domains,
            kv_title: kv_namespace_id.as_ref().and_then(|id| {
                namespaces
                    .iter()
                    .find(|namespace| namespace.id == *id)
                    .map(|namespace| namespace.title.clone())
            }),
            kv_namespace_id,
            kv_binding: plain_text(&bindings, "KV_BINDING")
                .or_else(|| kv.map(|binding| binding.name.clone())),
            required_secret_names,
            diagnostic,
        });
    }
    Ok(outcome)
}

/// Reconcile remote inventory with local metadata without exposing credential
/// references. Only candidates whose complete credential set resolves are
/// upgraded to `fully-managed`.
pub fn reconcile_local(
    outcome: &mut RecoverOutcome,
    deployments: &[Deployment],
    credentials: &CredentialManager,
) {
    for candidate in &mut outcome.candidates {
        let Some(local) = deployments.iter().find(|deployment| {
            deployment.account_id == candidate.account_id && deployment.name == candidate.name
        }) else {
            continue;
        };
        let credentials_available = credentials.resolve(&local.secret_ref).is_ok()
            && local
                .node_secret_ref
                .as_deref()
                .is_none_or(|reference| credentials.resolve(reference).is_ok())
            && local
                .sub
                .as_ref()
                .is_none_or(|sub| credentials.resolve(&sub.subscription_token_ref).is_ok());
        if credentials_available {
            candidate.state = RecoveryState::FullyManaged;
            candidate.diagnostic =
                "Remote state matches local metadata and all credential references resolve".into();
        }
    }
}

async fn active_remote_state(
    client: &CfClient,
    account_id: &str,
    worker: &str,
) -> Result<(Option<String>, Option<String>)> {
    let mut deployments = client.list_deployments(account_id, worker).await?;
    deployments.sort_by(|left, right| right.created_on.cmp(&left.created_on));
    let Some(deployment) = deployments.into_iter().next() else {
        return Ok((None, None));
    };
    let version = deployment
        .versions
        .iter()
        .find(|version| version.percentage >= 99.999)
        .map(|version| version.version_id.clone());
    Ok((version, Some(deployment.id)))
}

fn classify_role(bindings: &[BindingInfo]) -> Option<Role> {
    let marker = plain_text(bindings, OWNERSHIP_BINDING);
    if marker.as_deref() == Some(OWNERSHIP_RELAY)
        || bindings.iter().any(|binding| {
            binding.name == "VEILWEAVE_SESSION"
                && binding.kind == "durable_object_namespace"
                && binding.class_name.as_deref() == Some("VeilweaveSession")
        })
    {
        return Some(Role::Relay);
    }
    if marker.as_deref() == Some(OWNERSHIP_SUB)
        || bindings.iter().any(|binding| {
            binding.name == "VEILWEAVE_NODES"
                && matches!(binding.kind.as_str(), "secret_text" | "plain_text")
        })
    {
        return Some(Role::Sub);
    }
    None
}

fn plain_text(bindings: &[BindingInfo], name: &str) -> Option<String> {
    bindings
        .iter()
        .find(|binding| binding.name == name && binding.kind == "plain_text")
        .and_then(|binding| binding.text.clone())
}

#[derive(Debug, Clone)]
pub struct AdoptionCredentials {
    pub worker_secret_ref: String,
    pub node_secret_ref: Option<String>,
    pub subscription_token_ref: Option<String>,
}

pub fn adopt_candidate(
    candidate: &RecoveryCandidate,
    credentials: AdoptionCredentials,
    primary: PrimaryEndpoint,
) -> Result<Deployment> {
    let role = candidate
        .role
        .context("unrelated Worker cannot be adopted")?;
    if candidate.state == RecoveryState::Unrelated {
        bail!("unrelated Worker cannot be adopted");
    }
    if !matches!(
        candidate.state,
        RecoveryState::SecretMaterialUnavailable | RecoveryState::FullyManaged
    ) {
        bail!(
            "only a v2 Worker with secure secret bindings can be re-linked; repair legacy/broken bindings before adoption"
        );
    }
    if candidate.workers_dev_enabled && candidate.workers_dev_hostname.is_none() {
        bail!("workers.dev is enabled but the account subdomain is unknown");
    }
    let mode = match (
        candidate.workers_dev_enabled,
        candidate.custom_domains.is_empty(),
    ) {
        (true, true) => ExposureMode::WorkersDev,
        (false, false) => ExposureMode::CustomDomain,
        (true, false) => ExposureMode::Both,
        (false, true) => bail!("Worker has no public endpoint to adopt"),
    };
    let mut custom_domains = candidate.custom_domains.clone();
    if primary == PrimaryEndpoint::CustomDomain {
        let first = custom_domains
            .first_mut()
            .context("cannot select a missing Custom Domain as primary")?;
        first.primary = true;
    }
    let endpoint = EndpointConfig {
        mode,
        primary,
        workers_dev_enabled: candidate.workers_dev_enabled,
        workers_dev_hostname: candidate.workers_dev_hostname.clone(),
        custom_domains,
    };
    endpoint.validate()?;
    let sub = if role == Role::Sub {
        Some(SubDetails {
            kv_namespace_id: candidate
                .kv_namespace_id
                .clone()
                .context("sub Worker has no KV namespace binding")?,
            kv_title: candidate.kv_title.clone().unwrap_or_default(),
            kv_binding: candidate
                .kv_binding
                .clone()
                .context("sub Worker has no KV binding name")?,
            subscription_token_ref: credentials
                .subscription_token_ref
                .context("sub adoption requires a subscription-token credential reference")?,
            max_nodes: 100,
            fingerprint: "chrome".into(),
            disable_builtin_proxyip: false,
            proxyip_list: Vec::new(),
        })
    } else {
        None
    };
    if role == Role::Relay && credentials.node_secret_ref.is_none() {
        bail!("relay adoption requires a node-secret credential reference");
    }
    Ok(Deployment {
        id: Uuid::new_v4(),
        role,
        name: candidate.name.clone(),
        account_id: candidate.account_id.clone(),
        secret_ref: credentials.worker_secret_ref,
        node_secret_ref: credentials.node_secret_ref,
        endpoint,
        created_at: candidate.created_at.clone(),
        updated_at: Some(crate::config::now_utc_string()),
        stable_version_id: candidate.active_version_id.clone(),
        stable_deployment_id: candidate.active_deployment_id.clone(),
        previous_version_id: None,
        previous_deployment_id: None,
        bundle_hash: None,
        sub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(name: &str, kind: &str, text: Option<&str>) -> BindingInfo {
        BindingInfo {
            name: name.into(),
            kind: kind.into(),
            text: text.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn secure_bindings_are_classified_without_reading_values() {
        let relay = vec![
            binding(OWNERSHIP_BINDING, "plain_text", Some(OWNERSHIP_RELAY)),
            binding("SECRET_KEY", "secret_text", None),
            BindingInfo {
                name: "VEILWEAVE_SESSION".into(),
                kind: "durable_object_namespace".into(),
                class_name: Some("VeilweaveSession".into()),
                ..Default::default()
            },
        ];
        assert_eq!(classify_role(&relay), Some(Role::Relay));
        assert!(plain_text(&relay, "SECRET_KEY").is_none());
    }

    #[test]
    fn unrelated_worker_is_not_adoptable() {
        let candidate = RecoveryCandidate {
            account_id: "account".into(),
            name: "random-worker".into(),
            role: None,
            state: RecoveryState::Unrelated,
            created_at: crate::config::now_utc_string(),
            active_version_id: None,
            active_deployment_id: None,
            workers_dev_enabled: false,
            workers_dev_hostname: None,
            custom_domains: Vec::new(),
            kv_namespace_id: None,
            kv_title: None,
            kv_binding: None,
            required_secret_names: Vec::new(),
            diagnostic: String::new(),
        };
        assert!(adopt_candidate(
            &candidate,
            AdoptionCredentials {
                worker_secret_ref: "keyring:x".into(),
                node_secret_ref: None,
                subscription_token_ref: None,
            },
            PrimaryEndpoint::WorkersDev,
        )
        .is_err());
    }

    #[test]
    fn secure_v2_sub_can_be_relinked_with_explicit_references() {
        let candidate = RecoveryCandidate {
            account_id: "account".into(),
            name: "sub-worker".into(),
            role: Some(Role::Sub),
            state: RecoveryState::SecretMaterialUnavailable,
            created_at: crate::config::now_utc_string(),
            active_version_id: Some("version-1".into()),
            active_deployment_id: Some("deployment-1".into()),
            workers_dev_enabled: true,
            workers_dev_hostname: Some("sub-worker.example.workers.dev".into()),
            custom_domains: Vec::new(),
            kv_namespace_id: Some("kv-id".into()),
            kv_title: Some("sub-worker-kv".into()),
            kv_binding: Some("VEILWEAVE_KV".into()),
            required_secret_names: vec!["VEILWEAVE_NODES".into(), "SUBSCRIPTION_TOKEN".into()],
            diagnostic: String::new(),
        };
        let deployment = adopt_candidate(
            &candidate,
            AdoptionCredentials {
                worker_secret_ref: "env:NODES_SECRET".into(),
                node_secret_ref: None,
                subscription_token_ref: Some("env:SUBSCRIPTION_TOKEN".into()),
            },
            PrimaryEndpoint::WorkersDev,
        )
        .unwrap();
        let sub = deployment.sub.unwrap();
        assert_eq!(sub.kv_namespace_id, "kv-id");
        assert_eq!(sub.kv_title, "sub-worker-kv");
        assert_eq!(deployment.stable_version_id.as_deref(), Some("version-1"));
    }
}
