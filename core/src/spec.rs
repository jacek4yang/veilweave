//! Human-readable, secret-free declarative topology format.

use crate::cfapi::SubSettings;
use crate::config::{ExposureMode, PrimaryEndpoint};
use crate::deploy::{CustomDomainSpec, DeployPlan, EndpointSpec, RelaySpec, SubSpec};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const SPEC_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSpec {
    pub version: u32,
    #[serde(default)]
    pub topology: TopologySpec,
    pub sub: SubDeploymentSpec,
    #[serde(rename = "relay")]
    pub relays: Vec<RelayDeploymentSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TopologySpec {
    #[serde(default)]
    pub encryption: EncryptionMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionMode {
    #[default]
    None,
    Experimental,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubDeploymentSpec {
    pub account: String,
    pub worker: String,
    #[serde(default = "default_kv_title")]
    pub kv_title: String,
    #[serde(default = "default_kv_binding")]
    pub kv_binding: String,
    #[serde(default)]
    pub endpoint: PublicEndpointSpec,
    #[serde(default)]
    pub settings: SubSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayDeploymentSpec {
    pub account: String,
    pub worker: String,
    #[serde(default)]
    pub endpoint: PublicEndpointSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEndpointSpec {
    #[serde(default)]
    pub mode: ExposureMode,
    #[serde(default)]
    pub primary: PrimaryEndpoint,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub zone_name: Option<String>,
}

impl Default for PublicEndpointSpec {
    fn default() -> Self {
        Self {
            mode: ExposureMode::WorkersDev,
            primary: PrimaryEndpoint::WorkersDev,
            hostname: None,
            zone_id: None,
            zone_name: None,
        }
    }
}

impl PublicEndpointSpec {
    fn to_core(&self) -> Result<EndpointSpec> {
        let custom_enabled = matches!(self.mode, ExposureMode::CustomDomain | ExposureMode::Both);
        let custom_domain = if custom_enabled {
            Some(CustomDomainSpec {
                hostname: self
                    .hostname
                    .clone()
                    .context("custom-domain endpoint is missing hostname")?,
                zone_id: self
                    .zone_id
                    .clone()
                    .context("custom-domain endpoint is missing zone_id")?,
                zone_name: self
                    .zone_name
                    .clone()
                    .context("custom-domain endpoint is missing zone_name")?,
            })
        } else {
            if self.hostname.is_some() || self.zone_id.is_some() || self.zone_name.is_some() {
                bail!("workers.dev-only endpoint must not include Custom Domain fields");
            }
            None
        };
        let endpoint = EndpointSpec {
            mode: self.mode,
            primary: self.primary,
            custom_domain,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }
}

impl DeploymentSpec {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read deployment spec {}", path.display()))?;
        let spec: Self = toml::from_str(&text)
            .with_context(|| format!("parse deployment spec {}", path.display()))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != SPEC_VERSION {
            bail!(
                "unsupported deployment spec version {}; expected {SPEC_VERSION}",
                self.version
            );
        }
        if self.relays.is_empty() {
            bail!("deployment spec must contain at least one [[relay]]");
        }
        self.sub.settings.validate()?;
        self.sub.endpoint.to_core()?;
        for relay in &self.relays {
            relay.endpoint.to_core()?;
        }
        self.to_plan().map(|_| ())
    }

    pub fn to_plan(&self) -> Result<DeployPlan> {
        Ok(DeployPlan {
            sub: SubSpec {
                account: self.sub.account.clone(),
                worker_name: self.sub.worker.clone(),
                kv_title: self.sub.kv_title.clone(),
                kv_binding: self.sub.kv_binding.clone(),
                endpoint: self.sub.endpoint.to_core()?,
                settings: self.sub.settings.clone(),
            },
            relays: self
                .relays
                .iter()
                .map(|relay| {
                    Ok(RelaySpec {
                        account: relay.account.clone(),
                        worker_name: relay.worker.clone(),
                        endpoint: relay.endpoint.to_core()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            encryption: self.topology.encryption == EncryptionMode::Experimental,
        })
    }
}

fn default_kv_title() -> String {
    "veilweave-sub-kv".into()
}

fn default_kv_binding() -> String {
    "VEILWEAVE_KV".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_secret_free_custom_domain_topology() {
        let spec: DeploymentSpec = toml::from_str(
            r#"
version = 2
[topology]
encryption = "none"
[sub]
account = "account-id"
worker = "subscription-service"
[sub.endpoint]
mode = "custom-domain"
primary = "custom-domain"
hostname = "sub.example.com"
zone_id = "zone-id"
zone_name = "example.com"
[sub.settings]
max_nodes = 120
fingerprint = "chrome"
ech = "example-ech-config"
[[relay]]
account = "account-id"
worker = "edge-us"
[relay.endpoint]
mode = "both"
primary = "custom-domain"
hostname = "us.example.com"
zone_id = "zone-id"
zone_name = "example.com"
"#,
        )
        .unwrap();
        let plan = spec.to_plan().unwrap();
        assert_eq!(plan.relays.len(), 1);
        assert_eq!(
            plan.relays[0].endpoint.primary,
            PrimaryEndpoint::CustomDomain
        );
        assert_eq!(plan.sub.settings.max_nodes, 120);
        assert_eq!(plan.sub.settings.ech.as_deref(), Some("example-ech-config"));
    }

    #[test]
    fn unknown_secret_fields_are_rejected() {
        let text = r#"
version = 2
[sub]
account = "a"
worker = "sub"
subscription_token = "must-not-be-here"
[[relay]]
account = "a"
worker = "relay"
secret = "must-not-be-here"
"#;
        assert!(toml::from_str::<DeploymentSpec>(text).is_err());
    }
}
