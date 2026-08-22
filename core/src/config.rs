//! Durable schema-v2 local state.
//!
//! The TOML file contains topology metadata and opaque credential references
//! only. API tokens, Worker secrets, subscription tokens, and node material
//! live in the platform credential store (or an explicit `env:` reference).

use crate::credentials::{CredentialManager, SecretValue};
use crate::network::NetworkConfig;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub schema_version: u32,
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub deployments: Vec<Deployment>,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub ui_language: Option<String>,
    #[serde(default)]
    pub ui_theme: Option<String>,
    /// Populated only after recovering a corrupt primary file from `.bak`.
    #[serde(skip)]
    pub recovery_notice: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            accounts: Vec::new(),
            deployments: Vec::new(),
            network: NetworkConfig::default(),
            ui_language: None,
            ui_theme: None,
            recovery_notice: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    /// Display-only label. Stable references use `account_id`.
    pub name: String,
    pub account_id: String,
    pub credential_ref: String,
    #[serde(default)]
    pub workers_dev_subdomain: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Relay,
    Sub,
}

impl std::fmt::Display for Role {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Role::Relay => "relay",
            Role::Sub => "sub",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ExposureMode {
    #[default]
    WorkersDev,
    CustomDomain,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PrimaryEndpoint {
    #[default]
    WorkersDev,
    CustomDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EndpointConfig {
    #[serde(default)]
    pub mode: ExposureMode,
    #[serde(default)]
    pub primary: PrimaryEndpoint,
    #[serde(default)]
    pub workers_dev_enabled: bool,
    #[serde(default)]
    pub workers_dev_hostname: Option<String>,
    #[serde(default)]
    pub custom_domains: Vec<DomainBinding>,
}

impl EndpointConfig {
    pub fn primary_hostname(&self) -> Option<&str> {
        match self.primary {
            PrimaryEndpoint::WorkersDev => self.workers_dev_hostname.as_deref(),
            PrimaryEndpoint::CustomDomain => self
                .custom_domains
                .iter()
                .find(|domain| domain.primary)
                .or_else(|| self.custom_domains.first())
                .map(|domain| domain.hostname.as_str()),
        }
    }

    pub fn validate(&self) -> Result<()> {
        let needs_workers_dev = matches!(self.mode, ExposureMode::WorkersDev | ExposureMode::Both);
        let needs_custom = matches!(self.mode, ExposureMode::CustomDomain | ExposureMode::Both);
        if needs_workers_dev != self.workers_dev_enabled {
            bail!("workers.dev enabled state does not match exposure mode");
        }
        if needs_workers_dev {
            validate_hostname(
                self.workers_dev_hostname
                    .as_deref()
                    .context("workers.dev hostname is missing")?,
            )?;
        }
        if needs_custom && self.custom_domains.is_empty() {
            bail!("custom-domain exposure requires at least one exact hostname");
        }
        if self.primary == PrimaryEndpoint::CustomDomain && !needs_custom {
            bail!("custom domain cannot be primary when custom-domain exposure is disabled");
        }
        if self.primary == PrimaryEndpoint::WorkersDev && !needs_workers_dev {
            bail!("workers.dev cannot be primary when workers.dev exposure is disabled");
        }
        let primary_count = self
            .custom_domains
            .iter()
            .filter(|domain| domain.primary)
            .count();
        if primary_count > 1 {
            bail!("only one Custom Domain can be primary");
        }
        for domain in &self.custom_domains {
            domain.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DomainStatus {
    #[default]
    Attached,
    Provisioning,
    Ready,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainBinding {
    pub domain_id: String,
    pub hostname: String,
    pub zone_id: String,
    pub zone_name: String,
    pub service: String,
    #[serde(default)]
    pub primary: bool,
    #[serde(default)]
    pub status: DomainStatus,
}

impl DomainBinding {
    pub fn validate(&self) -> Result<()> {
        validate_hostname(&self.hostname)?;
        let zone = idna::domain_to_ascii(self.zone_name.trim_end_matches('.'))
            .context("invalid zone name")?
            .to_ascii_lowercase();
        let hostname = idna::domain_to_ascii(self.hostname.trim_end_matches('.'))
            .context("invalid Custom Domain hostname")?
            .to_ascii_lowercase();
        if hostname != zone && !hostname.ends_with(&format!(".{zone}")) {
            bail!(
                "Custom Domain {:?} does not belong to zone {:?}",
                self.hostname,
                self.zone_name
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub id: Uuid,
    pub role: Role,
    pub name: String,
    pub account_id: String,
    /// Credential containing relay SECRET_KEY or sub VEILWEAVE_NODES.
    pub secret_ref: String,
    /// Relay-only credential containing the node-side secret placed in the
    /// sub topology. This differs from `secret_ref` in encrypted mode.
    #[serde(default)]
    pub node_secret_ref: Option<String>,
    pub endpoint: EndpointConfig,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub stable_version_id: Option<String>,
    #[serde(default)]
    pub stable_deployment_id: Option<String>,
    #[serde(default)]
    pub previous_version_id: Option<String>,
    #[serde(default)]
    pub previous_deployment_id: Option<String>,
    #[serde(default)]
    pub bundle_hash: Option<String>,
    #[serde(default)]
    pub sub: Option<SubDetails>,
}

impl Deployment {
    pub fn primary_domain(&self) -> Option<&str> {
        self.endpoint.primary_hostname()
    }

    pub fn subscription_url(&self, credentials: &CredentialManager) -> Result<Option<String>> {
        let Some(sub) = &self.sub else {
            return Ok(None);
        };
        let domain = self
            .primary_domain()
            .context("sub deployment has no primary endpoint")?;
        let token = credentials.resolve(&sub.subscription_token_ref)?;
        Ok(Some(format!(
            "https://{domain}/sub?token={}",
            token.expose()
        )))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubDetails {
    pub kv_namespace_id: String,
    pub kv_title: String,
    pub kv_binding: String,
    pub subscription_token_ref: String,
    #[serde(default = "default_max_nodes")]
    pub max_nodes: u16,
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,
    #[serde(default)]
    pub disable_builtin_proxyip: bool,
    #[serde(default)]
    pub proxyip_list: Vec<String>,
}

fn default_max_nodes() -> u16 {
    100
}

fn default_fingerprint() -> String {
    "chrome".into()
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        let directory = dirs::config_dir().context("no platform config directory")?;
        Ok(directory.join("veilweave").join("config.toml"))
    }

    pub fn load() -> Result<Self> {
        Self::load_from_with_credentials(&Self::path()?, &CredentialManager::system())
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        Self::load_from_with_credentials(path, &CredentialManager::system())
    }

    pub fn load_from_with_credentials(
        path: &Path,
        credentials: &CredentialManager,
    ) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(error) => {
                return Err(error).with_context(|| format!("read config at {}", path.display()))
            }
        };
        match parse_or_migrate(path, &text, credentials) {
            Ok(config) => Ok(config),
            Err(primary_error) => {
                let backup = backup_path(path);
                let backup_text = std::fs::read_to_string(&backup).with_context(|| {
                    format!(
                        "config at {} is corrupt ({primary_error:#}); no readable recovery backup at {}",
                        path.display(),
                        backup.display()
                    )
                })?;
                let mut recovered: Config = toml::from_str(&backup_text).with_context(|| {
                    format!(
                        "config at {} and recovery backup at {} are both corrupt",
                        path.display(),
                        backup.display()
                    )
                })?;
                recovered.validate()?;
                recovered.recovery_notice = Some(format!(
                    "Recovered metadata from {} because {} was corrupt: {primary_error:#}",
                    backup.display(),
                    path.display()
                ));
                Ok(recovered)
            }
        }
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::path()?)
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let text = toml::to_string_pretty(self).context("serialize schema-v2 config")?;
        persist_atomic(path, text.as_bytes(), true)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!(
                "unsupported config schema version {}; expected {SCHEMA_VERSION}",
                self.schema_version
            );
        }
        if !matches!(self.ui_language.as_deref(), None | Some("en") | Some("zh")) {
            bail!("ui_language must be en, zh, or absent");
        }
        if !matches!(
            self.ui_theme.as_deref(),
            None | Some("dark") | Some("light")
        ) {
            bail!("ui_theme must be dark, light, or absent");
        }
        self.network.validate()?;
        let mut account_ids = HashSet::new();
        for account in &self.accounts {
            if account.account_id.trim().is_empty() || account.credential_ref.trim().is_empty() {
                bail!("account IDs and credential references cannot be empty");
            }
            if !account_ids.insert(account.account_id.as_str()) {
                bail!("duplicate Cloudflare account ID {:?}", account.account_id);
            }
        }
        let mut deployment_ids = HashSet::new();
        let mut remote_names = HashSet::new();
        for deployment in &self.deployments {
            if !deployment_ids.insert(deployment.id) {
                bail!("duplicate local deployment UUID {}", deployment.id);
            }
            if !account_ids.contains(deployment.account_id.as_str()) {
                bail!(
                    "deployment {} references missing account ID {:?}",
                    deployment.id,
                    deployment.account_id
                );
            }
            if !remote_names.insert((deployment.account_id.as_str(), deployment.name.as_str())) {
                bail!(
                    "duplicate Worker {:?} in account {:?}",
                    deployment.name,
                    deployment.account_id
                );
            }
            validate_worker_name(&deployment.name)?;
            deployment.endpoint.validate()?;
            if deployment.role == Role::Sub && deployment.sub.is_none() {
                bail!("sub deployment {} is missing sub settings", deployment.id);
            }
            if deployment.role == Role::Relay && deployment.sub.is_some() {
                bail!("relay deployment {} contains sub settings", deployment.id);
            }
        }
        Ok(())
    }

    pub fn account(&self, id_or_name: &str) -> Option<&Account> {
        self.accounts
            .iter()
            .find(|account| account.account_id == id_or_name || account.name == id_or_name)
    }
}

fn parse_or_migrate(path: &Path, text: &str, credentials: &CredentialManager) -> Result<Config> {
    let value: toml::Value = toml::from_str(text).context("parse config TOML")?;
    if value
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        == Some(SCHEMA_VERSION as i64)
    {
        let config: Config = toml::from_str(text).context("parse schema-v2 config")?;
        config.validate()?;
        return Ok(config);
    }
    if value.get("schema_version").is_some() {
        bail!("unsupported config schema version");
    }
    migrate_v1(path, text, credentials)
}

#[derive(Deserialize)]
struct LegacyConfig {
    #[serde(default)]
    accounts: Vec<LegacyAccount>,
    #[serde(default)]
    deployments: Vec<LegacyDeployment>,
    #[serde(default)]
    ui_language: Option<String>,
    #[serde(default)]
    ui_theme: Option<String>,
}

#[derive(Deserialize)]
struct LegacyAccount {
    name: String,
    token: String,
    account_id: String,
    #[serde(default)]
    workers_dev_subdomain: Option<String>,
}

#[derive(Deserialize)]
struct LegacyDeployment {
    role: Role,
    name: String,
    account: String,
    domain: String,
    secret: String,
    created_at: String,
    #[serde(default)]
    sub: Option<LegacySubDetails>,
}

#[derive(Deserialize)]
struct LegacySubDetails {
    kv_namespace_id: String,
    kv_title: String,
    kv_binding: String,
    subscription_token: String,
}

fn migrate_v1(path: &Path, text: &str, credentials: &CredentialManager) -> Result<Config> {
    let mut credential_journal = Vec::new();
    let result = (|| -> Result<Config> {
        let legacy: LegacyConfig = toml::from_str(text).context("parse legacy v1 config")?;
        let legacy_node_secrets = legacy
            .deployments
            .iter()
            .filter(|deployment| deployment.role == Role::Sub)
            .flat_map(|deployment| deployment.secret.split(','))
            .filter_map(|entry| entry.split_once('|'))
            .map(|(domain, secret)| (domain.to_string(), secret.to_string()))
            .collect::<HashMap<_, _>>();
        let mut account_ids = HashMap::new();
        let mut accounts = Vec::new();
        for account in legacy.accounts {
            let reference = CredentialManager::keyring_reference(&format!(
                "account/{}/api-token",
                account.account_id
            ));
            store_migration_credential(
                credentials,
                &mut credential_journal,
                &reference,
                &account.token,
            )
            .with_context(|| format!("migrate API token for account {:?}", account.name))?;
            account_ids.insert(account.name.clone(), account.account_id.clone());
            accounts.push(Account {
                name: account.name,
                account_id: account.account_id,
                credential_ref: reference,
                workers_dev_subdomain: account.workers_dev_subdomain,
            });
        }
        let mut deployments = Vec::new();
        for deployment in legacy.deployments {
            let id = Uuid::new_v4();
            let account_id = account_ids
                .get(&deployment.account)
                .cloned()
                .with_context(|| {
                    format!(
                        "legacy deployment {:?} references missing account label {:?}",
                        deployment.name, deployment.account
                    )
                })?;
            let secret_ref =
                CredentialManager::keyring_reference(&format!("deployment/{id}/worker-secret"));
            store_migration_credential(
                credentials,
                &mut credential_journal,
                &secret_ref,
                &deployment.secret,
            )
            .with_context(|| format!("migrate Worker secret for {:?}", deployment.name))?;
            let node_secret_ref = if deployment.role == Role::Relay {
                let reference =
                    CredentialManager::keyring_reference(&format!("deployment/{id}/node-secret"));
                let node_secret = legacy_node_secrets
                    .get(&deployment.domain)
                    .map(String::as_str)
                    .unwrap_or(&deployment.secret);
                store_migration_credential(
                    credentials,
                    &mut credential_journal,
                    &reference,
                    node_secret,
                )
                .with_context(|| format!("migrate node secret for {:?}", deployment.name))?;
                Some(reference)
            } else {
                None
            };
            let sub = match deployment.sub {
                Some(sub) => {
                    let token_ref = CredentialManager::keyring_reference(&format!(
                        "deployment/{id}/subscription-token"
                    ));
                    store_migration_credential(
                        credentials,
                        &mut credential_journal,
                        &token_ref,
                        &sub.subscription_token,
                    )
                    .with_context(|| {
                        format!("migrate subscription token for {:?}", deployment.name)
                    })?;
                    Some(SubDetails {
                        kv_namespace_id: sub.kv_namespace_id,
                        kv_title: sub.kv_title,
                        kv_binding: sub.kv_binding,
                        subscription_token_ref: token_ref,
                        max_nodes: default_max_nodes(),
                        fingerprint: default_fingerprint(),
                        disable_builtin_proxyip: false,
                        proxyip_list: Vec::new(),
                    })
                }
                None => None,
            };
            deployments.push(Deployment {
                id,
                role: deployment.role,
                name: deployment.name,
                account_id,
                secret_ref,
                node_secret_ref,
                endpoint: EndpointConfig {
                    mode: ExposureMode::WorkersDev,
                    primary: PrimaryEndpoint::WorkersDev,
                    workers_dev_enabled: true,
                    workers_dev_hostname: Some(deployment.domain),
                    custom_domains: Vec::new(),
                },
                created_at: deployment.created_at,
                updated_at: None,
                stable_version_id: None,
                stable_deployment_id: None,
                previous_version_id: None,
                previous_deployment_id: None,
                bundle_hash: None,
                sub,
            });
        }
        let config = Config {
            schema_version: SCHEMA_VERSION,
            accounts,
            deployments,
            network: NetworkConfig::default(),
            ui_language: legacy.ui_language,
            ui_theme: legacy.ui_theme,
            recovery_notice: Some("Migrated v1 plaintext credentials to secure storage".into()),
        };
        config.validate()?;
        let redacted = toml::to_string_pretty(&config).context("serialize migrated config")?;
        persist_atomic(path, redacted.as_bytes(), false)
            .context("install redacted schema-v2 config after credential verification")?;
        Ok(config)
    })();
    match result {
        Ok(config) => Ok(config),
        Err(error) => match rollback_migration_credentials(credentials, credential_journal) {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(error.context(format!(
                "secure credential rollback also failed: {rollback_error:#}"
            ))),
        },
    }
}

fn store_migration_credential(
    credentials: &CredentialManager,
    journal: &mut Vec<(String, Option<SecretValue>)>,
    reference: &str,
    value: &str,
) -> Result<()> {
    let previous = credentials.resolve(reference).ok();
    if let Err(error) = credentials.store_verified(reference, value) {
        match previous {
            Some(previous) => credentials.store_verified(reference, previous.expose())?,
            None => credentials.delete(reference)?,
        }
        return Err(error);
    }
    journal.push((reference.to_string(), previous));
    Ok(())
}

fn rollback_migration_credentials(
    credentials: &CredentialManager,
    journal: Vec<(String, Option<SecretValue>)>,
) -> Result<()> {
    for (reference, previous) in journal.into_iter().rev() {
        match previous {
            Some(previous) => credentials.store_verified(&reference, previous.expose())?,
            None => credentials.delete(&reference)?,
        }
    }
    Ok(())
}

fn persist_atomic(path: &Path, bytes: &[u8], keep_backup: bool) -> Result<()> {
    let parent = path
        .parent()
        .context("config path has no parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create config directory {}", parent.display()))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config"),
        Uuid::new_v4()
    ));
    write_private_file(&temporary, bytes)?;

    let previous = if keep_backup {
        backup_path(path)
    } else {
        path.with_extension("toml.v1-migrating")
    };
    if previous.exists() {
        std::fs::remove_file(&previous)
            .with_context(|| format!("remove stale replacement file {}", previous.display()))?;
    }
    let had_previous = path.exists();
    if had_previous {
        std::fs::rename(path, &previous).with_context(|| {
            format!(
                "move existing config {} to {}",
                path.display(),
                previous.display()
            )
        })?;
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        if had_previous {
            let _ = std::fs::rename(&previous, path);
        }
        return Err(error).with_context(|| format!("atomically install config {}", path.display()));
    }
    sync_directory(parent)?;
    if had_previous && !keep_backup {
        std::fs::remove_file(&previous).with_context(|| {
            format!(
                "retire legacy plaintext config after successful migration at {}",
                previous.display()
            )
        })?;
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create private temporary config {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write temporary config {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flush temporary config {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync temporary config {}", path.display()))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync config directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("toml.bak")
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
        bail!("invalid Cloudflare Worker name {name:?}");
    }
    Ok(())
}

pub fn validate_hostname(hostname: &str) -> Result<String> {
    let input = hostname.trim().trim_end_matches('.');
    if input.is_empty()
        || input.contains('*')
        || input.contains('/')
        || input.contains(char::is_whitespace)
    {
        bail!("Custom Domains must be exact hostnames without wildcards or URL syntax");
    }
    let ascii = idna::domain_to_ascii(input)
        .context("invalid IDNA hostname")?
        .to_ascii_lowercase();
    if ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        bail!("invalid hostname {hostname:?}");
    }
    Ok(ascii)
}

pub fn now_utc_string() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format_unix_utc(seconds)
}

/// Unix seconds to RFC 3339 UTC. Days-to-civil algorithm by Howard Hinnant.
pub fn format_unix_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (hour, minute, second) = (remainder / 3600, (remainder % 3600) / 60, remainder % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let day_of_year = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CredentialStore, MemoryCredentialStore};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct FailingCredentialStore {
        values: Mutex<HashMap<String, String>>,
        writes: AtomicUsize,
        fail_at: usize,
    }

    impl CredentialStore for FailingCredentialStore {
        fn set(&self, key: &str, value: &str) -> Result<()> {
            if self.writes.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_at {
                bail!("injected credential write failure");
            }
            self.values
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn get(&self, key: &str) -> Result<SecretValue> {
            self.values
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .map(SecretValue::new)
                .context("credential not found")
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.values.lock().unwrap().remove(key);
            Ok(())
        }
    }

    fn manager() -> CredentialManager {
        CredentialManager::with_store(Arc::new(MemoryCredentialStore::default()))
    }

    fn temporary_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "veilweave-{name}-{}-{}.toml",
            std::process::id(),
            Uuid::new_v4()
        ))
    }

    #[test]
    fn v1_migration_verifies_secrets_then_writes_only_references() {
        let path = temporary_path("migration");
        let legacy = r#"
[[accounts]]
name = "personal"
token = "cf-secret-token"
account_id = "account-123"
workers_dev_subdomain = "alice"

[[deployments]]
role = "relay"
name = "edge-one"
account = "personal"
domain = "edge-one.alice.workers.dev"
secret = "relay-secret-value"
created_at = "2026-08-20T00:00:00Z"

[[deployments]]
role = "sub"
name = "sub-one"
account = "personal"
domain = "sub-one.alice.workers.dev"
secret = "nodes-secret-value"
created_at = "2026-08-20T00:01:00Z"

[deployments.sub]
kv_namespace_id = "kv-id"
kv_title = "sub-kv"
kv_binding = "VEILWEAVE_KV"
subscription_token = "subscription-secret-value"
"#;
        std::fs::write(&path, legacy).unwrap();
        let credentials = manager();
        let config = Config::load_from_with_credentials(&path, &credentials).unwrap();
        assert_eq!(config.schema_version, SCHEMA_VERSION);
        assert_eq!(config.accounts[0].account_id, "account-123");
        let persisted = std::fs::read_to_string(&path).unwrap();
        for secret in [
            "cf-secret-token",
            "relay-secret-value",
            "nodes-secret-value",
            "subscription-secret-value",
        ] {
            assert!(!persisted.contains(secret));
        }
        assert_eq!(
            credentials
                .resolve(&config.accounts[0].credential_ref)
                .unwrap()
                .expose(),
            "cf-secret-token"
        );
        assert!(!path.with_extension("toml.v1-migrating").exists());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn v1_migration_rolls_back_all_credentials_when_a_write_fails() {
        let path = temporary_path("migration-rollback");
        let legacy = r#"
[[accounts]]
name = "first"
token = "first-secret"
account_id = "account-first"

[[accounts]]
name = "second"
token = "second-secret"
account_id = "account-second"
"#;
        std::fs::write(&path, legacy).unwrap();
        let store = Arc::new(FailingCredentialStore {
            values: Mutex::new(HashMap::new()),
            writes: AtomicUsize::new(0),
            fail_at: 2,
        });
        let credentials = CredentialManager::with_store(store.clone());
        assert!(Config::load_from_with_credentials(&path, &credentials).is_err());
        assert!(store.values.lock().unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), legacy);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn durable_write_keeps_redacted_backup_and_recovers_corruption() {
        let path = temporary_path("durability");
        let mut config = Config::default();
        config.save_to(&path).unwrap();
        config.ui_theme = Some("light".into());
        config.save_to(&path).unwrap();
        assert!(backup_path(&path).exists());
        std::fs::write(&path, "this is not toml = [").unwrap();
        let recovered = Config::load_from_with_credentials(&path, &manager()).unwrap();
        assert!(recovered.recovery_notice.is_some());
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(backup_path(&path)).ok();
    }

    #[test]
    fn custom_domains_are_exact_and_belong_to_zone() {
        assert_eq!(
            validate_hostname("Sub.Example.com.").unwrap(),
            "sub.example.com"
        );
        assert!(validate_hostname("*.example.com").is_err());
        let domain = DomainBinding {
            domain_id: "domain-id".into(),
            hostname: "sub.example.com".into(),
            zone_id: "zone-id".into(),
            zone_name: "example.com".into(),
            service: "sub-one".into(),
            primary: true,
            status: DomainStatus::Ready,
        };
        domain.validate().unwrap();
    }

    #[test]
    fn unix_utc_formatting() {
        assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_utc(1_787_184_000), "2026-08-20T00:00:00Z");
    }
}
