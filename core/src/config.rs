//! Persistent local config: Cloudflare accounts and past deployments.
//! Stored as TOML at `<platform config dir>/veilweave/config.toml`
//! (e.g. `%APPDATA%\veilweave\config.toml` on Windows). Writes are atomic-ish:
//! serialize to a `.tmp` sibling, then rename over the target.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub deployments: Vec<Deployment>,
    /// GUI language override: "zh" or "en". None = auto-detect from OS locale.
    #[serde(default)]
    pub ui_language: Option<String>,
    /// GUI theme override: "dark" or "light". None = dark.
    #[serde(default)]
    pub ui_theme: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Display label (defaults to the Cloudflare account name).
    pub name: String,
    /// API token with Workers Scripts / KV Storage / Account Settings perms.
    pub token: String,
    pub account_id: String,
    /// workers.dev subdomain, resolved once when the account is added.
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Relay => write!(f, "relay"),
            Role::Sub => write!(f, "sub"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub role: Role,
    /// Worker script name on Cloudflare.
    pub name: String,
    /// Reference to `Account.name`.
    pub account: String,
    /// Full workers.dev domain, e.g. `my-relay.user.workers.dev`.
    pub domain: String,
    /// The worker's secret: raw shared secret (plaintext) or relay/sub blob.
    pub secret: String,
    /// UTC timestamp, RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
    pub created_at: String,
    /// Present only for sub deployments.
    #[serde(default)]
    pub sub: Option<SubDetails>,
}

/// Sub-only extras: the KV namespace backing the subscription and the token
/// guarding the `/sub` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubDetails {
    pub kv_namespace_id: String,
    pub kv_title: String,
    pub kv_binding: String,
    pub subscription_token: String,
}

impl Deployment {
    /// The full subscription URL for a sub deployment.
    pub fn subscription_url(&self) -> Option<String> {
        self.sub
            .as_ref()
            .map(|s| format!("https://{}/sub?token={}", self.domain, s.subscription_token))
    }
}

impl Config {
    /// `<platform config dir>/veilweave/config.toml`.
    pub fn path() -> Result<PathBuf> {
        let dir = dirs::config_dir().context("no platform config directory")?;
        Ok(dir.join("veilweave").join("config.toml"))
    }

    /// Load from the default path; a missing file yields an empty config.
    pub fn load() -> Result<Self> {
        Self::load_from(&Self::path()?)
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("parse config at {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read config at {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        self.save_to(&path)
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let text = toml::to_string_pretty(self).context("serialize config")?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
        Ok(())
    }

    pub fn account(&self, name: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.name == name)
    }
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ` (no chrono dependency).
pub fn now_utc_string() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_utc(secs)
}

/// Unix seconds → RFC 3339 UTC. Days-to-civil algorithm by Howard Hinnant.
pub fn format_unix_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> Config {
        Config {
            ui_language: None,
            ui_theme: None,
            accounts: vec![Account {
                name: "personal".into(),
                token: "tok-abc".into(),
                account_id: "acc-123".into(),
                workers_dev_subdomain: Some("alice".into()),
            }],
            deployments: vec![
                Deployment {
                    role: Role::Relay,
                    name: "edge-worker-a1b2".into(),
                    account: "personal".into(),
                    domain: "edge-worker-a1b2.alice.workers.dev".into(),
                    secret: "raw-secret".into(),
                    created_at: "2026-08-20T12:00:00Z".into(),
                    sub: None,
                },
                Deployment {
                    role: Role::Sub,
                    name: "hub-service-c3d4".into(),
                    account: "personal".into(),
                    domain: "hub-service-c3d4.alice.workers.dev".into(),
                    secret: "raw-secret".into(),
                    created_at: "2026-08-20T12:01:00Z".into(),
                    sub: Some(SubDetails {
                        kv_namespace_id: "ns-1".into(),
                        kv_title: "hub-service-c3d4-kv".into(),
                        kv_binding: "kv_x7f2a9".into(),
                        subscription_token: "feedbeef".into(),
                    }),
                },
            ],
        }
    }

    #[test]
    fn config_toml_round_trip() {
        let cfg = sample_config();
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&text).unwrap();

        assert_eq!(back.accounts.len(), 1);
        assert_eq!(back.accounts[0].account_id, "acc-123");
        assert_eq!(back.deployments.len(), 2);
        assert_eq!(back.deployments[0].role, Role::Relay);
        let sub = &back.deployments[1];
        assert_eq!(sub.role, Role::Sub);
        assert_eq!(sub.sub.as_ref().unwrap().kv_binding, "kv_x7f2a9");
        assert_eq!(
            sub.subscription_url().unwrap(),
            "https://hub-service-c3d4.alice.workers.dev/sub?token=feedbeef"
        );
        assert!(back.deployments[0].subscription_url().is_none());
        assert_eq!(back.account("personal").unwrap().token, "tok-abc");
    }

    /// Configs written before ui_language/ui_theme existed must still load.
    #[test]
    fn config_backward_compat_without_ui_fields() {
        let text = "[[accounts]]\nname = \"a\"\ntoken = \"t\"\naccount_id = \"id\"\n";
        let cfg: Config = toml::from_str(text).unwrap();
        assert!(cfg.ui_language.is_none());
        assert!(cfg.ui_theme.is_none());
    }

    #[test]
    fn config_save_and_load_file() {
        let dir = std::env::temp_dir().join(format!("vw-config-test-{}", std::process::id()));
        let path = dir.join("config.toml");
        let cfg = sample_config();
        cfg.save_to(&path).unwrap();
        let back = Config::load_from(&path).unwrap();
        assert_eq!(back.deployments.len(), 2);
        assert!(
            !path.with_extension("toml.tmp").exists(),
            "tmp file renamed"
        );
        std::fs::remove_dir_all(&dir).ok();

        // Missing file → empty config, not an error.
        let empty = Config::load_from(&path).unwrap();
        assert!(empty.accounts.is_empty());
    }

    #[test]
    fn unix_utc_formatting() {
        assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_utc(1_787_184_000), "2026-08-20T00:00:00Z");
        assert_eq!(format_unix_utc(951_868_799), "2000-02-29T23:59:59Z");
    }
}
