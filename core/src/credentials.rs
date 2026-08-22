//! Secure local credential storage.
//!
//! Normal references resolve through the platform credential manager.  An
//! explicit `env:VARIABLE_NAME` reference is available for headless systems;
//! there is deliberately no plaintext-file fallback.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, ZeroizeOnDrop};

const SERVICE: &str = "dev.veilweave.credentials";
const KEYRING_PREFIX: &str = "keyring:";
const ENV_PREFIX: &str = "env:";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

pub trait CredentialStore: Send + Sync {
    fn set(&self, key: &str, value: &str) -> Result<()>;
    fn get(&self, key: &str) -> Result<SecretValue>;
    fn delete(&self, key: &str) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct SystemCredentialStore;

impl SystemCredentialStore {
    pub fn available() -> Result<()> {
        keyring::Entry::new(SERVICE, "availability-check")
            .map(|_| ())
            .context("platform credential store is unavailable")
    }

    fn entry(key: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, key)
            .with_context(|| format!("open platform credential entry {key:?}"))
    }
}

impl CredentialStore for SystemCredentialStore {
    fn set(&self, key: &str, value: &str) -> Result<()> {
        Self::entry(key)?
            .set_password(value)
            .with_context(|| format!("write platform credential {key:?}"))
    }

    fn get(&self, key: &str) -> Result<SecretValue> {
        Self::entry(key)?
            .get_password()
            .map(SecretValue::new)
            .with_context(|| format!("read platform credential {key:?}"))
    }

    fn delete(&self, key: &str) -> Result<()> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error).with_context(|| format!("delete platform credential {key:?}")),
        }
    }
}

#[derive(Clone)]
pub struct CredentialManager {
    store: Arc<dyn CredentialStore>,
}

impl fmt::Debug for CredentialManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialManager")
            .field("store", &"[secure store]")
            .finish()
    }
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::system()
    }
}

impl CredentialManager {
    pub fn system() -> Self {
        Self {
            store: Arc::new(SystemCredentialStore),
        }
    }

    pub fn with_store(store: Arc<dyn CredentialStore>) -> Self {
        Self { store }
    }

    /// Process-lifetime overlay used for an explicit CLI proxy credential.
    /// All other references fall through to the OS credential store.
    pub fn system_with_ephemeral(reference: &str, value: &str) -> Result<Self> {
        let key = keyring_key(reference)?.to_string();
        if value.is_empty() {
            bail!("refusing to install an empty ephemeral credential");
        }
        let mut values = HashMap::new();
        values.insert(key, value.to_string());
        Ok(Self {
            store: Arc::new(EphemeralOverlayStore {
                values: Mutex::new(values),
                fallback: SystemCredentialStore,
            }),
        })
    }

    pub fn keyring_reference(key: &str) -> String {
        format!("{KEYRING_PREFIX}{key}")
    }

    pub fn environment_reference(variable: &str) -> Result<String> {
        validate_environment_name(variable)?;
        Ok(format!("{ENV_PREFIX}{variable}"))
    }

    pub fn store_verified(&self, reference: &str, value: &str) -> Result<()> {
        if value.is_empty() {
            bail!("refusing to store an empty credential");
        }
        let key = keyring_key(reference)?;
        self.store.set(key, value)?;
        let verified = self.store.get(key)?;
        if verified.expose() != value {
            bail!("credential verification failed for {reference:?}");
        }
        Ok(())
    }

    pub fn resolve(&self, reference: &str) -> Result<SecretValue> {
        if let Some(variable) = reference.strip_prefix(ENV_PREFIX) {
            validate_environment_name(variable)?;
            return std::env::var(variable)
                .map(SecretValue::new)
                .with_context(|| {
                    format!("required credential environment variable {variable} is not set")
                });
        }
        self.store.get(keyring_key(reference)?)
    }

    pub fn delete(&self, reference: &str) -> Result<()> {
        if reference.starts_with(ENV_PREFIX) {
            bail!("environment-backed credentials cannot be deleted by Veilweave");
        }
        self.store.delete(keyring_key(reference)?)
    }
}

struct EphemeralOverlayStore {
    values: Mutex<HashMap<String, String>>,
    fallback: SystemCredentialStore,
}

impl fmt::Debug for EphemeralOverlayStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EphemeralOverlayStore([REDACTED])")
    }
}

impl CredentialStore for EphemeralOverlayStore {
    fn set(&self, key: &str, value: &str) -> Result<()> {
        self.values
            .lock()
            .expect("ephemeral credential mutex")
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<SecretValue> {
        if let Some(value) = self
            .values
            .lock()
            .expect("ephemeral credential mutex")
            .get(key)
            .cloned()
        {
            return Ok(SecretValue::new(value));
        }
        self.fallback.get(key)
    }

    fn delete(&self, key: &str) -> Result<()> {
        if self
            .values
            .lock()
            .expect("ephemeral credential mutex")
            .remove(key)
            .is_some()
        {
            return Ok(());
        }
        self.fallback.delete(key)
    }
}

fn keyring_key(reference: &str) -> Result<&str> {
    let Some(key) = reference.strip_prefix(KEYRING_PREFIX) else {
        bail!(
            "invalid credential reference {reference:?}; expected keyring:<id> or env:<VARIABLE>"
        );
    };
    if key.is_empty()
        || !key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.:/".contains(character))
    {
        bail!("invalid keyring credential identifier");
    }
    Ok(key)
}

fn validate_environment_name(variable: &str) -> Result<()> {
    let valid = !variable.is_empty()
        && variable
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && variable
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        bail!("invalid credential environment variable name {variable:?}");
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct MemoryCredentialStore {
    values: Mutex<HashMap<String, String>>,
}

impl CredentialStore for MemoryCredentialStore {
    fn set(&self, key: &str, value: &str) -> Result<()> {
        self.values
            .lock()
            .expect("memory credential mutex")
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<SecretValue> {
        self.values
            .lock()
            .expect("memory credential mutex")
            .get(key)
            .cloned()
            .map(SecretValue::new)
            .with_context(|| format!("credential {key:?} is not available"))
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.values
            .lock()
            .expect("memory credential mutex")
            .remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_round_trip_without_debug_leaks() {
        let manager = CredentialManager::with_store(Arc::new(MemoryCredentialStore::default()));
        let reference = CredentialManager::keyring_reference("proxy/default");
        manager
            .store_verified(&reference, "super-secret-password")
            .unwrap();
        let secret = manager.resolve(&reference).unwrap();
        assert_eq!(secret.expose(), "super-secret-password");
        assert!(!format!("{secret:?}").contains("super-secret-password"));
        assert!(!format!("{manager:?}").contains("super-secret-password"));
        manager.delete(&reference).unwrap();
        assert!(manager.resolve(&reference).is_err());
    }

    #[test]
    fn invalid_or_plaintext_references_are_rejected() {
        let manager = CredentialManager::with_store(Arc::new(MemoryCredentialStore::default()));
        assert!(manager.resolve("plaintext-secret").is_err());
        assert!(CredentialManager::environment_reference("bad-name").is_err());
    }
}
