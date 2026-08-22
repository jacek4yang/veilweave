//! Application-wide HTTP transport policy.
//!
//! A `NetworkManager` owns immutable client generations. Reconfiguration
//! builds generation N+1 completely before atomically swapping it in; existing
//! requests may finish on N while all new operations use N+1.

use crate::credentials::CredentialManager;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 45;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    #[default]
    Direct,
    System,
    Socks5,
    HttpProxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HttpProxyScheme {
    #[default]
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub credential_ref: Option<String>,
    #[serde(default = "default_remote_dns")]
    pub remote_dns: bool,
    #[serde(default)]
    pub allow_direct_fallback: bool,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default)]
    pub http_scheme: HttpProxyScheme,
}

impl fmt::Display for ProxyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub mode: NetworkMode,
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,
    #[serde(default)]
    pub bypass: Vec<String>,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Direct,
            proxy: None,
            bypass: Vec::new(),
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
        }
    }
}

impl NetworkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.request_timeout_secs == 0 || self.request_timeout_secs > 600 {
            bail!("network request timeout must be between 1 and 600 seconds");
        }
        match self.mode {
            NetworkMode::Direct | NetworkMode::System => {
                if self.proxy.is_some() {
                    bail!("direct/system network mode must not include an explicit proxy");
                }
            }
            NetworkMode::Socks5 | NetworkMode::HttpProxy => {
                let proxy = self
                    .proxy
                    .as_ref()
                    .context("explicit proxy settings are missing")?;
                validate_proxy(proxy)?;
            }
        }
        for entry in &self.bypass {
            if entry.trim().is_empty() || entry.chars().any(char::is_whitespace) {
                bail!("invalid empty or whitespace-containing proxy bypass entry");
            }
        }
        Ok(())
    }

    pub fn summary(&self) -> NetworkSummary {
        NetworkSummary {
            mode: self.mode,
            proxy_endpoint: self.proxy.as_ref().map(ToString::to_string),
            remote_dns: self.proxy.as_ref().map(|proxy| proxy.remote_dns),
            allow_direct_fallback: self.proxy.as_ref().map(|proxy| proxy.allow_direct_fallback),
            bypass: self.bypass.clone(),
        }
    }
}

fn default_remote_dns() -> bool {
    true
}

fn default_connect_timeout() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_SECS
}

fn default_request_timeout() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECS
}

fn validate_proxy(proxy: &ProxyConfig) -> Result<()> {
    let host = proxy.host.trim();
    if host.is_empty()
        || host.contains("//")
        || host.contains('@')
        || host.contains('/')
        || host.contains(char::is_whitespace)
    {
        bail!("proxy host must be a hostname or IP address without a URL scheme");
    }
    if proxy.port == 0 {
        bail!("proxy port must be between 1 and 65535");
    }
    if proxy.connect_timeout_secs == 0 || proxy.connect_timeout_secs > 120 {
        bail!("proxy connection timeout must be between 1 and 120 seconds");
    }
    if proxy.username.as_deref().is_some_and(str::is_empty) {
        bail!("proxy username cannot be empty when configured");
    }
    if proxy.credential_ref.is_some() != proxy.username.is_some() {
        bail!("proxy username and secure credential reference must be configured together");
    }
    if proxy.allow_direct_fallback {
        bail!(
            "direct fallback is not supported: explicit proxy mode is fail-closed for Cloudflare and updater traffic"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkSummary {
    pub mode: NetworkMode,
    pub proxy_endpoint: Option<String>,
    pub remote_dns: Option<bool>,
    pub allow_direct_fallback: Option<bool>,
    pub bypass: Vec<String>,
}

#[derive(Clone)]
pub struct NetworkSnapshot {
    generation: u64,
    config: NetworkConfig,
    client: reqwest::Client,
    /// Exact explicit proxy URL used to build `client`, retained only in this
    /// immutable generation so updater metadata and package requests cannot
    /// observe a mixed configuration during a concurrent policy swap.
    updater_proxy_url: Option<reqwest::Url>,
}

impl fmt::Debug for NetworkSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkSnapshot")
            .field("generation", &self.generation)
            .field("summary", &self.config.summary())
            .finish()
    }
}

impl NetworkSnapshot {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    pub fn updater_proxy_url(&self) -> Option<reqwest::Url> {
        self.updater_proxy_url.clone()
    }
}

#[derive(Clone)]
pub struct NetworkManager {
    active: Arc<RwLock<Arc<NetworkSnapshot>>>,
    credentials: CredentialManager,
    next_generation: Arc<AtomicU64>,
}

/// Fully built replacement generation. Construction may fail; installation is
/// an infallible pointer swap, which lets callers persist configuration only
/// after every fallible transport/credential check has completed.
pub struct PreparedNetworkSnapshot(Arc<NetworkSnapshot>);

/// Small shared adapter for non-Tauri update consumers and transport tests.
/// Desktop builds configure the Tauri updater from the same snapshot/proxy;
/// signature verification remains the updater plugin's responsibility.
#[derive(Clone, Debug)]
pub struct UpdaterNetworkAdapter {
    network: NetworkManager,
}

impl UpdaterNetworkAdapter {
    pub fn new(network: NetworkManager) -> Self {
        Self { network }
    }

    pub async fn metadata<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        self.network
            .snapshot()
            .client()
            .get(url)
            .send()
            .await
            .context("retrieve update metadata")?
            .error_for_status()
            .context("update metadata HTTP failure")?
            .json()
            .await
            .context("parse update metadata")
    }

    pub async fn package(&self, url: &str) -> Result<Vec<u8>> {
        Ok(self
            .network
            .snapshot()
            .client()
            .get(url)
            .send()
            .await
            .context("download update package")?
            .error_for_status()
            .context("update package HTTP failure")?
            .bytes()
            .await
            .context("read update package")?
            .to_vec())
    }
}

impl fmt::Debug for NetworkManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkManager")
            .field("active", &self.snapshot())
            .finish()
    }
}

impl NetworkManager {
    pub fn new(config: NetworkConfig, credentials: CredentialManager) -> Result<Self> {
        let snapshot = build_snapshot(1, config, &credentials)?;
        Ok(Self {
            active: Arc::new(RwLock::new(Arc::new(snapshot))),
            credentials,
            next_generation: Arc::new(AtomicU64::new(2)),
        })
    }

    pub fn direct() -> Result<Self> {
        Self::new(NetworkConfig::default(), CredentialManager::system())
    }

    pub fn snapshot(&self) -> Arc<NetworkSnapshot> {
        self.active.read().expect("network manager lock").clone()
    }

    pub fn replace(&self, config: NetworkConfig) -> Result<u64> {
        let prepared = self.prepare_replacement(config)?;
        Ok(self.install_prepared(prepared))
    }

    pub fn prepare_replacement(&self, config: NetworkConfig) -> Result<PreparedNetworkSnapshot> {
        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        let snapshot = Arc::new(build_snapshot(generation, config, &self.credentials)?);
        Ok(PreparedNetworkSnapshot(snapshot))
    }

    pub fn install_prepared(&self, prepared: PreparedNetworkSnapshot) -> u64 {
        let generation = prepared.0.generation;
        *self.active.write().expect("network manager lock") = prepared.0;
        generation
    }

    /// Construct the same ephemeral proxy URL used by the Tauri updater for
    /// both metadata and package downloads. Credentials never enter config or
    /// a Debug representation.
    pub fn updater_proxy_url(&self) -> Result<Option<reqwest::Url>> {
        Ok(self.snapshot().updater_proxy_url())
    }

    pub async fn test_connection(&self) -> NetworkTestReport {
        let snapshot = self.snapshot();
        let mut checks = Vec::new();

        if let Some(proxy) = &snapshot.config.proxy {
            let started = Instant::now();
            let address = format!("{}:{}", bracket_ipv6(&proxy.host), proxy.port);
            let result = tokio::time::timeout(
                Duration::from_secs(proxy.connect_timeout_secs),
                tokio::net::TcpStream::connect(&address),
            )
            .await;
            checks.push(match result {
                Ok(Ok(_)) => NetworkCheck::ok("proxy-server", started.elapsed()),
                Ok(Err(error)) => NetworkCheck::failed(
                    "proxy-server",
                    started.elapsed(),
                    "proxy-unreachable",
                    format!("proxy {address} is unreachable: {error}; direct fallback is disabled"),
                ),
                Err(_) => NetworkCheck::failed(
                    "proxy-server",
                    started.elapsed(),
                    "tcp-timeout",
                    format!("connection to proxy {address} timed out; direct fallback is disabled"),
                ),
            });
            if !checks.last().is_some_and(|check| check.ok) {
                return NetworkTestReport {
                    generation: snapshot.generation,
                    summary: snapshot.config.summary(),
                    checks,
                };
            }
        }

        for (name, url) in [
            ("https-tls", "https://www.cloudflare.com/cdn-cgi/trace"),
            (
                "cloudflare-api",
                "https://api.cloudflare.com/client/v4/user/tokens/verify",
            ),
            (
                "github-updater",
                "https://github.com/jacek4yang/veilweave/releases/latest/download/latest.json",
            ),
        ] {
            checks.push(check_http(&snapshot, name, url).await);
        }

        NetworkTestReport {
            generation: snapshot.generation,
            summary: snapshot.config.summary(),
            checks,
        }
    }
}

fn build_snapshot(
    generation: u64,
    config: NetworkConfig,
    credentials: &CredentialManager,
) -> Result<NetworkSnapshot> {
    build_snapshot_with_root(generation, config, credentials, None)
}

fn build_snapshot_with_root(
    generation: u64,
    config: NetworkConfig,
    credentials: &CredentialManager,
    extra_root: Option<reqwest::Certificate>,
) -> Result<NetworkSnapshot> {
    config.validate()?;
    let connect_timeout = config
        .proxy
        .as_ref()
        .map_or(DEFAULT_CONNECT_TIMEOUT_SECS, |proxy| {
            proxy.connect_timeout_secs
        });
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!("veilweave/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(connect_timeout))
        .timeout(Duration::from_secs(config.request_timeout_secs));
    if let Some(certificate) = extra_root {
        builder = builder.add_root_certificate(certificate);
    }

    let updater_proxy_url = proxy_url(&config, credentials)?;
    match config.mode {
        NetworkMode::Direct => builder = builder.no_proxy(),
        NetworkMode::System => {}
        NetworkMode::Socks5 | NetworkMode::HttpProxy => {
            // Disable system/environment interception before adding the one
            // explicit all-destinations policy. reqwest never falls back from
            // a failed explicit proxy to a direct connection.
            builder = builder.no_proxy();
            let url = updater_proxy_url.clone().context("proxy URL is missing")?;
            let mut proxy = reqwest::Proxy::all(url).context("build explicit proxy policy")?;
            if !config.bypass.is_empty() {
                proxy = proxy.no_proxy(reqwest::NoProxy::from_string(&config.bypass.join(",")));
            }
            builder = builder.proxy(proxy);
        }
    }

    Ok(NetworkSnapshot {
        generation,
        config,
        client: builder.build().context("build network client")?,
        updater_proxy_url,
    })
}

fn proxy_url(
    config: &NetworkConfig,
    credentials: &CredentialManager,
) -> Result<Option<reqwest::Url>> {
    let Some(proxy) = &config.proxy else {
        return Ok(None);
    };
    let scheme = match config.mode {
        NetworkMode::Socks5 if proxy.remote_dns => "socks5h",
        NetworkMode::Socks5 => "socks5",
        NetworkMode::HttpProxy if proxy.http_scheme == HttpProxyScheme::Https => "https",
        NetworkMode::HttpProxy => "http",
        NetworkMode::Direct | NetworkMode::System => return Ok(None),
    };
    let host = bracket_ipv6(&proxy.host);
    let mut url = reqwest::Url::parse(&format!("{scheme}://{host}:{}", proxy.port))
        .context("construct proxy URL")?;
    if let (Some(username), Some(reference)) = (&proxy.username, &proxy.credential_ref) {
        let password = credentials.resolve(reference)?;
        url.set_username(username)
            .map_err(|_| anyhow::anyhow!("invalid proxy username"))?;
        url.set_password(Some(password.expose()))
            .map_err(|_| anyhow::anyhow!("invalid proxy password"))?;
    }
    Ok(Some(url))
}

fn bracket_ipv6(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]"),
        _ => host.to_string(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkTestReport {
    pub generation: u64,
    pub summary: NetworkSummary,
    pub checks: Vec<NetworkCheck>,
}

impl NetworkTestReport {
    pub fn successful(&self) -> bool {
        self.checks.iter().all(|check| check.ok)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkCheck {
    pub name: String,
    pub ok: bool,
    pub latency_ms: u128,
    pub category: Option<String>,
    pub detail: String,
}

impl NetworkCheck {
    fn ok(name: &str, elapsed: Duration) -> Self {
        Self {
            name: name.to_string(),
            ok: true,
            latency_ms: elapsed.as_millis(),
            category: None,
            detail: "reachable".into(),
        }
    }

    fn failed(name: &str, elapsed: Duration, category: &str, detail: String) -> Self {
        Self {
            name: name.to_string(),
            ok: false,
            latency_ms: elapsed.as_millis(),
            category: Some(category.to_string()),
            detail,
        }
    }
}

async fn check_http(snapshot: &NetworkSnapshot, name: &str, url: &str) -> NetworkCheck {
    let started = Instant::now();
    match snapshot.client.get(url).send().await {
        Ok(response) if response.status().as_u16() < 500 => NetworkCheck {
            name: name.to_string(),
            ok: true,
            latency_ms: started.elapsed().as_millis(),
            category: None,
            detail: format!("HTTP {}", response.status()),
        },
        Ok(response) => NetworkCheck::failed(
            name,
            started.elapsed(),
            "http-failure",
            format!("remote endpoint returned HTTP {}", response.status()),
        ),
        Err(error) => {
            let category = if error.is_timeout() {
                "tcp-timeout"
            } else if error.is_connect() {
                "proxy-or-connect-failure"
            } else if error.is_request() {
                "request-failure"
            } else {
                "network-failure"
            };
            NetworkCheck::failed(name, started.elapsed(), category, error.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::MemoryCredentialStore;
    use serde::Deserialize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn credentials() -> CredentialManager {
        CredentialManager::with_store(Arc::new(MemoryCredentialStore::default()))
    }

    #[test]
    fn explicit_socks_defaults_to_remote_dns_and_fail_closed() {
        let config: NetworkConfig = toml::from_str(
            r#"
mode = "socks5"
[proxy]
host = "127.0.0.1"
port = 10808
"#,
        )
        .unwrap();
        assert!(config.proxy.as_ref().unwrap().remote_dns);
        assert!(!config.proxy.as_ref().unwrap().allow_direct_fallback);
        let manager = NetworkManager::new(config, credentials()).unwrap();
        let url = manager.updater_proxy_url().unwrap().unwrap();
        assert_eq!(url.scheme(), "socks5h");
        assert_eq!(url.host_str(), Some("127.0.0.1"));

        let mut unsupported = manager.snapshot().config().clone();
        unsupported.proxy.as_mut().unwrap().allow_direct_fallback = true;
        assert!(NetworkManager::new(unsupported, credentials()).is_err());
    }

    #[test]
    fn direct_and_system_modes_build_distinct_policy_snapshots() {
        let direct = NetworkManager::new(NetworkConfig::default(), credentials()).unwrap();
        let system = NetworkManager::new(
            NetworkConfig {
                mode: NetworkMode::System,
                ..NetworkConfig::default()
            },
            credentials(),
        )
        .unwrap();
        assert_eq!(direct.snapshot().config().mode, NetworkMode::Direct);
        assert_eq!(system.snapshot().config().mode, NetworkMode::System);
        assert!(direct.updater_proxy_url().unwrap().is_none());
        assert!(system.updater_proxy_url().unwrap().is_none());
    }

    #[test]
    fn proxy_password_is_securely_resolved_and_redacted() {
        let credentials = credentials();
        let reference = CredentialManager::keyring_reference("proxy/default");
        credentials
            .store_verified(&reference, "never-log-this")
            .unwrap();
        let config = NetworkConfig {
            mode: NetworkMode::Socks5,
            proxy: Some(ProxyConfig {
                host: "localhost".into(),
                port: 1080,
                username: Some("alice".into()),
                credential_ref: Some(reference),
                remote_dns: false,
                allow_direct_fallback: false,
                connect_timeout_secs: 5,
                http_scheme: HttpProxyScheme::Http,
            }),
            bypass: vec![],
            request_timeout_secs: 30,
        };
        let manager = NetworkManager::new(config, credentials).unwrap();
        assert!(!format!("{manager:?}").contains("never-log-this"));
        let old_snapshot = manager.snapshot();
        let url = old_snapshot.updater_proxy_url().unwrap();
        assert_eq!(url.username(), "alice");
        assert_eq!(url.password(), Some("never-log-this"));
        manager.replace(NetworkConfig::default()).unwrap();
        assert!(manager.snapshot().updater_proxy_url().is_none());
        assert_eq!(
            old_snapshot.updater_proxy_url().unwrap().password(),
            Some("never-log-this")
        );
    }

    #[test]
    fn reconfiguration_swaps_immutable_generations() {
        let manager = NetworkManager::new(NetworkConfig::default(), credentials()).unwrap();
        let old = manager.snapshot();
        let prepared = manager
            .prepare_replacement(NetworkConfig {
                mode: NetworkMode::System,
                ..NetworkConfig::default()
            })
            .unwrap();
        assert_eq!(manager.snapshot().config().mode, NetworkMode::Direct);
        let generation = manager.install_prepared(prepared);
        let new = manager.snapshot();
        assert_eq!(old.generation(), 1);
        assert_eq!(generation, 2);
        assert_eq!(new.generation(), 2);
        assert_eq!(old.config().mode, NetworkMode::Direct);
        assert_eq!(new.config().mode, NetworkMode::System);
    }

    #[tokio::test]
    async fn dead_explicit_proxy_does_not_fall_back_direct() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let manager = NetworkManager::new(
            NetworkConfig {
                mode: NetworkMode::Socks5,
                proxy: Some(ProxyConfig {
                    host: "127.0.0.1".into(),
                    port,
                    username: None,
                    credential_ref: None,
                    remote_dns: true,
                    allow_direct_fallback: false,
                    connect_timeout_secs: 1,
                    http_scheme: HttpProxyScheme::Http,
                }),
                bypass: vec![],
                request_timeout_secs: 2,
            },
            credentials(),
        )
        .unwrap();
        let error = manager
            .snapshot()
            .client()
            .get("https://api.cloudflare.com/client/v4/user/tokens/verify")
            .send()
            .await
            .expect_err("dead proxy must fail closed");
        assert!(error.is_connect() || error.is_timeout());
    }

    async fn destination_server() -> (std::net::SocketAddr, Arc<AtomicU64>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicU64::new(0));
        let count = requests.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let count = count.clone();
                tokio::spawn(async move {
                    let mut request = vec![0u8; 4096];
                    let length = stream.read(&mut request).await.unwrap_or(0);
                    count.fetch_add(1, Ordering::SeqCst);
                    let request = String::from_utf8_lossy(&request[..length]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let (content_type, body) = if path.contains("tokens/verify") {
                        (
                            "application/json",
                            r#"{"success":true,"errors":[],"result":{"status":"active"}}"#,
                        )
                    } else if path.contains("latest.json") {
                        (
                            "application/json",
                            r#"{"version":"2.0.0","url":"http://only-through-proxy.invalid/package.bin"}"#,
                        )
                    } else if path.contains("package.bin") {
                        ("application/octet-stream", "signed-package-bytes")
                    } else {
                        ("text/plain", "ok")
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (address, requests)
    }

    async fn tls_destination_server() -> (std::net::SocketAddr, reqwest::Certificate) {
        use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
        use tokio_rustls::rustls::ServerConfig;
        use tokio_rustls::TlsAcceptor;

        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certified =
            rcgen::generate_simple_self_signed(vec!["only-through-proxy.invalid".into()]).unwrap();
        let certificate_der = certified.cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], private_key.into())
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut request = [0u8; 2048];
                    if stream.read(&mut request).await.is_err() {
                        return;
                    }
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nsecure-route",
                        )
                        .await;
                });
            }
        });
        (
            address,
            reqwest::Certificate::from_der(certificate_der.as_ref()).unwrap(),
        )
    }

    async fn socks_server(
        destination: std::net::SocketAddr,
        authentication: Option<(&'static str, &'static str)>,
    ) -> (
        u16,
        Arc<tokio::sync::Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let destinations = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let observed = destinations.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                let observed = observed.clone();
                tokio::spawn(async move {
                    let mut greeting = [0u8; 2];
                    if inbound.read_exact(&mut greeting).await.is_err() || greeting[0] != 5 {
                        return;
                    }
                    let mut methods = vec![0u8; greeting[1] as usize];
                    if inbound.read_exact(&mut methods).await.is_err() {
                        return;
                    }
                    let method = if authentication.is_some() { 2 } else { 0 };
                    if !methods.contains(&method) || inbound.write_all(&[5, method]).await.is_err()
                    {
                        return;
                    }
                    if let Some((expected_user, expected_password)) = authentication {
                        let mut header = [0u8; 2];
                        if inbound.read_exact(&mut header).await.is_err() || header[0] != 1 {
                            return;
                        }
                        let mut user = vec![0u8; header[1] as usize];
                        if inbound.read_exact(&mut user).await.is_err() {
                            return;
                        }
                        let mut password_length = [0u8; 1];
                        if inbound.read_exact(&mut password_length).await.is_err() {
                            return;
                        }
                        let mut password = vec![0u8; password_length[0] as usize];
                        if inbound.read_exact(&mut password).await.is_err() {
                            return;
                        }
                        let valid = user == expected_user.as_bytes()
                            && password == expected_password.as_bytes();
                        let _ = inbound.write_all(&[1, if valid { 0 } else { 1 }]).await;
                        if !valid {
                            return;
                        }
                    }
                    let mut request = [0u8; 4];
                    if inbound.read_exact(&mut request).await.is_err()
                        || request[0] != 5
                        || request[1] != 1
                    {
                        return;
                    }
                    let host = match request[3] {
                        1 => {
                            let mut octets = [0u8; 4];
                            if inbound.read_exact(&mut octets).await.is_err() {
                                return;
                            }
                            std::net::Ipv4Addr::from(octets).to_string()
                        }
                        3 => {
                            let mut length = [0u8; 1];
                            if inbound.read_exact(&mut length).await.is_err() {
                                return;
                            }
                            let mut name = vec![0u8; length[0] as usize];
                            if inbound.read_exact(&mut name).await.is_err() {
                                return;
                            }
                            String::from_utf8_lossy(&name).to_string()
                        }
                        4 => {
                            let mut octets = [0u8; 16];
                            if inbound.read_exact(&mut octets).await.is_err() {
                                return;
                            }
                            std::net::Ipv6Addr::from(octets).to_string()
                        }
                        _ => return,
                    };
                    let mut target_port = [0u8; 2];
                    if inbound.read_exact(&mut target_port).await.is_err() {
                        return;
                    }
                    observed.lock().await.push(host);
                    let Ok(mut outbound) = tokio::net::TcpStream::connect(destination).await else {
                        let _ = inbound.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                        return;
                    };
                    if inbound
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                });
            }
        });
        (port, destinations, task)
    }

    fn socks_manager(
        port: u16,
        remote_dns: bool,
        credentials: CredentialManager,
        username: Option<&str>,
    ) -> NetworkManager {
        NetworkManager::new(
            NetworkConfig {
                mode: NetworkMode::Socks5,
                proxy: Some(ProxyConfig {
                    host: "127.0.0.1".into(),
                    port,
                    username: username.map(str::to_string),
                    credential_ref: username
                        .map(|_| CredentialManager::keyring_reference("proxy/test")),
                    remote_dns,
                    allow_direct_fallback: false,
                    connect_timeout_secs: 2,
                    http_scheme: HttpProxyScheme::Http,
                }),
                bypass: Vec::new(),
                request_timeout_secs: 3,
            },
            credentials,
        )
        .unwrap()
    }

    fn socks_manager_with_root(port: u16, root: reqwest::Certificate) -> NetworkManager {
        let credentials = credentials();
        let config = NetworkConfig {
            mode: NetworkMode::Socks5,
            proxy: Some(ProxyConfig {
                host: "127.0.0.1".into(),
                port,
                username: None,
                credential_ref: None,
                remote_dns: true,
                allow_direct_fallback: false,
                connect_timeout_secs: 2,
                http_scheme: HttpProxyScheme::Http,
            }),
            bypass: Vec::new(),
            request_timeout_secs: 3,
        };
        let snapshot = build_snapshot_with_root(1, config, &credentials, Some(root)).unwrap();
        NetworkManager {
            active: Arc::new(RwLock::new(Arc::new(snapshot))),
            credentials,
            next_generation: Arc::new(AtomicU64::new(2)),
        }
    }

    #[tokio::test]
    async fn socks5h_routes_an_unresolvable_destination_and_uses_remote_dns() {
        let (destination, _) = destination_server().await;
        let (port, observed, task) = socks_server(destination, None).await;
        let manager = socks_manager(port, true, credentials(), None);
        let response = manager
            .snapshot()
            .client()
            .get("http://only-through-proxy.invalid/probe")
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "ok");
        assert_eq!(
            observed.lock().await.as_slice(),
            &["only-through-proxy.invalid"]
        );
        task.abort();
    }

    #[tokio::test]
    async fn https_tls_handshake_and_http_request_traverse_socks5h() {
        let (destination, root) = tls_destination_server().await;
        let (port, observed, task) = socks_server(destination, None).await;
        let manager = socks_manager_with_root(port, root);
        let response = manager
            .snapshot()
            .client()
            .get("https://only-through-proxy.invalid/secure")
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "secure-route");
        assert_eq!(
            observed.lock().await.as_slice(),
            &["only-through-proxy.invalid"]
        );
        task.abort();
    }

    #[tokio::test]
    async fn socks5_username_password_authentication_succeeds_and_rejects_invalid_password() {
        let (destination, _) = destination_server().await;
        let (port, _, task) = socks_server(destination, Some(("alice", "correct"))).await;
        let store = Arc::new(MemoryCredentialStore::default());
        let manager_credentials = CredentialManager::with_store(store);
        let reference = CredentialManager::keyring_reference("proxy/test");
        manager_credentials
            .store_verified(&reference, "correct")
            .unwrap();
        let manager = socks_manager(port, true, manager_credentials.clone(), Some("alice"));
        assert!(manager
            .snapshot()
            .client()
            .get("http://only-through-proxy.invalid/auth")
            .send()
            .await
            .unwrap()
            .status()
            .is_success());

        manager_credentials
            .store_verified(&reference, "wrong")
            .unwrap();
        let invalid = socks_manager(port, true, manager_credentials, Some("alice"));
        let error = invalid
            .snapshot()
            .client()
            .get("http://only-through-proxy.invalid/auth")
            .send()
            .await
            .unwrap_err();
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("wrong"));
        assert!(!rendered.contains("correct"));
        task.abort();
    }

    #[derive(Deserialize)]
    struct UpdateMetadata {
        version: String,
        url: String,
    }

    #[tokio::test]
    async fn cloudflare_and_both_updater_fetches_use_the_same_socks_transport() {
        let (destination, requests) = destination_server().await;
        let (port, observed, task) = socks_server(destination, None).await;
        let manager = socks_manager(port, true, credentials(), None);
        let cloudflare = crate::cfapi::CfClient::with_network("token", manager.clone())
            .unwrap()
            .with_api_base("http://only-through-proxy.invalid/client/v4")
            .unwrap();
        cloudflare.verify_token().await.unwrap();

        let updater = UpdaterNetworkAdapter::new(manager);
        let metadata: UpdateMetadata = updater
            .metadata("http://only-through-proxy.invalid/latest.json")
            .await
            .unwrap();
        assert_eq!(metadata.version, "2.0.0");
        assert_eq!(
            updater.package(&metadata.url).await.unwrap(),
            b"signed-package-bytes"
        );
        assert_eq!(requests.load(Ordering::SeqCst), 3);
        assert_eq!(observed.lock().await.len(), 3);
        assert!(observed
            .lock()
            .await
            .iter()
            .all(|host| host == "only-through-proxy.invalid"));
        task.abort();
    }

    #[tokio::test]
    async fn socks5_local_dns_does_not_accidentally_use_proxy_dns() {
        let (destination, _) = destination_server().await;
        let (port, observed, task) = socks_server(destination, None).await;
        let manager = socks_manager(port, false, credentials(), None);
        assert!(manager
            .snapshot()
            .client()
            .get("http://only-through-proxy.invalid/local-dns")
            .send()
            .await
            .is_err());
        assert!(observed.lock().await.is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn unresponsive_socks_handshake_honors_request_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            if let Ok((_stream, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
        let manager = NetworkManager::new(
            NetworkConfig {
                mode: NetworkMode::Socks5,
                proxy: Some(ProxyConfig {
                    host: "127.0.0.1".into(),
                    port,
                    username: None,
                    credential_ref: None,
                    remote_dns: true,
                    allow_direct_fallback: false,
                    connect_timeout_secs: 1,
                    http_scheme: HttpProxyScheme::Http,
                }),
                bypass: Vec::new(),
                request_timeout_secs: 1,
            },
            credentials(),
        )
        .unwrap();
        let error = manager
            .snapshot()
            .client()
            .get("http://only-through-proxy.invalid/timeout")
            .send()
            .await
            .unwrap_err();
        assert!(error.is_timeout());
        task.abort();
    }
}
