use anyhow::{bail, Context};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand, ValueEnum};
use rand::{seq::SliceRandom, RngCore};
use std::net::Ipv4Addr;
use veilweave_core::util::{
    decode_blob, encode_blob, gen_raw_secret, generate_hex_id, random_kv_binding,
    random_worker_name,
};

mod codec;
mod hmac;
mod sha256;
mod wizard;

use codec::UuidCodec;

#[derive(Parser)]
#[command(name = "veilweave-tools")]
#[command(about = "Veilweave v2 deployment, recovery, and network control plane")]
struct Cli {
    /// No subcommand (e.g. double-clicking the .exe) runs `bundle` with defaults.
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a single VLESS subscription link
    GenLink {
        /// Worker address (hostname or IP)
        #[arg(long)]
        address: String,
        /// Worker port
        #[arg(long)]
        port: u16,
        /// Proxy type
        #[arg(long, value_enum)]
        r#type: ProxyType,
        /// Proxy IPv4 address (required for non-direct types)
        #[arg(long)]
        proxy_ip: Option<String>,
        /// Proxy port (default: 443 for proxyip, 1080 for socks5, 80 for http)
        #[arg(long, default_value_t = 0)]
        proxy_port: u16,
        /// TLS SNI (defaults to address)
        #[arg(long)]
        sni: Option<String>,
        /// Node display name (defaults to address)
        #[arg(long)]
        name: Option<String>,
        /// Secret key used for UUID encoding
        #[arg(long)]
        secret_key: String,
    },
    /// Generate secrets for relay + sub. Default: ONE raw random secret used
    /// as the relay's `SECRET_KEY` and in the sub's `VEILWEAVE_NODES` as
    /// `domain|<same secret>` — plaintext VLESS (`encryption=none`).
    /// `--encryption` instead prints the EXPERIMENTAL combined blob pair
    /// (UUID secret plus X25519 key material for mlkem768x25519plus).
    GenSecret {
        /// Print the EXPERIMENTAL VLESS Encryption blob pair instead of a raw
        /// secret. Warning: the encryption datapath is CPU-heavy and can
        /// exceed the Workers free plan's per-invocation CPU limit.
        #[arg(long)]
        encryption: bool,
    },
    /// Pack the prebuilt workers (shipped next to this binary in `bundle/`) into
    /// ready-to-deploy folders with randomized resource names and secret-free
    /// Wrangler configuration. No Rust toolchain or source build required.
    Bundle {
        /// Output directory for the generated deploy folders
        #[arg(long, default_value = "dist")]
        out: String,
        /// Domain of the relay worker, e.g. veilweave.<sub>.workers.dev.
        /// Defaults to "<relay-name>.<your-subdomain>.workers.dev" and is used
        /// only in the printed `wrangler secret put VEILWEAVE_NODES` guidance.
        #[arg(long)]
        relay_domain: Option<String>,
        /// Directory containing the prebuilt workers. Defaults to `bundle/`
        /// next to the executable (as shipped in the release archive).
        #[arg(long)]
        bundle_dir: Option<String>,
        /// Use the EXPERIMENTAL VLESS Encryption blob pair instead of the
        /// default plaintext (encryption=none) raw secret.
        #[arg(long)]
        encryption: bool,
    },
    /// Interactive deploy wizard: deploy the relay and sub workers directly to
    /// Cloudflare via the API — no wrangler, no Node.js required.
    Deploy {
        /// Directory containing the prebuilt workers. Defaults to `bundle/`
        /// next to the executable (as shipped in the release archive).
        #[arg(long)]
        bundle_dir: Option<String>,
        /// Apply a declarative v2 topology instead of opening the wizard.
        #[arg(long)]
        config: Option<String>,
        /// Transient network override. CLI > saved config > opted-in ALL_PROXY.
        #[arg(long)]
        proxy: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Validate and show a declarative deployment without mutating Cloudflare.
    Plan {
        #[arg(long, default_value = "veilweave.toml")]
        config: String,
        #[arg(long)]
        bundle_dir: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Apply a declarative v2 topology.
    Apply {
        #[arg(long, default_value = "veilweave.toml")]
        config: String,
        #[arg(long)]
        bundle_dir: Option<String>,
        #[arg(long)]
        proxy: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Show redacted local deployment/version status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Upload and promote embedded code while inheriting existing secrets.
    Update {
        #[arg(long)]
        deployment: String,
        #[arg(long)]
        bundle_dir: Option<String>,
        #[arg(long)]
        proxy: Option<String>,
    },
    /// Rotate a Sub subscription token without changing relay-node secrets.
    RotateToken {
        #[arg(long)]
        deployment: String,
        #[arg(long)]
        bundle_dir: Option<String>,
        #[arg(long)]
        proxy: Option<String>,
    },
    /// Restore a deployment's previous known-good Worker version.
    Rollback {
        #[arg(long)]
        deployment: String,
        #[arg(long)]
        proxy: Option<String>,
    },
    /// Structured local, network, Cloudflare, credential, and bundle checks.
    Doctor {
        #[arg(long)]
        bundle_dir: Option<String>,
        #[arg(long)]
        proxy: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Discover remote Workers without attempting to read Cloudflare secrets.
    Recover {
        #[arg(long)]
        account: String,
        /// Re-link one secure v2 Worker into local metadata.
        #[arg(long)]
        adopt_worker: Option<String>,
        /// Existing keyring:... or env:... reference for the Worker's deployed secret.
        #[arg(long, requires = "adopt_worker")]
        worker_secret_ref: Option<String>,
        /// Existing reference for the matching relay node/signing secret.
        #[arg(long, requires = "adopt_worker")]
        node_secret_ref: Option<String>,
        /// Existing reference for a Sub subscription token.
        #[arg(long, requires = "adopt_worker")]
        subscription_token_ref: Option<String>,
        #[arg(
            long,
            value_enum,
            default_value = "workers-dev",
            requires = "adopt_worker"
        )]
        primary: PrimaryEndpointArg,
        #[arg(long)]
        proxy: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect Worker Custom Domains for one configured account.
    Domain {
        #[arg(long)]
        account: String,
        #[arg(long)]
        proxy: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Configure saved application-wide networking.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Test the saved or transient proxy policy.
    Proxy {
        #[command(subcommand)]
        command: ProxyCommand,
    },
    /// Manage existing deployments: list them, re-show a subscription URL, or
    /// delete a worker (and its KV namespace) from Cloudflare.
    Manage,
    /// Build or validate the canonical Worker runtime bundle used by release
    /// packaging, the CLI, and the desktop app.
    WorkerBundle {
        #[command(subcommand)]
        command: WorkerBundleCommand,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    Network {
        #[arg(long, value_enum)]
        mode: NetworkModeArg,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long, default_value_t = true)]
        remote_dns: bool,
        #[arg(long, value_delimiter = ',')]
        bypass: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ProxyCommand {
    Test {
        #[arg(long)]
        proxy: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum NetworkModeArg {
    Direct,
    System,
    Socks5,
    HttpProxy,
}

#[derive(Clone, Copy, ValueEnum)]
enum PrimaryEndpointArg {
    WorkersDev,
    CustomDomain,
}

impl From<PrimaryEndpointArg> for veilweave_core::config::PrimaryEndpoint {
    fn from(value: PrimaryEndpointArg) -> Self {
        match value {
            PrimaryEndpointArg::WorkersDev => Self::WorkersDev,
            PrimaryEndpointArg::CustomDomain => Self::CustomDomain,
        }
    }
}

struct RecoverOptions {
    account: String,
    adopt_worker: Option<String>,
    worker_secret_ref: Option<String>,
    node_secret_ref: Option<String>,
    subscription_token_ref: Option<String>,
    primary: PrimaryEndpointArg,
}

#[derive(Subcommand)]
enum WorkerBundleCommand {
    /// Convert worker-build output into a deterministic manifest-backed bundle.
    Prepare {
        #[arg(long, value_enum)]
        role: WorkerRoleArg,
        #[arg(long)]
        source: String,
        #[arg(long)]
        out: String,
    },
    /// Validate every module, type, size, and hash in a shipped bundle.
    Validate {
        #[arg(long, value_enum)]
        role: WorkerRoleArg,
        #[arg(long)]
        dir: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum WorkerRoleArg {
    Relay,
    Sub,
}

impl From<WorkerRoleArg> for veilweave_core::bundle::WorkerRole {
    fn from(value: WorkerRoleArg) -> Self {
        match value {
            WorkerRoleArg::Relay => Self::Relay,
            WorkerRoleArg::Sub => Self::Sub,
        }
    }
}

#[derive(Clone, ValueEnum)]
enum ProxyType {
    Direct,
    Proxyip,
    Socks5,
    Http,
}

fn main() {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        // Double-click (no subcommand): point at the deploy wizard. The
        // graphical deployer is the separate Tauri app.
        println!("veilweave-tools — 部署请运行 / to deploy, run:");
        println!("    veilweave-tools deploy");
        println!();
        println!("更多命令 / more commands: veilweave-tools --help");
        pause_before_exit();
        return;
    };
    let pause = matches!(command, Commands::Bundle { .. });
    let result = run(command);
    if pause {
        pause_before_exit();
    }
    if let Err(error) = result {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::GenLink {
            address,
            port,
            r#type,
            proxy_ip,
            proxy_port,
            sni,
            name,
            secret_key,
        } => {
            // SECRET_KEY may be a combined blob (UUID secret + X25519 key) or a
            // legacy raw secret. Either way the codec is seeded from the UUID part;
            // a blob additionally yields the encryption public key for the link.
            let (uuid_key, enc_pubkey) = parse_secret_for_link(&secret_key);
            let codec = UuidCodec::new(&uuid_key);
            let (type_byte, proxy_ipv4, effective_proxy_port) = match r#type {
                ProxyType::Direct => (0x00, Ipv4Addr::new(0, 0, 0, 0), 0),
                ProxyType::Proxyip => {
                    let ip = proxy_ip
                        .context("--proxy-ip is required for proxyip type")?
                        .parse::<Ipv4Addr>()
                        .context("--proxy-ip must be a valid IPv4 address")?;
                    let port = if proxy_port == 0 { 443 } else { proxy_port };
                    (0x01, ip, port)
                }
                ProxyType::Socks5 => {
                    let ip = proxy_ip
                        .context("--proxy-ip is required for socks5 type")?
                        .parse::<Ipv4Addr>()
                        .context("--proxy-ip must be a valid IPv4 address")?;
                    let port = if proxy_port == 0 { 1080 } else { proxy_port };
                    (0x02, ip, port)
                }
                ProxyType::Http => {
                    let ip = proxy_ip
                        .context("--proxy-ip is required for http type")?
                        .parse::<Ipv4Addr>()
                        .context("--proxy-ip must be a valid IPv4 address")?;
                    let port = if proxy_port == 0 { 80 } else { proxy_port };
                    (0x03, ip, port)
                }
            };
            let uuid = codec.encode(type_byte, proxy_ipv4, effective_proxy_port);
            let sni = sni.unwrap_or_else(|| address.clone());
            let name = name.unwrap_or_else(|| address.clone());
            let path = generate_realistic_path();

            let encoded_path = percent_encode(&path);
            let encoded_name = percent_encode(&name);

            // The single best profile: native (lowest overhead inside WSS) + 1rtt
            // (stateless) + hybrid ML-KEM-768/X25519 PFS. `none` when the secret
            // carries no key (legacy / encryption off).
            let encryption = match enc_pubkey {
                Some(pk) => format!(
                    "mlkem768x25519plus.native.1rtt.{}",
                    general_purpose::URL_SAFE_NO_PAD.encode(pk)
                ),
                None => "none".to_string(),
            };

            let url = format!(
                "vless://{uuid}@{address}:{port}?encryption={encryption}&security=tls&sni={sni}&fp=chrome&alpn=http%2F1.1&type=ws&host={sni}&path={encoded_path}&ech=cloudflare-ech.com%2Bhttps%3A%2F%2Fdns.alidns.com%2Fdns-query&insecure=0&allowInsecure=0#{encoded_name}"
            );

            println!("{}", url);
        }
        Commands::GenSecret { encryption } => {
            if encryption {
                print_encryption_secret_pair();
            } else {
                // Plaintext mode (encryption=none): ONE raw random secret shared
                // between the relay (SECRET_KEY) and the sub (VEILWEAVE_NODES).
                let secret = gen_raw_secret();
                println!("# Plaintext VLESS (encryption=none) — one shared raw secret.");
                println!();
                println!("# ── veilweave relay ──  set  SECRET_KEY  to:");
                println!("{secret}");
                println!();
                println!(
                    "# ── veilweave-sub ──  use in  VEILWEAVE_NODES  as  <domain>|<secret>, e.g.:"
                );
                println!("my-relay.example.workers.dev|{secret}");
                println!();
                println!(
                    "# Every relay should get its OWN secret — run gen-secret once per relay."
                );
            }
        }
        Commands::Bundle {
            out,
            relay_domain,
            bundle_dir,
            encryption,
        } => {
            run_bundle(
                &out,
                relay_domain.as_deref(),
                bundle_dir.as_deref(),
                encryption,
            )?;
        }
        Commands::Deploy {
            bundle_dir,
            config,
            proxy,
            dry_run,
            json,
            yes,
        } => match config {
            Some(config) => run_async(run_apply(config, bundle_dir, proxy, dry_run, json, yes)),
            None if proxy.is_some() || dry_run || json || yes => {
                eprintln!("error: --proxy/--dry-run/--json/--yes require --config");
                std::process::exit(2);
            }
            None => run_async(wizard::run_deploy(bundle_dir)),
        },
        Commands::Plan {
            config,
            bundle_dir,
            json,
        } => run_async(run_plan(config, bundle_dir, json)),
        Commands::Apply {
            config,
            bundle_dir,
            proxy,
            dry_run,
            json,
            yes,
        } => run_async(run_apply(config, bundle_dir, proxy, dry_run, json, yes)),
        Commands::Status { json } => run_async(run_status(json)),
        Commands::Update {
            deployment,
            bundle_dir,
            proxy,
        } => run_async(run_update(deployment, bundle_dir, proxy)),
        Commands::RotateToken {
            deployment,
            bundle_dir,
            proxy,
        } => run_async(run_rotate_token(deployment, bundle_dir, proxy)),
        Commands::Rollback { deployment, proxy } => run_async(run_rollback(deployment, proxy)),
        Commands::Doctor {
            bundle_dir,
            proxy,
            json,
        } => run_async(run_doctor(bundle_dir, proxy, json)),
        Commands::Recover {
            account,
            adopt_worker,
            worker_secret_ref,
            node_secret_ref,
            subscription_token_ref,
            primary,
            proxy,
            json,
        } => run_async(run_recover(
            RecoverOptions {
                account,
                adopt_worker,
                worker_secret_ref,
                node_secret_ref,
                subscription_token_ref,
                primary,
            },
            proxy,
            json,
        )),
        Commands::Domain {
            account,
            proxy,
            json,
        } => run_async(run_domains(account, proxy, json)),
        Commands::Config { command } => run_async(run_config(command)),
        Commands::Proxy { command } => run_async(run_proxy(command)),
        Commands::Manage => run_async(wizard::run_manage()),
        Commands::WorkerBundle { command } => run_worker_bundle(command)?,
    }
    Ok(())
}

fn run_worker_bundle(command: WorkerBundleCommand) -> anyhow::Result<()> {
    use std::path::Path;
    use veilweave_core::bundle::WorkerBundle;

    match command {
        WorkerBundleCommand::Prepare { role, source, out } => {
            let role = role.into();
            let bundle = WorkerBundle::from_worker_build(Path::new(&source), role)
                .with_context(|| format!("prepare {} bundle", role.as_str()))?;
            bundle
                .write_to(Path::new(&out))
                .with_context(|| format!("write {} bundle", role.as_str()))?;
            println!(
                "validated {} bundle {} ({} modules)",
                role.as_str(),
                bundle.manifest().bundle_sha256,
                bundle.modules().len()
            );
        }
        WorkerBundleCommand::Validate { role, dir } => {
            let role = role.into();
            let bundle = WorkerBundle::from_directory(Path::new(&dir), role)
                .with_context(|| format!("validate {} bundle", role.as_str()))?;
            println!(
                "valid {} bundle {} ({} modules)",
                role.as_str(),
                bundle.manifest().bundle_sha256,
                bundle.modules().len()
            );
        }
    }
    Ok(())
}

/// Print the EXPERIMENTAL VLESS Encryption combined blob pair (the pre-1.0
/// `gen-secret` behavior). Kept byte-compatible with relay/src/secret.rs.
fn print_encryption_secret_pair() {
    use x25519_dalek::{PublicKey, StaticSecret};
    // One shared UUID-signing secret, plus one X25519 keypair for VLESS
    // Encryption. The relay gets the private key, the sub gets the public.
    let mut uuid_secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut uuid_secret);
    let x = StaticSecret::random_from_rng(rand::thread_rng());
    let priv_bytes = x.to_bytes();
    let pub_bytes = PublicKey::from(&x).to_bytes();

    let relay = encode_blob(0, &uuid_secret, &priv_bytes);
    let sub = encode_blob(1, &uuid_secret, &pub_bytes);

    println!("⚠️  EXPERIMENTAL: VLESS Encryption (mlkem768x25519plus) is CPU-heavy and");
    println!("    can exceed the Workers free plan's per-invocation CPU limit. The default");
    println!("    plaintext mode (gen-secret without --encryption) is recommended.");
    println!();
    println!("# ── veilweave relay ──  set  SECRET_KEY  to:");
    println!("{relay}");
    println!();
    println!("# ── veilweave-sub ──  use in  VEILWEAVE_NODES  as  <domain>|<blob>:");
    println!("{sub}");
}

/// Run an async deploy/manage entry point on a fresh tokio runtime.
fn run_async(future: impl std::future::Future<Output = anyhow::Result<()>>) {
    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
    if let Err(e) = rt.block_on(future) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run_plan(config: String, bundle_dir: Option<String>, json: bool) -> anyhow::Result<()> {
    let spec = veilweave_core::spec::DeploymentSpec::load(std::path::Path::new(&config))?;
    let plan = spec.to_plan()?;
    let source = veilweave_core::deploy::BundleSource::Dir(
        veilweave_core::deploy::locate_bundle_dir(bundle_dir.as_deref()),
    );
    let relay = source.worker_bundle(veilweave_core::bundle::WorkerRole::Relay)?;
    let sub = source.worker_bundle(veilweave_core::bundle::WorkerRole::Sub)?;
    let value = serde_json::json!({
        "valid": true,
        "version": spec.version,
        "encryption": plan.encryption,
        "sub": {
            "account": plan.sub.account,
            "worker": plan.sub.worker_name,
            "endpoint": format!("{:?}", plan.sub.endpoint.mode),
        },
        "relays": plan.relays.iter().map(|relay| serde_json::json!({
            "account": relay.account,
            "worker": relay.worker_name,
            "endpoint": format!("{:?}", relay.endpoint.mode),
        })).collect::<Vec<_>>(),
        "bundles": {
            "relay": relay.manifest().bundle_sha256,
            "sub": sub.manifest().bundle_sha256,
        }
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Plan is valid.");
        println!("  sub:    {} ({})", plan.sub.worker_name, plan.sub.account);
        for relay in &plan.relays {
            println!("  relay:  {} ({})", relay.worker_name, relay.account);
        }
        println!("  bundle: relay {}", relay.manifest().bundle_sha256);
        println!("          sub   {}", sub.manifest().bundle_sha256);
    }
    Ok(())
}

async fn run_apply(
    config: String,
    bundle_dir: Option<String>,
    proxy: Option<String>,
    dry_run: bool,
    json: bool,
    yes: bool,
) -> anyhow::Result<()> {
    if dry_run {
        return run_plan(config, bundle_dir, json).await;
    }
    if !yes
        && !dialoguer::Confirm::new()
            .with_prompt("Apply this topology to Cloudflare?")
            .default(false)
            .interact()?
    {
        println!("Aborted; no Cloudflare mutation was started.");
        return Ok(());
    }
    let spec = veilweave_core::spec::DeploymentSpec::load(std::path::Path::new(&config))?;
    let plan = spec.to_plan()?;
    let source = veilweave_core::deploy::BundleSource::Dir(
        veilweave_core::deploy::locate_bundle_dir(bundle_dir.as_deref()),
    );
    let mut state = veilweave_core::config::Config::load()?;
    let (credentials, network, network_source) =
        effective_network(&state.network, proxy.as_deref())?;
    let mut events = Vec::new();
    let outcome = veilweave_core::deploy::execute_with(
        &plan,
        &source,
        &mut state,
        &credentials,
        network,
        true,
        &mut |line| {
            if json {
                events.push(serde_json::json!({
                    "kind": format!("{:?}", line.kind),
                    "stage": format!("{:?}", line.stage),
                    "message": line.message,
                }));
            } else {
                println!("[{:?}] {}", line.stage, line.message);
            }
        },
    )
    .await?;
    let subscription_url = outcome.subscription_url(&state, &credentials)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "transaction_id": outcome.transaction_id,
                "network_source": network_source,
                "relays": outcome.relays,
                "sub": outcome.sub,
                "journal": outcome.journal,
                "events": events,
                "subscription_url": subscription_url,
            }))?
        );
    } else if let Some(url) = subscription_url {
        println!("Deployment complete.");
        println!("Subscription URL: {url}");
    }
    Ok(())
}

async fn run_status(json: bool) -> anyhow::Result<()> {
    let state = veilweave_core::config::Config::load()?;
    let deployments = state
        .deployments
        .iter()
        .map(|deployment| {
            serde_json::json!({
                "id": deployment.id,
                "role": deployment.role.to_string(),
                "name": deployment.name,
                "account_id": deployment.account_id,
                "primary_hostname": deployment.primary_domain(),
                "exposure": format!("{:?}", deployment.endpoint.mode),
                "stable_version_id": deployment.stable_version_id,
                "previous_version_id": deployment.previous_version_id,
                "updated_at": deployment.updated_at,
            })
        })
        .collect::<Vec<_>>();
    if json {
        println!("{}", serde_json::to_string_pretty(&deployments)?);
    } else if deployments.is_empty() {
        println!("No local deployments.");
    } else {
        for deployment in &state.deployments {
            println!(
                "{}  {:5}  {}  {}",
                deployment.id,
                deployment.role,
                deployment.name,
                deployment
                    .primary_domain()
                    .unwrap_or("endpoint unavailable")
            );
        }
    }
    Ok(())
}

async fn run_update(
    deployment: String,
    bundle_dir: Option<String>,
    proxy: Option<String>,
) -> anyhow::Result<()> {
    let deployment_id = uuid::Uuid::parse_str(&deployment).context("invalid deployment UUID")?;
    let mut state = veilweave_core::config::Config::load()?;
    let (credentials, network, _) = effective_network(&state.network, proxy.as_deref())?;
    let source = veilweave_core::deploy::BundleSource::Dir(
        veilweave_core::deploy::locate_bundle_dir(bundle_dir.as_deref()),
    );
    let remote_id = veilweave_core::deploy::update_code(
        deployment_id,
        &source,
        &mut state,
        &credentials,
        network,
        true,
        &mut |line| println!("[{:?}] {}", line.stage, line.message),
    )
    .await?;
    println!("Update promoted as Cloudflare deployment {remote_id}.");
    Ok(())
}

async fn run_rollback(deployment: String, proxy: Option<String>) -> anyhow::Result<()> {
    let deployment_id = uuid::Uuid::parse_str(&deployment).context("invalid deployment UUID")?;
    let mut state = veilweave_core::config::Config::load()?;
    let (credentials, network, _) = effective_network(&state.network, proxy.as_deref())?;
    let remote_id =
        veilweave_core::deploy::rollback(deployment_id, &mut state, &credentials, network, true)
            .await?;
    println!("Previous stable version restored as Cloudflare deployment {remote_id}.");
    Ok(())
}

async fn run_rotate_token(
    deployment: String,
    bundle_dir: Option<String>,
    proxy: Option<String>,
) -> anyhow::Result<()> {
    let deployment_id = uuid::Uuid::parse_str(&deployment).context("invalid deployment UUID")?;
    let mut state = veilweave_core::config::Config::load()?;
    let (credentials, network, _) = effective_network(&state.network, proxy.as_deref())?;
    let source = veilweave_core::deploy::BundleSource::Dir(
        veilweave_core::deploy::locate_bundle_dir(bundle_dir.as_deref()),
    );
    let remote_id = veilweave_core::deploy::rotate_subscription_token(
        deployment_id,
        &source,
        &mut state,
        &credentials,
        network,
        true,
    )
    .await?;
    println!("Subscription token rotated in Cloudflare and the secure credential store (deployment {remote_id}).");
    Ok(())
}

async fn run_doctor(
    bundle_dir: Option<String>,
    proxy: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let state = veilweave_core::config::Config::load()?;
    let (credentials, network, network_source) =
        effective_network(&state.network, proxy.as_deref())?;
    let report = network.test_connection().await;
    let source = veilweave_core::deploy::BundleSource::Dir(
        veilweave_core::deploy::locate_bundle_dir(bundle_dir.as_deref()),
    );
    let relay_bundle = source
        .worker_bundle(veilweave_core::bundle::WorkerRole::Relay)
        .map(|bundle| bundle.manifest().bundle_sha256.clone());
    let sub_bundle = source
        .worker_bundle(veilweave_core::bundle::WorkerRole::Sub)
        .map(|bundle| bundle.manifest().bundle_sha256.clone());
    let mut accounts = Vec::new();
    for account in &state.accounts {
        let result = match credentials.resolve(&account.credential_ref) {
            Ok(token) => {
                match veilweave_core::cfapi::CfClient::with_network(token.expose(), network.clone())
                {
                    Ok(client) => client.verify_token().await.map(|_| "active".to_string()),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        accounts.push(serde_json::json!({
            "account_id": account.account_id,
            "name": account.name,
            "token": result.as_deref().unwrap_or("unavailable"),
            "error": result.err().map(|error| format!("{error:#}")),
        }));
    }
    let value = serde_json::json!({
        "network_source": network_source,
        "network": report,
        "config_schema": state.schema_version,
        "config_recovery_notice": state.recovery_notice,
        "accounts": accounts,
        "deployments": state.deployments.len(),
        "bundles": {
            "relay": relay_bundle.as_ref().ok(),
            "relay_error": relay_bundle.as_ref().err().map(|error| format!("{error:#}")),
            "sub": sub_bundle.as_ref().ok(),
            "sub_error": sub_bundle.as_ref().err().map(|error| format!("{error:#}")),
        }
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Network policy source: {network_source}");
        for check in &report.checks {
            println!(
                "{:20} {:4} {:5} ms  {}",
                check.name,
                if check.ok { "OK" } else { "FAIL" },
                check.latency_ms,
                check.detail
            );
        }
        println!(
            "Relay bundle: {}",
            relay_bundle
                .as_ref()
                .map(String::as_str)
                .unwrap_or("INVALID")
        );
        println!(
            "Sub bundle:   {}",
            sub_bundle.as_ref().map(String::as_str).unwrap_or("INVALID")
        );
    }
    Ok(())
}

async fn run_recover(
    options: RecoverOptions,
    proxy: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let RecoverOptions {
        account,
        adopt_worker,
        worker_secret_ref,
        node_secret_ref,
        subscription_token_ref,
        primary,
    } = options;
    let state = veilweave_core::config::Config::load()?;
    let cloudflare_account = state
        .account(&account)
        .cloned()
        .with_context(|| format!("configured account {account:?} not found"))?;
    let (credentials, network, _) = effective_network(&state.network, proxy.as_deref())?;
    let token = credentials.resolve(&cloudflare_account.credential_ref)?;
    let client = veilweave_core::cfapi::CfClient::with_network(token.expose(), network)?;
    let mut outcome = veilweave_core::recover::recover_account(
        &client,
        &cloudflare_account.account_id,
        cloudflare_account.workers_dev_subdomain.as_deref(),
    )
    .await?;
    veilweave_core::recover::reconcile_local(&mut outcome, &state.deployments, &credentials);
    if let Some(worker) = adopt_worker {
        if state.deployments.iter().any(|deployment| {
            deployment.account_id == cloudflare_account.account_id && deployment.name == worker
        }) {
            bail!("Worker {worker:?} is already present in local metadata");
        }
        let candidate = outcome
            .candidates
            .iter()
            .find(|candidate| candidate.name == worker)
            .with_context(|| format!("remote Worker {worker:?} was not found"))?;
        let worker_secret_ref =
            worker_secret_ref.context("--worker-secret-ref is required for adoption")?;
        credentials
            .resolve(&worker_secret_ref)
            .context("the Worker secret reference does not resolve")?;
        if let Some(reference) = &node_secret_ref {
            credentials
                .resolve(reference)
                .context("the node secret reference does not resolve")?;
        }
        if let Some(reference) = &subscription_token_ref {
            credentials
                .resolve(reference)
                .context("the subscription-token reference does not resolve")?;
        }
        let deployment = veilweave_core::recover::adopt_candidate(
            candidate,
            veilweave_core::recover::AdoptionCredentials {
                worker_secret_ref,
                node_secret_ref,
                subscription_token_ref,
            },
            primary.into(),
        )?;
        let result = serde_json::json!({
            "id": deployment.id,
            "role": deployment.role.to_string(),
            "name": deployment.name,
            "account_id": deployment.account_id,
            "primary_hostname": deployment.primary_domain(),
        });
        let mut candidate_config = state.clone();
        candidate_config.deployments.push(deployment);
        candidate_config.save()?;
        if json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "Re-linked secure v2 Worker {:?} as local deployment {}.",
                result["name"].as_str().unwrap_or_default(),
                result["id"].as_str().unwrap_or_default()
            );
        }
        return Ok(());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        for warning in outcome
            .summary
            .iter()
            .filter(|line| line.contains("unavailable"))
        {
            eprintln!("warning: {warning}");
        }
        for candidate in outcome.candidates {
            println!(
                "{:28} {:10} {:?}  {}",
                candidate.name,
                candidate
                    .role
                    .map_or_else(|| "unrelated".into(), |role| role.to_string()),
                candidate.state,
                candidate.diagnostic
            );
        }
    }
    Ok(())
}

async fn run_domains(account: String, proxy: Option<String>, json: bool) -> anyhow::Result<()> {
    let state = veilweave_core::config::Config::load()?;
    let cloudflare_account = state
        .account(&account)
        .cloned()
        .with_context(|| format!("configured account {account:?} not found"))?;
    let (credentials, network, _) = effective_network(&state.network, proxy.as_deref())?;
    let token = credentials.resolve(&cloudflare_account.credential_ref)?;
    let client = veilweave_core::cfapi::CfClient::with_network(token.expose(), network)?;
    let domains = client.list_domains(&cloudflare_account.account_id).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&domains)?);
    } else if domains.is_empty() {
        println!("No Worker Custom Domains in this account.");
    } else {
        for domain in domains {
            println!(
                "{:36} → {:28}  {}",
                domain.hostname,
                domain.service,
                domain.status.as_deref().unwrap_or("provisioning")
            );
        }
    }
    Ok(())
}

async fn run_config(command: ConfigCommand) -> anyhow::Result<()> {
    match command {
        ConfigCommand::Network {
            mode,
            host,
            port,
            username,
            remote_dns,
            bypass,
        } => {
            let mut state = veilweave_core::config::Config::load()?;
            let mode = match mode {
                NetworkModeArg::Direct => veilweave_core::network::NetworkMode::Direct,
                NetworkModeArg::System => veilweave_core::network::NetworkMode::System,
                NetworkModeArg::Socks5 => veilweave_core::network::NetworkMode::Socks5,
                NetworkModeArg::HttpProxy => veilweave_core::network::NetworkMode::HttpProxy,
            };
            let credentials = veilweave_core::credentials::CredentialManager::system();
            let mut staged_proxy_credential = None;
            let proxy = match mode {
                veilweave_core::network::NetworkMode::Direct
                | veilweave_core::network::NetworkMode::System => None,
                veilweave_core::network::NetworkMode::Socks5
                | veilweave_core::network::NetworkMode::HttpProxy => {
                    let host = host.context("--host is required for an explicit proxy")?;
                    let port = port.context("--port is required for an explicit proxy")?;
                    let username = username.filter(|value| !value.trim().is_empty());
                    let credential_ref = if username.is_some() {
                        let password = dialoguer::Password::new()
                            .with_prompt("Proxy password (stored in OS credential manager)")
                            .interact()?;
                        let reference =
                            veilweave_core::credentials::CredentialManager::keyring_reference(
                                "network/proxy/default",
                            );
                        let previous = if state
                            .network
                            .proxy
                            .as_ref()
                            .and_then(|proxy| proxy.credential_ref.as_ref())
                            == Some(&reference)
                        {
                            Some(credentials.resolve(&reference)?)
                        } else {
                            None
                        };
                        credentials.store_verified(&reference, &password)?;
                        staged_proxy_credential = Some((reference.clone(), previous));
                        Some(reference)
                    } else {
                        None
                    };
                    Some(veilweave_core::network::ProxyConfig {
                        host,
                        port,
                        username,
                        credential_ref,
                        remote_dns,
                        allow_direct_fallback: false,
                        connect_timeout_secs: 10,
                        http_scheme: veilweave_core::network::HttpProxyScheme::Http,
                    })
                }
            };
            let replacement = veilweave_core::network::NetworkConfig {
                mode,
                proxy,
                bypass,
                request_timeout_secs: 45,
            };
            let result = (|| -> anyhow::Result<()> {
                veilweave_core::network::NetworkManager::new(
                    replacement.clone(),
                    credentials.clone(),
                )?;
                let mut candidate = state.clone();
                candidate.network = replacement;
                candidate.save()?;
                state = candidate;
                Ok(())
            })();
            if let Err(error) = result {
                if let Some((reference, previous)) = staged_proxy_credential {
                    let rollback = match previous {
                        Some(previous) => credentials.store_verified(&reference, previous.expose()),
                        None => credentials.delete(&reference),
                    };
                    return match rollback {
                        Ok(()) => Err(error),
                        Err(rollback_error) => Err(error.context(format!(
                            "proxy credential rollback also failed: {rollback_error:#}"
                        ))),
                    };
                }
                return Err(error);
            }
            println!("Network policy saved. New application operations will use it immediately.");
        }
    }
    Ok(())
}

async fn run_proxy(command: ProxyCommand) -> anyhow::Result<()> {
    match command {
        ProxyCommand::Test { proxy, json } => {
            let state = veilweave_core::config::Config::load()?;
            let (_, network, source) = effective_network(&state.network, proxy.as_deref())?;
            let report = network.test_connection().await;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Network policy source: {source}");
                for check in report.checks {
                    println!(
                        "{:20} {:4} {:5} ms  {}",
                        check.name,
                        if check.ok { "OK" } else { "FAIL" },
                        check.latency_ms,
                        check.detail
                    );
                }
            }
        }
    }
    Ok(())
}

fn effective_network(
    saved: &veilweave_core::network::NetworkConfig,
    cli_proxy: Option<&str>,
) -> anyhow::Result<(
    veilweave_core::credentials::CredentialManager,
    veilweave_core::network::NetworkManager,
    String,
)> {
    let environment_proxy = if cli_proxy.is_none()
        && saved.mode == veilweave_core::network::NetworkMode::Direct
        && std::env::var("VEILWEAVE_USE_ENV_PROXY").as_deref() == Ok("1")
    {
        std::env::var("ALL_PROXY").ok()
    } else {
        None
    };
    let (config, credentials, source) =
        if let Some(proxy) = cli_proxy.map(str::to_string).or(environment_proxy) {
            let source = if cli_proxy.is_some() {
                "CLI --proxy"
            } else {
                "ALL_PROXY (VEILWEAVE_USE_ENV_PROXY=1)"
            };
            let (config, credentials) = transient_proxy(&proxy)?;
            (config, credentials, source.to_string())
        } else {
            (
                saved.clone(),
                veilweave_core::credentials::CredentialManager::system(),
                "saved network configuration".to_string(),
            )
        };
    let network = veilweave_core::network::NetworkManager::new(config, credentials.clone())?;
    Ok((credentials, network, source))
}

fn transient_proxy(
    value: &str,
) -> anyhow::Result<(
    veilweave_core::network::NetworkConfig,
    veilweave_core::credentials::CredentialManager,
)> {
    let url = url::Url::parse(value)
        .context("proxy must be a URL such as socks5h://127.0.0.1:10808 or http://proxy:8080")?;
    let (mode, remote_dns, http_scheme, default_port) = match url.scheme() {
        "socks5h" => (
            veilweave_core::network::NetworkMode::Socks5,
            true,
            veilweave_core::network::HttpProxyScheme::Http,
            1080,
        ),
        "socks5" => (
            veilweave_core::network::NetworkMode::Socks5,
            false,
            veilweave_core::network::HttpProxyScheme::Http,
            1080,
        ),
        "http" => (
            veilweave_core::network::NetworkMode::HttpProxy,
            true,
            veilweave_core::network::HttpProxyScheme::Http,
            80,
        ),
        "https" => (
            veilweave_core::network::NetworkMode::HttpProxy,
            true,
            veilweave_core::network::HttpProxyScheme::Https,
            443,
        ),
        scheme => bail!("unsupported proxy URL scheme {scheme:?}"),
    };
    let username = (!url.username().is_empty()).then(|| url.username().to_string());
    let reference =
        veilweave_core::credentials::CredentialManager::keyring_reference("session/proxy");
    let (credential_ref, credentials) = match (username.as_ref(), url.password()) {
        (Some(_), Some(password)) => (
            Some(reference.clone()),
            veilweave_core::credentials::CredentialManager::system_with_ephemeral(
                &reference,
                password,
            )?,
        ),
        (Some(_), None) => bail!(
            "authenticated transient proxy URL requires a password; prefer the saved secure network configuration"
        ),
        (None, Some(_)) => bail!("proxy URL password cannot be used without a username"),
        (None, None) => (
            None,
            veilweave_core::credentials::CredentialManager::system(),
        ),
    };
    Ok((
        veilweave_core::network::NetworkConfig {
            mode,
            proxy: Some(veilweave_core::network::ProxyConfig {
                host: url.host_str().context("proxy URL has no host")?.to_string(),
                port: url.port().unwrap_or(default_port),
                username,
                credential_ref,
                remote_dns,
                allow_direct_fallback: false,
                connect_timeout_secs: 10,
                http_scheme,
            }),
            bypass: Vec::new(),
            request_timeout_secs: 45,
        },
        credentials,
    ))
}

// ─── bundle: pack prebuilt workers into ready-to-deploy folders ─────────────────

/// End-to-end "no source build" path. Copies the prebuilt worker bundles shipped
/// next to the binary and randomizes resource names. Sensitive values are
/// deliberately never written to the generated wrangler.toml files.
fn run_bundle(
    out: &str,
    relay_domain: Option<&str>,
    bundle_dir: Option<&str>,
    encryption: bool,
) -> anyhow::Result<()> {
    use std::path::Path;

    let bundle_root = veilweave_core::deploy::locate_bundle_dir(bundle_dir);
    for unit in ["relay", "sub"] {
        let src = bundle_root.join(unit);
        if !src.join(veilweave_core::bundle::MANIFEST_FILE).is_file() {
            bail!(
                "prebuilt worker not found at {}\nDownload the full release archive (it contains bundle/{unit}/) or pass --bundle-dir.",
                src.display()
            );
        }
    }

    let relay_name = random_worker_name();
    let sub_name = random_worker_name();
    let kv_binding = random_kv_binding();
    let relay_domain = relay_domain
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{relay_name}.<your-subdomain>.workers.dev"));

    let out_root = Path::new(out);
    let relay_out = out_root.join(&relay_name);
    let sub_out = out_root.join(&sub_name);

    pack_worker(
        &bundle_root.join("relay"),
        &relay_out,
        veilweave_core::bundle::WorkerRole::Relay,
    )?;
    pack_worker(
        &bundle_root.join("sub"),
        &sub_out,
        veilweave_core::bundle::WorkerRole::Sub,
    )?;

    std::fs::write(
        relay_out.join("wrangler.toml"),
        relay_wrangler_toml(&relay_name),
    )
    .with_context(|| format!("write {}", relay_out.join("wrangler.toml").display()))?;
    std::fs::write(
        sub_out.join("wrangler.toml"),
        sub_wrangler_toml(&sub_name, &kv_binding),
    )
    .with_context(|| format!("write {}", sub_out.join("wrangler.toml").display()))?;

    println!(
        "✔ Generated deploy-ready workers in {}/",
        out_root.display()
    );
    println!();
    println!(
        "  relay  →  {}  (worker name: {relay_name})",
        relay_out.display()
    );
    println!(
        "  sub    →  {}  (worker name: {sub_name})",
        sub_out.display()
    );
    println!();
    println!("Next steps (secret values are intentionally absent from every file):");
    println!(
        "  1. Generate the relay secret once: veilweave-tools gen-secret{}",
        if encryption { " --encryption" } else { "" }
    );
    println!(
        "  2. cd {} && wrangler secret put SECRET_KEY",
        relay_out.display()
    );
    println!("     then run: wrangler deploy");
    println!("     → note the https://<name>.<your-subdomain>.workers.dev domain");
    println!(
        "  3. cd {} && wrangler secret put VEILWEAVE_NODES",
        sub_out.display()
    );
    println!("     use: {relay_domain}|<the matching secret>");
    println!("     then set a new random value with: wrangler secret put SUBSCRIPTION_TOKEN");
    println!("     run: wrangler kv:namespace create {kv_binding}");
    println!("     and paste the printed id into [[kv_namespaces]].id");
    println!("  4. cd {} && wrangler deploy", sub_out.display());
    println!("  5. Subscription URL: https://<sub-domain>/sub?token=<your token>");
    Ok(())
}

/// Materialize only manifest-declared runtime modules for manual wrangler use.
fn pack_worker(
    src: &std::path::Path,
    dst: &std::path::Path,
    role: veilweave_core::bundle::WorkerRole,
) -> anyhow::Result<()> {
    let bundle = veilweave_core::bundle::WorkerBundle::from_directory(src, role)
        .with_context(|| format!("validate {} bundle", role.as_str()))?;
    bundle
        .write_runtime_to(&dst.join("build"))
        .with_context(|| format!("write {} runtime", role.as_str()))?;
    Ok(())
}

fn relay_wrangler_toml(name: &str) -> String {
    format!(
        r#"name = "{name}"
main = "build/index.js"
compatibility_date = "{}"
compatibility_flags = ["nodejs_compat"]
workers_dev = true

[observability]
enabled = true

# Set SECRET_KEY with `wrangler secret put SECRET_KEY` before deployment.
# Never add it to [vars] or commit it to this file.

[[durable_objects.bindings]]
name = "VEILWEAVE_SESSION"
class_name = "VeilweaveSession"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["VeilweaveSession"]
"#,
        veilweave_core::cfapi::COMPATIBILITY_DATE
    )
}

fn sub_wrangler_toml(name: &str, kv_binding: &str) -> String {
    format!(
        r#"name = "{name}"
main = "build/index.js"
compatibility_date = "{}"
compatibility_flags = ["nodejs_compat"]
workers_dev = true

# Run:  wrangler kv:namespace create {kv_binding}   and paste the id below.
# The binding name is randomized per bundle; feel free to pick your own —
# the worker finds its namespace via the KV_BINDING var below, so just keep
# `binding` and `KV_BINDING` identical (must be a valid JS identifier).
[[kv_namespaces]]
binding = "{kv_binding}"
id = "REPLACE_ME_WITH_KV_NAMESPACE_ID"

[vars]
KV_BINDING = "{kv_binding}"
MAX_NODES = "100"
FP = "chrome"
DISABLE_BUILTIN_PROXYIP = "false"

# Set VEILWEAVE_NODES and SUBSCRIPTION_TOKEN with `wrangler secret put`.
# Never add either value to [vars] or commit it to this file.
"#,
        veilweave_core::cfapi::COMPATIBILITY_DATE
    )
}

/// Keep the console window open when the binary was double-clicked, so the
/// generated paths stay visible. Skipped when stdin is piped (scripts, CI).
fn pause_before_exit() {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        println!();
        println!("Press Enter to exit / 按回车退出…");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
}

// The VW1 blob codec lives in veilweave_core::util (encode_blob/decode_blob,
// byte-compatible with veilweave/src/secret.rs).

/// Parse a secret for link generation: returns the UUID codec key bytes and, when
/// the secret is a blob, the encryption **public** key (derived from the private
/// key if a relay blob was supplied, so the private key never leaks into a link).
fn parse_secret_for_link(s: &str) -> (Vec<u8>, Option<[u8; 32]>) {
    use x25519_dalek::{PublicKey, StaticSecret};
    match decode_blob(s) {
        Some((kind, uuid, key)) => {
            let public = if kind == 0 {
                PublicKey::from(&StaticSecret::from(key)).to_bytes()
            } else {
                key
            };
            (uuid.to_vec(), Some(public))
        }
        None => (s.as_bytes().to_vec(), None),
    }
}

fn generate_realistic_path() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let templates: &[&str] = &[
        // API 版本化流式接口
        "/api/v{ver}/{resource}/{action}",
        "/api/v{ver}/{resource}/{id}/{action}",
        "/api/v{ver}/stream/{resource}",
        "/api/v{ver}/realtime/{resource}",
        "/api/v{ver}/live/{resource}",
        // WebSocket 原生路径
        "/ws/{resource}",
        "/ws/{resource}/{id}",
        "/websocket/{resource}",
        "/socket/{resource}",
        "/socket.io/{resource}",
        // 功能/资源路径
        "/{resource}/stream",
        "/{resource}/live",
        "/{resource}/realtime",
        "/{resource}/feed",
        "/{resource}/events",
        "/{resource}/sync",
        "/{resource}/push",
        "/{resource}/subscribe",
        // 流式数据
        "/stream/{resource}",
        "/stream/{resource}/{id}",
        "/live/{resource}",
        "/live/{resource}/{id}",
        "/realtime/{resource}",
        "/realtime/{resource}/{id}",
        // 内部/网关
        "/internal/{resource}/stream",
        "/services/{resource}/websocket",
        "/gateway/{resource}/connection",
        "/hub/{resource}/broadcast",
        // 特定协议
        "/graphql",
        "/subscriptions",
        "/stomp/websocket",
        "/mqtt",
        "/signalr/negotiate",
        "/signalr/connect",
        "/pusher/app/{id}",
        "/pubsub/{resource}",
        // 协作/通信
        "/collab/{resource}",
        "/collab/{resource}/sync",
        "/call/{resource}",
        "/conference/{resource}",
        "/room/{id}",
        "/channel/{id}",
    ];

    let resources: &[&str] = &[
        // 通信
        "chat",
        "messages",
        "notifications",
        "alerts",
        "mentions",
        "inbox",
        "conversations",
        "threads",
        "replies",
        // 金融
        "market",
        "trades",
        "tickers",
        "orders",
        "transactions",
        "positions",
        "balances",
        "funding",
        "liquidation",
        "candles",
        // 媒体
        "video",
        "audio",
        "screen",
        "camera",
        "microphone",
        "stream",
        "broadcast",
        "recording",
        "playback",
        "media",
        // 游戏
        "game",
        "match",
        "lobby",
        "room",
        "session",
        "party",
        "squad",
        "team",
        "leaderboard",
        "ranking",
        // IoT
        "device",
        "sensor",
        "telemetry",
        "iot",
        "gateway",
        "controller",
        "actuator",
        "beacon",
        "tracker",
        "monitor",
        // 协作
        "document",
        "editor",
        "whiteboard",
        "presentation",
        "spreadsheet",
        "cursor",
        "selection",
        "annotation",
        "comment",
        "revision",
        // 用户/社交
        "user",
        "presence",
        "status",
        "activity",
        "profile",
        "friend",
        "follower",
        "contact",
        "group",
        "community",
        // 数据/监控
        "data",
        "metrics",
        "logs",
        "analytics",
        "monitoring",
        "health",
        "performance",
        "trace",
        "span",
        "event",
        // 位置
        "location",
        "tracking",
        "geo",
        "map",
        "navigation",
        "route",
        "delivery",
        "shipment",
        "fleet",
        "vehicle",
        // 系统
        "system",
        "config",
        "state",
        "cache",
        "queue",
        "job",
        "task",
        "workflow",
        "pipeline",
        "build",
    ];

    let actions: &[&str] = &[
        "stream",
        "live",
        "realtime",
        "feed",
        "websocket",
        "events",
        "sync",
        "push",
        "pull",
        "subscribe",
        "broadcast",
        "publish",
        "connect",
        "channel",
        "negotiate",
        "handshake",
        "heartbeat",
        "ping",
        "update",
        "delta",
    ];

    let template = templates.choose(&mut rng).unwrap();
    let resource = resources.choose(&mut rng).unwrap();
    let action = actions.choose(&mut rng).unwrap();
    let ver = rng.gen_range(1..=4);
    let id = if rng.gen_bool(0.5) {
        generate_ws_uuid()
    } else {
        generate_short_id()
    };

    let path = template
        .replace("{ver}", &ver.to_string())
        .replace("{resource}", resource)
        .replace("{action}", action)
        .replace("{id}", &id);

    let mut params: Vec<String> = Vec::new();

    // 协议特定的参数
    if path.contains("socket.io") {
        params.push(format!("EIO={}", rng.gen_range(3..=4)));
        params.push("transport=websocket".to_string());
        if rng.gen_bool(0.7) {
            params.push(format!("sid={}", generate_hex_id(16)));
        }
    } else if path.contains("graphql") {
        params.push(format!("query={}", generate_graphql_query()));
        if rng.gen_bool(0.5) {
            params.push(format!(
                "operationName={}",
                [
                    "SubscribePrices",
                    "SubscribeTrades",
                    "SubscribeOrders",
                    "OnMessageReceived",
                    "OnPresenceUpdate",
                    "OnNotification",
                ]
                .choose(&mut rng)
                .unwrap()
            ));
        }
    } else if path.contains("signalr") {
        params.push(format!("id={}", generate_ws_uuid()));
        params.push(format!("access_token={}", generate_jwt_token()));
    } else if path.contains("pusher") {
        params.push(format!("protocol={}", rng.gen_range(5..=7)));
        params.push("client=js".to_string());
        params.push(format!(
            "version={}",
            ["7.0.0", "7.6.0", "8.0.0"].choose(&mut rng).unwrap()
        ));
    } else {
        let pool = vec![
            format!("token={}", generate_jwt_token()),
            format!("session={}", generate_ws_uuid()),
            format!("client_id={}", generate_hex_id(16)),
            format!("connection_id={}", generate_ws_uuid()),
            format!(
                "format={}",
                ["json", "protobuf", "binary", "msgpack"]
                    .choose(&mut rng)
                    .unwrap()
            ),
            format!("encoding={}", ["utf8", "base64"].choose(&mut rng).unwrap()),
            format!(
                "compress={}",
                ["zstd", "deflate", "gzip", "none"]
                    .choose(&mut rng)
                    .unwrap()
            ),
            format!("heartbeat={}", [30, 60, 120].choose(&mut rng).unwrap()),
            format!("ping_interval={}", [30, 60, 120].choose(&mut rng).unwrap()),
            format!("protocol={}", ["wss", "ws"].choose(&mut rng).unwrap()),
            format!(
                "transport={}",
                ["websocket", "polling"].choose(&mut rng).unwrap()
            ),
            format!(
                "version={}",
                ["2.1.0", "3.0.1", "1.4.2", "2.5.0"]
                    .choose(&mut rng)
                    .unwrap()
            ),
            format!(
                "client={}",
                ["web-3.2.1", "ios-4.1.0", "android-2.8.3", "desktop-1.5.0"]
                    .choose(&mut rng)
                    .unwrap()
            ),
            format!("api_key={}", generate_hex_id(32)),
            format!("room={}", generate_room_id()),
            format!("channel={}", generate_channel_name()),
            format!("user_id={}", rng.gen::<u64>()),
            format!("timestamp={}", generate_timestamp()),
            format!("nonce={}", generate_hex_id(8)),
        ];
        let n = rng.gen_range(2..=5);
        for p in pool.choose_multiple(&mut rng, n) {
            params.push(p.clone());
        }
    }

    // No `ed=2048`: it is an xray early-data marker, not a WebSocket requirement,
    // and the relay reads the VLESS header from the first frame without it. Omitting
    // it makes the path indistinguishable from genuine app WebSocket traffic.
    if params.is_empty() {
        return path;
    }
    params.shuffle(&mut rng);
    format!("{}?{}", path, params.join("&"))
}

fn generate_ws_uuid() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn generate_short_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let len = rng.gen_range(8..=16);
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn generate_jwt_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let payload_len = rng.gen_range(48..=96);
    let mut payload_bytes = vec![0u8; payload_len];
    rng.fill_bytes(&mut payload_bytes);
    let payload = general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);
    let sig_len = rng.gen_range(32..=48);
    let mut sig_bytes = vec![0u8; sig_len];
    rng.fill_bytes(&mut sig_bytes);
    let signature = general_purpose::URL_SAFE_NO_PAD.encode(&sig_bytes);
    format!("{}.{}.{}", header, payload, signature)
}

fn generate_graphql_query() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let queries = [
        "subscription%20OnPriceUpdate%20%7B%20price%20%7B%20symbol%20price%20timestamp%20%7D%20%7D",
        "subscription%20OnTrade%20%7B%20trade%20%7B%20id%20amount%20price%20side%20%7D%20%7D",
        "subscription%20OnMessage%20%7B%20message%20%7B%20id%20content%20sender%20timestamp%20%7D%20%7D",
        "subscription%20OnNotification%20%7B%20notification%20%7B%20type%20data%20read%20%7D%20%7D",
        "subscription%20OnPresence%20%7B%20presence%20%7B%20userId%20status%20lastSeen%20%7D%20%7D",
        "subscription%20OnOrder%20%7B%20order%20%7B%20id%20status%20amount%20symbol%20%7D%20%7D",
    ];
    queries[rng.gen_range(0..queries.len())].to_string()
}

fn generate_room_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let prefixes = ["room", "lobby", "channel", "space", "hub"];
    let prefix = prefixes[rng.gen_range(0..prefixes.len())];
    let id: u64 = rng.gen();
    format!("{}_{}", prefix, id)
}

fn generate_channel_name() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let names = [
        "global", "general", "random", "dev", "ops", "alerts", "trades", "prices", "orders",
        "system", "logs", "events", "private", "direct", "group", "team", "project",
    ];
    let name = names[rng.gen_range(0..names.len())];
    let suffix: u32 = rng.gen();
    format!("{}-{}", name, suffix)
}

fn generate_timestamp() -> u64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let base: u64 = 1_700_000_000;
    base + rng.gen_range(0..100_000_000)
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
