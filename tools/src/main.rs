use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand, ValueEnum};
use rand::{seq::SliceRandom, RngCore};
use std::net::Ipv4Addr;

mod cfapi;
mod codec;
mod config;
mod deploy;
mod gui;
mod hmac;
mod sha256;
mod wizard;

use codec::UuidCodec;

#[derive(Parser)]
#[command(name = "veilweave-tools")]
#[command(about = "VLESS subscription link generator for veilweave")]
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
    /// (UUID secret + X25519 key, `mlkem768x25519plus`).
    GenSecret {
        /// Print the EXPERIMENTAL VLESS Encryption blob pair instead of a raw
        /// secret. Warning: the encryption datapath is CPU-heavy and can
        /// exceed the Workers free plan's per-invocation CPU limit.
        #[arg(long)]
        encryption: bool,
    },
    /// Pack the prebuilt workers (shipped next to this binary in `bundle/`) into
    /// ready-to-deploy folders: fresh secrets, randomized worker names, and a
    /// per-run nonce injected into each script so every user's artifact is unique.
    /// No Rust toolchain or source build required — just `wrangler deploy`.
    Bundle {
        /// Output directory for the generated deploy folders
        #[arg(long, default_value = "dist")]
        out: String,
        /// Domain of the relay worker, e.g. veilweave.<sub>.workers.dev.
        /// Defaults to "<relay-name>.<your-subdomain>.workers.dev" — edit
        /// VEILWEAVE_NODES in the generated sub/wrangler.toml after deploying.
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
    },
    /// Manage existing deployments: list them, re-show a subscription URL, or
    /// delete a worker (and its KV namespace) from Cloudflare.
    Manage,
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
        // Double-click (no subcommand) launches the GUI deployer.
        if let Err(e) = gui::launch() {
            eprintln!("无法创建图形界面窗口 / could not open the GUI window: {e:#}");
            eprintln!("（无显示环境？）请改用命令行部署向导 / headless? use the CLI wizard:");
            eprintln!("    veilweave-tools deploy");
            pause_before_exit();
            std::process::exit(1);
        }
        return;
    };
    let pause = matches!(command, Commands::Bundle { .. });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(command)));
    if pause {
        pause_before_exit();
    }
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn run(command: Commands) {
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
                        .expect("--proxy-ip is required for proxyip type")
                        .parse::<Ipv4Addr>()
                        .expect("invalid IPv4 address");
                    let port = if proxy_port == 0 { 443 } else { proxy_port };
                    (0x01, ip, port)
                }
                ProxyType::Socks5 => {
                    let ip = proxy_ip
                        .expect("--proxy-ip is required for socks5 type")
                        .parse::<Ipv4Addr>()
                        .expect("invalid IPv4 address");
                    let port = if proxy_port == 0 { 1080 } else { proxy_port };
                    (0x02, ip, port)
                }
                ProxyType::Http => {
                    let ip = proxy_ip
                        .expect("--proxy-ip is required for http type")
                        .parse::<Ipv4Addr>()
                        .expect("invalid IPv4 address");
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
            );
        }
        Commands::Deploy { bundle_dir } => run_async(wizard::run_deploy(bundle_dir)),
        Commands::Manage => run_async(wizard::run_manage()),
    }
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

// ─── bundle: pack prebuilt workers into ready-to-deploy folders ─────────────────

/// End-to-end "no source build" path. Copies the prebuilt worker bundles shipped
/// next to the binary, generates fresh secrets, randomizes worker names, and
/// injects a per-run nonce comment into each `index.js` so every user's artifact
/// has a unique content hash.
fn run_bundle(out: &str, relay_domain: Option<&str>, bundle_dir: Option<&str>, encryption: bool) {
    use std::path::Path;

    let bundle_root = crate::deploy::locate_bundle_dir(bundle_dir);
    for unit in ["relay", "sub"] {
        let src = bundle_root.join(unit);
        if !src.join("build/index.js").is_file() {
            eprintln!(
                "error: prebuilt worker not found at {}\n\
                 Download the full release archive (it contains bundle/{unit}/) or pass --bundle-dir.",
                src.display()
            );
            std::process::exit(1);
        }
    }

    // One shared secret for relay and sub. Plaintext (default): a raw random
    // string. --encryption: the EXPERIMENTAL blob pair (UUID secret + X25519).
    let (relay_secret, sub_secret) = if encryption {
        gen_secret_pair()
    } else {
        let raw = gen_raw_secret();
        (raw.clone(), raw)
    };
    let token = generate_hex_id(32);
    let relay_name = random_worker_name();
    let sub_name = random_worker_name();
    let kv_binding = random_kv_binding();
    let relay_domain = relay_domain
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{relay_name}.<your-subdomain>.workers.dev"));

    let out_root = Path::new(out);
    let relay_out = out_root.join(&relay_name);
    let sub_out = out_root.join(&sub_name);

    pack_worker(&bundle_root.join("relay"), &relay_out);
    pack_worker(&bundle_root.join("sub"), &sub_out);

    std::fs::write(
        relay_out.join("wrangler.toml"),
        relay_wrangler_toml(&relay_name, &relay_secret, encryption),
    )
    .expect("write relay wrangler.toml");
    std::fs::write(
        sub_out.join("wrangler.toml"),
        sub_wrangler_toml(
            &sub_name,
            &relay_domain,
            &sub_secret,
            &token,
            &kv_binding,
            encryption,
        ),
    )
    .expect("write sub wrangler.toml");

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
    println!("Next steps:");
    println!("  1. cd {} && wrangler deploy", relay_out.display());
    println!("     → note the https://<name>.<your-subdomain>.workers.dev domain");
    println!(
        "  2. Edit {}/wrangler.toml: set VEILWEAVE_NODES domain to that domain,",
        sub_out.display()
    );
    println!("     then run:  wrangler kv:namespace create {kv_binding}");
    println!("     and paste the printed id into [[kv_namespaces]].id");
    println!("  3. cd {} && wrangler deploy", sub_out.display());
    println!("  4. Subscription URL:  https://<sub-domain>/sub?token={token}");
    println!();
    println!("Every run randomizes worker names and re-signs the scripts, so your");
    println!("deployment never shares a content hash with anyone else's.");
}

/// Copy the prebuilt worker (`build/`) into `dst` and inject a random nonce
/// comment at the top of `index.js` (per-run unique content hash).
fn pack_worker(src: &std::path::Path, dst: &std::path::Path) {
    copy_dir(&src.join("build"), &dst.join("build"));
    let index = dst.join("build/index.js");
    let js = std::fs::read_to_string(&index).expect("read build/index.js");
    std::fs::write(&index, inject_nonce(&js)).expect("write build/index.js");
}

/// Prepend a per-run nonce comment so every user's artifact has a unique
/// content hash. Shared by `bundle` and the direct-deploy path.
fn inject_nonce(js: &str) -> String {
    format!("/* vw:{} */\n{js}", generate_hex_id(64))
}

fn copy_dir(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).expect("create output dir");
    for entry in std::fs::read_dir(src).expect("read bundle dir") {
        let entry = entry.expect("read bundle entry");
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir(&from, &to);
        } else {
            std::fs::copy(&from, &to).expect("copy bundle file");
        }
    }
}

fn gen_secret_pair() -> (String, String) {
    use x25519_dalek::{PublicKey, StaticSecret};
    let mut uuid_secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut uuid_secret);
    let x = StaticSecret::random_from_rng(rand::thread_rng());
    let relay = encode_blob(0, &uuid_secret, &x.to_bytes());
    let sub = encode_blob(1, &uuid_secret, &PublicKey::from(&x).to_bytes());
    (relay, sub)
}

/// Random, innocuous worker name — a new one every run.
fn random_worker_name() -> String {
    use rand::Rng;
    const WORDS: &[&str] = &[
        "edge", "api", "cdn", "cache", "media", "data", "sync", "hub", "core", "node", "link",
        "stream", "relay", "proxy", "gate", "mesh", "orbit",
    ];
    const KINDS: &[&str] = &[
        "service", "worker", "backend", "endpoint", "gateway", "bridge", "feed",
    ];
    let mut rng = rand::thread_rng();
    format!(
        "{}-{}-{}",
        WORDS[rng.gen_range(0..WORDS.len())],
        KINDS[rng.gen_range(0..KINDS.len())],
        generate_hex_id(4)
    )
}

/// Random raw shared secret for plaintext mode: 32 bytes, base64url (no pad).
/// Used as the relay's SECRET_KEY and in the sub's VEILWEAVE_NODES verbatim.
fn gen_raw_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Random KV binding name, e.g. `kv_x7f2a9` — always a valid JS identifier.
/// The sub worker resolves its KV namespace via the `KV_BINDING` var, so the
/// binding name itself can (and should) vary per deployment.
fn random_kv_binding() -> String {
    format!("kv_{}", generate_hex_id(6))
}

fn relay_wrangler_toml(name: &str, secret: &str, encryption: bool) -> String {
    let secret_comment = if encryption {
        "# EXPERIMENTAL: SECRET_KEY is the relay blob — it carries the UUID-signing\n\
         # secret AND the X25519 private key for VLESS Encryption (mlkem768x25519plus).\n\
         # Keep it private; regenerate with a fresh bundle if leaked."
    } else {
        "# SECRET_KEY is the raw shared secret for plaintext VLESS (encryption=none).\n\
         # The same string goes in the sub's VEILWEAVE_NODES as `<domain>|<secret>`.\n\
         # Keep it private; regenerate with a fresh bundle if leaked."
    };
    format!(
        r#"name = "{name}"
main = "build/index.js"
compatibility_date = "2026-05-26"
compatibility_flags = ["nodejs_compat"]
workers_dev = true

[observability]
enabled = true

# Generated by `veilweave-tools bundle`.
{secret_comment}
[vars]
SECRET_KEY = "{secret}"

[[durable_objects.bindings]]
name = "VEILWEAVE_SESSION"
class_name = "VeilweaveSession"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["VeilweaveSession"]
"#
    )
}

fn sub_wrangler_toml(
    name: &str,
    relay_domain: &str,
    secret: &str,
    token: &str,
    kv_binding: &str,
    encryption: bool,
) -> String {
    let secret_comment = if encryption {
        "# <relay domain>|<sub blob> — replace the domain with your deployed relay's.\n\
         # EXPERIMENTAL: the blob carries the UUID secret + X25519 public key."
    } else {
        "# <relay domain>|<raw secret> — replace the domain with your deployed relay's.\n\
         # Plaintext VLESS (encryption=none); the secret must match the relay's SECRET_KEY."
    };
    format!(
        r#"name = "{name}"
main = "build/index.js"
compatibility_date = "2026-05-26"
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
{secret_comment}
VEILWEAVE_NODES = "{relay_domain}|{secret}"
SUBSCRIPTION_TOKEN = "{token}"
MAX_NODES = "100"
FP = "chrome"
DISABLE_BUILTIN_PROXYIP = "false"
"#
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

// ─── Combined secret blob (must match veilweave/src/secret.rs) ───────────────────
// Layout (base64url, no pad): "VW1" ‖ kind(1) ‖ uuid_secret(32) ‖ x25519(32)
//   kind 0 = relay (x25519 private),  kind 1 = sub (x25519 public)

fn encode_blob(kind: u8, uuid_secret: &[u8; 32], key: &[u8; 32]) -> String {
    let mut b = Vec::with_capacity(68);
    b.extend_from_slice(b"VW1");
    b.push(kind);
    b.extend_from_slice(uuid_secret);
    b.extend_from_slice(key);
    general_purpose::URL_SAFE_NO_PAD.encode(&b)
}

fn decode_blob(s: &str) -> Option<(u8, [u8; 32], [u8; 32])> {
    let b = general_purpose::URL_SAFE_NO_PAD.decode(s.trim()).ok()?;
    if b.len() != 68 || &b[0..3] != b"VW1" {
        return None;
    }
    let mut uuid = [0u8; 32];
    uuid.copy_from_slice(&b[4..36]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&b[36..68]);
    Some((b[3], uuid, key))
}

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

fn generate_hex_id(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    const HEX: &[u8] = b"0123456789abcdef";
    (0..len)
        .map(|_| HEX[rng.gen_range(0..HEX.len())] as char)
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
