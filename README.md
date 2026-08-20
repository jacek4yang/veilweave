<div align="center">

# veilweave

**Post-quantum, forward-secret VLESS over WebSocket — end-to-end through Cloudflare Workers**

**后量子、前向保密的 VLESS over WebSocket —— 端到端穿透 Cloudflare Workers**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 1.81+](https://img.shields.io/badge/Rust-1.81%2B-orange.svg)](https://www.rust-lang.org)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![WASM SIMD](https://img.shields.io/badge/WASM-SIMD128-9cf)](https://webassembly.org/features/)
[![Release](https://img.shields.io/github/v/release/jacek4yang/veilweave)](https://github.com/jacek4yang/veilweave/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A faithful Rust port of xray-core's `mlkem768x25519plus` VLESS Encryption, designed
to run on the Cloudflare Workers free plan. A per-connection Durable Object terminates
the encrypted stream, the bulk data path runs through WebCrypto AES-NI, and every
on-path observer — including Cloudflare itself — sees only opaque bytes.

xray-core `mlkem768x25519plus` VLESS Encryption 的忠实 Rust 移植，专为
Cloudflare Workers 免费套餐设计。每条连接由独立的 Durable Object 终止加密流，
批量数据走 WebCrypto AES-NI——链路上所有观察者（包括 Cloudflare 自己）只能看到
无法区分的密文。

</div>

---

## ⚡ Quick deploy — no build required / 快捷部署 —— 无需编译

> **You don't need Rust, cargo, or the source code.** Download a release, run one
> executable, deploy two workers. ~5 minutes.
>
> **不需要 Rust、cargo 或源码。** 下载 release，运行一个可执行文件，部署两个
> worker，约 5 分钟完成。

**Prerequisites / 前置条件：** a free Cloudflare account and
[`wrangler`](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
(`npm i -g wrangler`, then `wrangler login`).
一个免费 Cloudflare 账号和 wrangler（`npm i -g wrangler`，然后 `wrangler login`）。

### 1. Download / 下载

Grab the archive for your platform from
[**Releases**](https://github.com/jacek4yang/veilweave/releases) and unzip it:
从 [Releases](https://github.com/jacek4yang/veilweave/releases) 下载对应平台的
压缩包并解压：

| Platform / 平台 | Archive / 压缩包 |
|---|---|
| Windows (x64) | `veilweave-<ver>-windows-x64.zip` |
| Linux (x64) | `veilweave-<ver>-linux-x64.tar.gz` |
| macOS (Apple Silicon) | `veilweave-<ver>-macos-arm64.tar.gz` |

Each archive contains / 压缩包内含：

```
veilweave-tools(.exe)   ← the CLI / 命令行工具
bundle/relay/build/     ← PREBUILT relay worker (no compilation needed / 预编译)
bundle/sub/build/       ← PREBUILT sub worker   (no compilation needed / 预编译)
QUICKSTART.txt
```

### 2. Generate your deployable workers / 生成可部署产物

**Windows: double-click `veilweave-tools.exe`.**
Everyone else: run `./veilweave-tools bundle` in a terminal.

**Windows 直接双击 `veilweave-tools.exe`**；其他系统在终端运行
`./veilweave-tools bundle`。

It writes two ready-to-deploy folders into `dist/` and prints exact next steps.
它会在 `dist/` 下生成两个可直接部署的目录，并打印后续步骤。

> **Every run is unique / 每次运行都独一无二：**
>
> - fresh UUID-signing secret + X25519 keypair / 全新的 UUID 签名密钥 + X25519 密钥对
> - randomized worker names / 随机化的 worker 名称
> - randomized subscription token / 随机订阅令牌
> - a per-run nonce injected into each script, so **your artifact never shares a
>   content hash with anyone else's** — no fleet-wide fingerprint for Cloudflare
>   to flag / 每个脚本注入一次性随机串，**你的产物哈希与任何其他人都不相同**，
>   不会因批量指纹被 Cloudflare 标记

### 3. Deploy / 部署

```bash
cd dist/<relay-name> && wrangler deploy        # note the *.workers.dev domain
# edit dist/<sub-name>/wrangler.toml → put that domain in VEILWEAVE_NODES
cd dist/<sub-name>
wrangler kv:namespace create VEILWEAVE_KV      # paste the id into wrangler.toml
wrangler deploy
```

```bash
cd dist/<relay目录> && wrangler deploy          # 记下 *.workers.dev 域名
# 编辑 dist/<sub目录>/wrangler.toml → 把域名填进 VEILWEAVE_NODES
cd dist/<sub目录>
wrangler kv:namespace create VEILWEAVE_KV       # 把输出的 id 填进 wrangler.toml
wrangler deploy
```

### 4. Subscribe / 订阅

```
https://<sub-domain>/sub?token=<SUBSCRIPTION_TOKEN>
```

Paste the base64 response into v2rayN / NekoBox / mihomo / sing-box.
把返回的 base64 文本粘到 v2rayN / NekoBox / mihomo / sing-box 的订阅栏即可。

---

## What is this / 项目是什么

`veilweave` is **one repo, three components / 单仓库三件套**:

| Component / 子项目 | Form / 形态 | Role / 作用 |
|---|---|---|
| **`relay/`** | Cloudflare Worker (Rust → WASM) | **Data plane / 数据面**: terminates VLESS+WS+Encryption, forwards to targets / 终止 VLESS+WS+Encryption 连接，转发到目标站点 |
| **`sub/`** | Cloudflare Worker (Rust → WASM) | **Subscription plane / 订阅面**: serves `vless://…` link lists, multi egress/entry IP / 生成 `vless://…` 链接列表，支持多出口/入口 IP |
| **`tools/`** | Native CLI (Rust) | **Ops plane / 运维面**: keypairs, single links, one-click deploy bundles / 生成配套密钥、签发单条链接、一键生成部署产物 |

All three share the same "signed UUID" codec (HKDF + HMAC-SHA256 + 5-byte MAC).
**A UUID only decodes under the key that signed it**, so every relay node accepts
only its own links: sub signs UUIDs with one key, relay verifies with the same
key — multi-relay nodes behind one subscription source, natively.

三者共用同一套「签名 UUID」编解码（HKDF + HMAC-SHA256 + 5 字节 MAC）。
**UUID 只在签名它的密钥下能解码**，所以每个 relay 节点只接受自己的链接；
sub 用对应密钥签出 UUID，relay 用同一把密钥验签——天然支持多 relay 节点、
统一订阅源。

## Why / 为什么要做这个

Plain "VLESS over WS on a Cloudflare Worker" has a fundamental problem:

普通的「VLESS over WS on Cloudflare Worker」有一个根本问题：

> The Worker runs **after Cloudflare's TLS termination** — Cloudflare itself can
> see the plaintext destination and payload.
>
> Worker 跑在 Cloudflare **TLS 终结之后**——Cloudflare 自己就能看到明文的目的地
> 和载荷。

veilweave's answer: a second, end-to-end encryption layer **inside the WS** —
xray-core's `mlkem768x25519plus`, hybrid post-quantum forward secrecy
(**ML-KEM-768 + X25519**, fresh keys per connection), BLAKE3 derivation,
**AES-256-GCM** AEAD. As a result:

veilweave 的解法：在 **WS 内部**再套一层端到端加密——xray-core 的
`mlkem768x25519plus` 协议，混合后量子前向保密（**ML-KEM-768 + X25519**，每次
连接换密钥），BLAKE3 派生，**AES-256-GCM** AEAD。这样：

- client ↔ Worker bytes are **indistinguishable ciphertext**;
  客户端 ↔ Worker 之间的字节是**不可区分的密文**；
- Cloudflare and every middlebox see neither destination nor content;
  Cloudflare 和链路上的任何中间人都看不到目的地和内容；
- one connection's ephemeral keys never affect any other (forward secrecy);
  任何一次连接的临时密钥都不会影响其他连接（前向保密）；
- future quantum computers cannot retro-decrypt (post-quantum).
  量子计算机将来也无法回溯（后量子）。

The whole design is tuned for the **Workers free plan's 10 ms CPU cap per
invocation**: every inbound WS frame is its own invocation (WebSocket Hibernation
API), bulk AES-GCM runs in WebCrypto (BoringSSL/AES-NI), and the download path
pipelines + coalesces records to halve WebCrypto and `ws.send` calls.

整套设计为 **Workers 免费版 10 ms / 调用的 CPU 上限**量身打造：每条入站 WS 帧
= 一次独立 invocation（WebSocket Hibernation API）；bulk AES-GCM 走 WebCrypto
（BoringSSL/AES-NI）；下载路径 pipeline + 合并 ≤16 KiB/record，WebCrypto 调用
次数和 `ws.send` 次数都减半。

## Architecture / 整体架构

```
                                ┌────────────────────────┐
                                │  veilweave-tools (CLI) │
                                │  gen-secret / gen-link │
                                │  bundle                │
                                └───────────┬────────────┘
                                            │  matched pair: relay blob + sub blob
                       ┌────────────────────┴────────────────────┐
                       │                                         │
                       ▼                                         ▼
            ┌──────────────────────┐                  ┌──────────────────────┐
            │   relay  worker      │ ◄── WS+TLS ─── │   xray / sing-box /   │
            │  (data plane)        │   client         │   v2rayN 客户端      │
            │  ● Durable Object    │                  └──────────────────────┘
            │  ● WebCrypto AES-GCM │
            └──────────┬───────────┘
                       │
                       │  Direct / ProxyIP / SOCKS5 / HTTP-CONNECT
                       ▼
                  target site / 目标站点

            ┌──────────────────────┐
            │   sub  worker        │   GET /sub?token=…   →   vless:// link list
            │  (subscription)      │
            │  ● KV cache          │
            └──────────┬───────────┘
                       │  same signed-UUID codec / 同一份签名 UUID codec
                       ▼
                 client import / 客户端导入
```

## Repository layout / 仓库结构

```
veilweave/
├── relay/                    # data-plane Worker / 数据面 Worker（veilweave crate）
│   ├── src/                  # Rust source (enc/session/vless/codec/...)
│   ├── static/               # Apache camouflage pages / Apache 伪装页
│   ├── .cargo/config.toml    # +simd128 and other wasm target features
│   ├── wrangler.toml
│   └── README.md
│
├── sub/                      # subscription Worker / 订阅 Worker（veilweave-sub crate）
│   ├── src/                  # Rust source (lib/codec/optimized_ip/...)
│   ├── static/
│   ├── wrangler.toml
│   └── README.md
│
├── tools/                    # CLI / 运维 CLI（veilweave-tools crate, native binary）
│   ├── src/                  # gen-secret / gen-link / bundle
│   └── README.md
│
├── docs/                     # design / deployment / protocol docs / 设计·部署·协议文档
│   ├── architecture.md
│   ├── deployment.md
│   └── protocol.md
│
├── .github/workflows/        # CI + Release automation / CI 与 Release 自动化
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE                   # MIT
└── SECURITY.md
```

> The three components are independent (own `Cargo.toml` / `wrangler.toml`) — no
> top-level Cargo workspace, because `relay`/`sub` are cdylib targeting
> `wasm32-unknown-unknown` while `tools` is a native binary.
>
> 三个子项目**互相独立**，各自有自己的 `Cargo.toml` / `wrangler.toml`，没有
> 顶层 Cargo workspace——`relay`/`sub` 是走 wasm 目标的 cdylib，`tools` 是原生
> 二进制，混在一起反而麻烦。

## Build from source / 从源码构建

> Only needed for development. End users should use the
> [release flow](#-quick-deploy--no-build-required--快捷部署--无需编译) above.
>
> 仅开发需要。终端用户请使用上方的免编译 release 流程。

Prerequisites / 前置：`rustup` with the `wasm32-unknown-unknown` target,
`wrangler ≥ 3`, a Cloudflare account.
`rustup` + `wasm32-unknown-unknown` target、`wrangler ≥ 3`、一个 Cloudflare 账号。

```bash
git clone https://github.com/jacek4yang/veilweave.git
cd veilweave
rustup target add wasm32-unknown-unknown

# 1. matched secrets / 生成配套密钥
cargo run --manifest-path tools/Cargo.toml -- gen-secret

# 2. paste the RELAY blob into relay/wrangler.toml [vars].SECRET_KEY, then:
#    把 relay blob 填入 relay/wrangler.toml 后：
cd relay && wrangler deploy

# 3. paste the SUB blob into sub/wrangler.toml [vars].VEILWEAVE_NODES as
#    <relay-domain>|<blob>, create the KV namespace, then:
#    把 sub blob 以 <relay域名>|<blob> 填入 sub/wrangler.toml，创建 KV 后：
cd ../sub
wrangler kv:namespace create VEILWEAVE_KV   # paste id into wrangler.toml
wrangler deploy

# 4. single test link / 单条测试链接
cd ..
cargo run --manifest-path tools/Cargo.toml -- gen-link \
  --address veilweave.<your-subdomain>.workers.dev \
  --port 443 --type proxyip --proxy-ip 1.2.3.4 --proxy-port 443 \
  --secret-key "<relay blob>"
```

Paste the resulting `vless://…` link into v2rayN / NekoBox / mihomo / sing-box —
clients negotiate `mlkem768x25519plus` automatically during the handshake.
把输出的 `vless://…` 链接粘到客户端即可，握手时自动协商 `mlkem768x25519plus`。

## How the pieces fit / 三件套怎么搭配

| Flow / 流程 | Produced by / 谁生成 | Consumed by / 谁使用 |
|---|---|---|
| UUID signing secret / UUID 签名密钥 | `tools gen-secret` | `relay` (verify / 验签) + `sub` (sign / 签发) |
| X25519 private key / 私钥 | `tools gen-secret` (relay blob) | `relay` only — VLESS Encryption handshake / 仅 relay 握手用 |
| X25519 public key / 公钥 | `tools gen-secret` (sub blob) | `sub` writes it into `encryption=...`; clients negotiate from it / 写进链接，客户端据此协商 |
| Single `vless://` / 单条链接 | `tools gen-link` | straight into a client (no sub) / 直接喂给客户端 |
| Full subscription / 整组订阅 | `sub` worker (`GET /sub?token=…`) | straight into a client (recommended) / 直接喂给客户端（推荐） |
| Deploy bundle / 部署产物 | `tools bundle` | `wrangler deploy` — no source build / 直接部署，无需编译 |

### Hard constraints / 关键约束

- **`VEILWEAVE_NODES` in `sub` must pair one-to-one with each relay's
  `SECRET_KEY`.** A mismatched blob means 401 (MAC failure) for that node's links.
  Production: `tools gen-secret` once per relay node.
  **`sub` 里的 `VEILWEAVE_NODES` 必须与 `relay` 的 `SECRET_KEY` 一一对应**。
  填错密钥对应链接会 401。生产环境建议每个 relay 节点各生成一对 blob。
- **`tools gen-link --secret-key` must match the relay's deployed `SECRET_KEY`**,
  or the link is 401 as well. **`gen-link` 的 `--secret-key` 必须与 relay 部署时
  的 `SECRET_KEY` 一致**，否则同样 401。
- **Never commit production blobs.** Use `wrangler secret put SECRET_KEY` for
  production injection. **不要**把生产 blob 写进 commit；用
  `wrangler secret put SECRET_KEY` 注入。
- The `sub` KV caches entry IPs (24 h) and rendered subscriptions (1 h); the cold
  path stays under 5 subrequests, far below the free plan's 50/request cap.
  `sub` 的 KV 缓存入口 IP（24 h）与渲染好的订阅（1 h），冷路径 < 5 个子请求，
  远低于免费版 50/请求的上限。

## Common scenarios / 常见组合场景

**A. Single relay + single egress IP — minimal / 单 relay + 单出口 IP（最小部署）**

```
1. tools gen-secret                                    → 1 blob pair
2. relay/wrangler.toml: SECRET_KEY=<relay blob>  →  wrangler deploy
3. tools gen-link --type proxyip --proxy-ip 1.2.3.4 …  → one vless:// link
4. import into client / 客户端导入
```

**B. Single relay + multi entry IP + subscription / 单 relay + 多入口 IP + 订阅分发**

Deploy relay + sub, hand out `https://<sub>/sub?token=<TOKEN>` — sub auto-filters
optimized CT/CU/CMCC edge IPs by the user's CF-ASN.
部署 relay + sub，分发订阅地址——sub 会按用户 CF-ASN 自动筛三网优选 IP。

**C. Multi-relay high availability / 多 relay 节点（高可用）**

One blob pair per relay, all of them listed comma-separated in `VEILWEAVE_NODES`.
Codecs are per-node independent — links never cross-validate.
每个 relay 一对 blob，全部逗号分隔写进 `VEILWEAVE_NODES`；不同节点链接互不通用。

**D. Direct egress (no proxyip) / 纯直连**

```
tools gen-link --type direct --secret-key <relay blob>
```

The UUID's `type_byte=0x00` tells relay to dial the target directly.
UUID 编码里 `type_byte=0x00`，relay 看到后直连目标。

## Performance notes / 性能设计要点

| Optimization / 优化 | Payoff / 收益 | How / 怎么做的 |
|---|---|---|
| WebSocket Hibernation | 10 ms CPU budget per frame / 每帧 10 ms CPU 预算 | `accept_web_socket` + `websocket_message` |
| WebCrypto AES-NI | 10×+ throughput / 吞吐 10×+ | `crypto.subtle.encrypt` in BoringSSL |
| `+simd128` handshake | handshake CPU halved / 握手 CPU 减半 | `.cargo/config.toml` + `blake3/wasm32_simd` |
| Pipeline + coalesce download | WebCrypto calls ÷4 / 调用数 ÷4 | background loop, merge ≤ 16 KiB |
| Zero-copy upload | no wasm memory growth / wasm 内存不增 | `Uint8Array` straight into WebCrypto |
| Per-isolate codec | constant-time UUID verify / 验签常数时间 | `OnceCell` + 16-entry LRU |
| Direct-first ProxyIP | most requests skip the detour / 多数请求不绕道 | fall back to ProxyIP only on dial failure |

Full version / 完整版： [`docs/architecture.md`](docs/architecture.md).

## Client compatibility / 协议兼容性

| Client / 客户端 | OK / 兼容 | Notes / 备注 |
|---|---|---|
| xray-core (≥ 1.9.x) | ✅ | recommended / 推荐 |
| sing-box (≥ 1.9.x) | ✅ | leave `flow=...` empty / `flow` 留空即可 |
| v2rayN / NekoBox | ✅ | latest core / 用最新 core |
| mihomo | ✅ | pick the VLESS node type / 选 VLESS 节点类型 |
| Clash for Windows | ⚠️ | Clash Verge Rev works; stock Clash lacks `encryption=...` / 原版 Clash 不支持 `encryption=...` |

## Build & test (development) / 构建与测试（开发）

```bash
cargo build --release --target wasm32-unknown-unknown --manifest-path relay/Cargo.toml
cargo build --release --target wasm32-unknown-unknown --manifest-path sub/Cargo.toml
cargo build --release                                       --manifest-path tools/Cargo.toml

# local relay dev server / 本地跑 relay（需 wrangler 已登录）
cd relay && wrangler dev

# fmt check (CI enforces) / 格式化检查（CI 会跑）
cargo fmt --manifest-path relay/Cargo.toml -- --check
cargo fmt --manifest-path sub/Cargo.toml   -- --check
cargo fmt --manifest-path tools/Cargo.toml -- --check
```

## Releases / 发布

Pushing a `v*` tag (or running the **Release** workflow manually) builds the CLI
for Windows/Linux/macOS and both workers, then publishes per-platform archives
containing everything the no-build flow needs. See
[`.github/workflows/release.yml`](.github/workflows/release.yml).

推送 `v*` tag（或手动触发 **Release** workflow）会构建三平台 CLI 和两个 worker，
并发布包含免编译部署全部所需文件的分平台压缩包。

## Docs / 文档

- [`docs/architecture.md`](docs/architecture.md) — data plane / handshake / protocol design · 数据面/握手/协议设计
- [`docs/deployment.md`](docs/deployment.md) — production deploy, key rotation, monitoring · 生产部署、密钥轮换、监控
- [`docs/protocol.md`](docs/protocol.md) — wire format of signed UUIDs and encrypted records · 签名 UUID 与加密 record 线格式
- [`relay/README.md`](relay/README.md) — data-plane Worker details · 数据面 Worker 细节
- [`sub/README.md`](sub/README.md) — subscription Worker details · 订阅 Worker 细节
- [`tools/README.md`](tools/README.md) — CLI reference · CLI 参考
- [`CHANGELOG.md`](CHANGELOG.md) — what changed in each version · 版本变更
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute · 贡献指南
- [`SECURITY.md`](SECURITY.md) — security disclosure policy · 安全披露策略

## License & legal / 协议与法律

[MIT](LICENSE).

**This project is a network proxy / tunnel relay tool.** Use it in compliance
with the laws of your jurisdiction and applicable terms of service. The authors
accept no liability for misuse.

**本项目是一个网络代理 / 隧道中继工具**。请在遵守所在国家/地区法律法规和
服务条款的前提下使用。作者不为任何滥用行为承担责任。

## Security / 安全

**Do not report security-sensitive issues in public issues.**
See [`SECURITY.md`](SECURITY.md).
**请勿在公开 issue 中报告安全敏感问题**，详见 [`SECURITY.md`](SECURITY.md)。

## Contributing / 贡献

PRs and issues welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
Commits follow Conventional Commits; `CODEOWNERS` routes reviews automatically.
欢迎 PR 和 issue；提交请遵循 Conventional Commits，`CODEOWNERS` 会自动路由评审。
