<div align="center">

# veilweave

**VLESS over WebSocket on Cloudflare Workers — plaintext by default, with an experimental post-quantum encryption option**

**Cloudflare Workers 上的 VLESS over WebSocket —— 默认明文直通，可选实验性后量子加密**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 1.81+](https://img.shields.io/badge/Rust-1.81%2B-orange.svg)](https://www.rust-lang.org)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![WASM SIMD](https://img.shields.io/badge/WASM-SIMD128-9cf)](https://webassembly.org/features/)
[![Release](https://img.shields.io/github/v/release/jacek4yang/veilweave)](https://github.com/jacek4yang/veilweave/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A VLESS + WebSocket proxy stack built for the Cloudflare Workers free plan: a
relay worker whose per-connection Durable Object forwards traffic with near-zero
per-frame CPU, a subscription worker, and a native deployer (GUI + CLI) that
publishes everything through the Cloudflare API. The default datapath is
**plaintext passthrough**; an experimental, opt-in VLESS Encryption layer
(xray-core `mlkem768x25519plus`: ML-KEM-768 + X25519 + AES-256-GCM) can hide the
stream from on-path observers at a much higher CPU cost.

为 Cloudflare Workers 免费套餐打造的 VLESS + WebSocket 代理三件套：relay
worker 用独立的 Durable Object 逐连接转发，每帧 CPU 开销接近零；订阅 worker
分发链接；原生部署器（GUI + CLI）直接通过 Cloudflare API 完成部署。默认数据
面是**明文直通**；另有一个实验性、需手动开启的 VLESS Encryption 加密层
（xray-core `mlkem768x25519plus`：ML-KEM-768 + X25519 + AES-256-GCM），可以
对链路上的观察者隐藏流量，但 CPU 开销大得多。

</div>

---

## ⚡ Quick deploy — no build required / 快捷部署 —— 无需编译

> **You don't need Rust, cargo, wrangler, Node.js, or the source code.**
> Download a release, run the deployer, get a subscription URL. ~5 minutes.
>
> **不需要 Rust、cargo、wrangler、Node.js 或源码。** 下载 release，运行部署器，
> 拿到订阅地址，约 5 分钟完成。

**Prerequisites / 前置条件：** one or more free Cloudflare accounts.
一个或多个免费 Cloudflare 账号。

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
veilweave-tools(.exe)   ← deployer GUI + CLI / 部署器（图形界面 + 命令行）
bundle/relay/build/     ← PREBUILT relay worker (no compilation needed / 预编译)
bundle/sub/build/       ← PREBUILT sub worker   (no compilation needed / 预编译)
QUICKSTART.txt
```

### 2. Run the deployer / 运行部署器

**Windows: double-click `veilweave-tools.exe`.** The GUI ("veilweave 部署器")
opens with three pages: **Accounts / Deploy / Manage**.
Everyone else: run `./veilweave-tools` with no arguments for the same GUI, or
`./veilweave-tools deploy` for the interactive CLI wizard — identical flow.

**Windows 直接双击 `veilweave-tools.exe`**，打开图形界面「veilweave 部署器」
（账号 / 部署 / 管理三个页面）；其他系统不带参数运行 `./veilweave-tools`
打开同样的界面，或用 `./veilweave-tools deploy` 走交互式命令行向导——流程
完全一样。

1. **Accounts / 账号** — add one or more Cloudflare accounts with an API token.
   The app opens <https://dash.cloudflare.com/profile/api-tokens>
   ("Create Custom Token"); the token needs:
   用一个 API token 添加一个或多个 Cloudflare 账号。程序会打开
   <https://dash.cloudflare.com/profile/api-tokens>（"Create Custom Token"），
   token 需要以下权限：
   - Account → Workers Scripts → **Edit**
   - Account → Workers KV Storage → **Edit**
   - Account → Account Settings → **Read**（用于解析 workers.dev 子域）
2. **Deploy / 部署** — pick the topology: which account hosts the **sub**
   worker, and how many **relays** on which accounts (each relay gets its own
   secret). Confirm — the deployer creates the KV namespace, uploads both
   workers via the Cloudflare API, and prints your **subscription URL**.
   规划拓扑：sub 放哪个账号、部署几个 relay、分别放哪些账号（每个 relay
   独立密钥）。确认后部署器会自动创建 KV、通过 Cloudflare API 上传两个
   worker，并打印**订阅地址**。
3. **Manage / 管理** — list deployments, re-show a subscription URL, or delete
   a worker (and its KV namespace).
   列出现有部署、重新查看订阅地址、删除 worker（及其 KV）。

> **Pick your own names / 建议自定义命名：** worker names, KV titles, and
> binding names are randomized by default, and you are encouraged to choose
> your own — the sub worker finds its KV namespace via the `KV_BINDING` var,
> so any valid binding name works.
> worker 名称、KV 名称、绑定名默认随机生成，也建议你改成自己的——sub
> 通过 `KV_BINDING` 变量定位 KV 命名空间，任何合法绑定名都可以。

### 3. Subscribe / 订阅

```
https://<sub-domain>/sub?token=<SUBSCRIPTION_TOKEN>
```

The deployer prints this URL at the end (recoverable anytime via Manage /
`veilweave-tools manage`). Paste the base64 response into
v2rayN / NekoBox / mihomo / sing-box.
部署完成后会打印该地址（之后可随时在「管理」页 / `veilweave-tools manage`
重新查看）。把返回的 base64 文本粘到 v2rayN / NekoBox / mihomo / sing-box
的订阅栏即可。

### Advanced: `bundle` + wrangler (manual) / 手动方式：bundle + wrangler

Prefer wrangler, or want to audit every generated file? The classic flow is
still there — it needs [`wrangler`](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
(`npm i -g wrangler`, then `wrangler login`):
如果你更习惯 wrangler，或想逐个检查生成的文件，传统流程仍然可用（需要
wrangler：`npm i -g wrangler`，然后 `wrangler login`）：

```bash
./veilweave-tools bundle                       # writes dist/<relay>/ + dist/<sub>/
cd dist/<relay-name> && wrangler deploy        # note the *.workers.dev domain
# edit dist/<sub-name>/wrangler.toml → put that domain in VEILWEAVE_NODES
cd dist/<sub-name>
wrangler kv:namespace create <KV_BINDING>      # binding name is in the generated
                                               # wrangler.toml (randomized, e.g. kv_x7f2a9);
                                               # paste the printed id into [[kv_namespaces]].id
wrangler deploy
```

```bash
./veilweave-tools bundle                       # 生成 dist/<relay目录>/ + dist/<sub目录>/
cd dist/<relay目录> && wrangler deploy          # 记下 *.workers.dev 域名
# 编辑 dist/<sub目录>/wrangler.toml → 把域名填进 VEILWEAVE_NODES
cd dist/<sub目录>
wrangler kv:namespace create <KV_BINDING>       # 绑定名见生成的 wrangler.toml
                                                # （随机生成，如 kv_x7f2a9）；
                                                # 把输出的 id 填进 [[kv_namespaces]].id
wrangler deploy
```

> **Every run is unique / 每次运行都独一无二：**
>
> - fresh UUID-signing secret per relay / 每个 relay 全新的 UUID 签名密钥
> - randomized worker names and KV binding / 随机化的 worker 名称与 KV 绑定名
> - randomized subscription token / 随机订阅令牌
> - a per-run nonce injected into each script, so **your artifact never shares a
>   content hash with anyone else's** — no fleet-wide fingerprint for Cloudflare
>   to flag / 每个脚本注入一次性随机串，**你的产物哈希与任何其他人都不相同**，
>   不会因批量指纹被 Cloudflare 标记

---

## What is this / 项目是什么

`veilweave` is **one repo, three components / 单仓库三件套**:

| Component / 子项目 | Form / 形态 | Role / 作用 |
|---|---|---|
| **`relay/`** | Cloudflare Worker (Rust → WASM) | **Data plane / 数据面**: terminates VLESS+WS (plaintext passthrough by default; optional VLESS Encryption), forwards to targets / 终止 VLESS+WS 连接（默认明文直通，可选加密），转发到目标站点 |
| **`sub/`** | Cloudflare Worker (Rust → WASM) | **Subscription plane / 订阅面**: serves `vless://…` link lists, multi egress/entry IP / 生成 `vless://…` 链接列表，支持多出口/入口 IP |
| **`tools/`** | Native GUI + CLI (Rust) | **Ops plane / 运维面**: deploys to Cloudflare accounts via API (multi-account topologies), keypairs, single links, wrangler bundles / 通过 Cloudflare API 部署（支持多账号拓扑）、生成配套密钥、签发单条链接、生成 wrangler 部署产物 |

All three share the same "signed UUID" codec (HKDF + HMAC-SHA256 + 5-byte MAC).
**A UUID only decodes under the key that signed it**, so every relay node accepts
only its own links: sub signs UUIDs with one key, relay verifies with the same
key — multi-relay nodes behind one subscription source, natively.

三者共用同一套「签名 UUID」编解码（HKDF + HMAC-SHA256 + 5 字节 MAC）。
**UUID 只在签名它的密钥下能解码**，所以每个 relay 节点只接受自己的链接；
sub 用对应密钥签出 UUID，relay 用同一把密钥验签——天然支持多 relay 节点、
统一订阅源。

## Encryption: default vs. optional / 加密：默认与可选

Plain "VLESS over WS on a Cloudflare Worker" has a fundamental limitation:

普通的「VLESS over WS on Cloudflare Worker」有一个根本限制：

> The Worker runs **after Cloudflare's TLS termination** — Cloudflare itself can
> see the plaintext destination and payload.
>
> Worker 跑在 Cloudflare **TLS 终结之后**——Cloudflare 自己就能看到明文的目的地
> 和载荷。

**veilweave's default is honest about this tradeoff.** Out of the box the relay
serves plaintext VLESS passthrough (`encryption=none`): the hop client ↔
Cloudflare is still TLS-protected like any HTTPS site, but Cloudflare itself can
see the traffic — same trust model as any site hosted on Cloudflare. In return
you get near-zero per-frame CPU, comfortably inside the free plan's 10 ms
per-invocation budget.

**veilweave 的默认模式对这个取舍是坦诚的。** 开箱即用是明文 VLESS 直通
（`encryption=none`）：客户端 ↔ Cloudflare 这一跳仍然像普通 HTTPS 站点一样
有 TLS 保护，但 Cloudflare 自己能看到流量——信任模型与任何托管在
Cloudflare 上的站点相同。换来的是每帧接近零的 CPU 开销，轻松落在免费版
10 ms / 调用的预算内。

**For stronger confidentiality there is an experimental opt-in:** xray-core's
`mlkem768x25519plus` VLESS Encryption, a second end-to-end layer **inside the
WS** — hybrid post-quantum forward secrecy (**ML-KEM-768 + X25519**, fresh keys
per connection), BLAKE3 derivation, **AES-256-GCM** AEAD (via WebCrypto
AES-NI). Then client ↔ Worker bytes are indistinguishable ciphertext and
Cloudflare sees neither destination nor content. The cost: the per-connection
handshake and per-record AEAD are CPU-heavy and can exceed the free plan's CPU
limit, so it is **off by default** — enable it with `gen-secret --encryption` /
`bundle --encryption`, or by setting the relay's `SECRET_KEY` to a `VW1` blob.

**如果对机密性要求更高，还有一个实验性的可选加密层**：xray-core 的
`mlkem768x25519plus` VLESS Encryption，在 **WS 内部**再套一层端到端加密——
混合后量子前向保密（**ML-KEM-768 + X25519**，每次连接换密钥），BLAKE3
派生，**AES-256-GCM** AEAD（走 WebCrypto AES-NI）。开启后客户端 ↔ Worker
之间的字节是不可区分的密文，Cloudflare 看不到目的地和内容。代价是每次连接
的握手和每条 record 的 AEAD 都很吃 CPU，可能超出免费版的 CPU 上限，所以
**默认关闭**——用 `gen-secret --encryption` / `bundle --encryption`，或把
relay 的 `SECRET_KEY` 设为 `VW1` blob 来开启。

The encrypted datapath is tuned for the **Workers free plan's 10 ms CPU cap per
invocation**: every inbound WS frame is its own invocation (WebSocket Hibernation
API), bulk AES-GCM runs in WebCrypto (BoringSSL/AES-NI), and the download path
pipelines + coalesces records to halve WebCrypto and `ws.send` calls.

加密数据面针对 **Workers 免费版 10 ms / 调用的 CPU 上限**做了专门优化：每条
入站 WS 帧 = 一次独立 invocation（WebSocket Hibernation API）；bulk AES-GCM
走 WebCrypto（BoringSSL/AES-NI）；下载路径 pipeline + 合并 ≤16 KiB/record，
WebCrypto 调用次数和 `ws.send` 次数都减半。

## Architecture / 整体架构

```
                                ┌───────────────────────────────┐
                                │  veilweave-tools (GUI + CLI)  │
                                │  deploy / manage              │
                                │  gen-secret / gen-link        │
                                │  bundle                       │
                                └───────────┬───────────────────┘
                                            │  shared secret (raw; or VW1 blob pair with --encryption)
                       ┌────────────────────┴────────────────────┐
                       │                                         │
                       ▼                                         ▼
            ┌──────────────────────┐                  ┌──────────────────────┐
            │   relay  worker      │ ◄── WS+TLS ─── │   xray / sing-box /   │
            │  (data plane)        │   client         │   v2rayN 客户端      │
            │  ● Durable Object    │                  └──────────────────────┘
            │  ● plaintext relay   │
            │    (AES-GCM opt-in)  │
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
├── tools/                    # deployer GUI + CLI / 部署器（veilweave-tools crate, native binary）
│   ├── src/                  # deploy / manage / gen-secret / gen-link / bundle
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

# 1. one shared raw secret (plaintext default) / 生成共享密钥（默认明文）
cargo run --manifest-path tools/Cargo.toml -- gen-secret
#    (add --encryption for the EXPERIMENTAL mlkem768x25519plus blob pair)
#   （加 --encryption 则生成实验性 mlkem768x25519plus blob 对）

# 2. paste the secret into relay/wrangler.toml [vars].SECRET_KEY, then:
#    把密钥填入 relay/wrangler.toml 后：
cd relay && wrangler deploy

# 3. paste the same secret into sub/wrangler.toml [vars].VEILWEAVE_NODES as
#    <relay-domain>|<secret>, create the KV namespace, then:
#    把同一密钥以 <relay域名>|<密钥> 填入 sub/wrangler.toml，创建 KV 后：
cd ../sub
wrangler kv:namespace create VEILWEAVE_KV   # paste id into wrangler.toml
wrangler deploy

# 4. single test link / 单条测试链接
cd ..
cargo run --manifest-path tools/Cargo.toml -- gen-link \
  --address veilweave.<your-subdomain>.workers.dev \
  --port 443 --type proxyip --proxy-ip 1.2.3.4 --proxy-port 443 \
  --secret-key "<the same secret>"
```

Paste the resulting `vless://…` link into v2rayN / NekoBox / mihomo / sing-box.
Raw-secret links carry `encryption=none`; links generated from a `VW1` blob
carry `encryption=mlkem768x25519plus...` and clients negotiate it automatically
during the handshake.
把输出的 `vless://…` 链接粘到客户端即可。raw 密钥生成的链接是
`encryption=none`；用 `VW1` blob 生成的链接带 `encryption=mlkem768x25519plus...`，
客户端握手时自动协商。

## How the pieces fit / 三件套怎么搭配

| Flow / 流程 | Produced by / 谁生成 | Consumed by / 谁使用 |
|---|---|---|
| UUID signing secret / UUID 签名密钥 | `tools gen-secret` | `relay` (verify / 验签) + `sub` (sign / 签发) |
| X25519 private key / 私钥（加密模式） | `tools gen-secret --encryption` (relay blob) | `relay` only — VLESS Encryption handshake / 仅 relay 握手用 |
| X25519 public key / 公钥（加密模式） | `tools gen-secret --encryption` (sub blob) | `sub` writes it into `encryption=...`; clients negotiate from it / 写进链接，客户端据此协商 |
| Single `vless://` / 单条链接 | `tools gen-link` | straight into a client (no sub) / 直接喂给客户端 |
| Full subscription / 整组订阅 | `sub` worker (`GET /sub?token=…`) | straight into a client (recommended) / 直接喂给客户端（推荐） |
| One-shot deployment / 一键部署 | `tools deploy` (GUI or CLI) | Cloudflare API — no wrangler / 直接走 Cloudflare API |
| Deploy bundle / 部署产物 | `tools bundle` | `wrangler deploy` — no source build / 直接部署，无需编译 |

### Hard constraints / 关键约束

- **`VEILWEAVE_NODES` in `sub` must pair one-to-one with each relay's
  `SECRET_KEY`.** A mismatched secret means 401 (MAC failure) for that node's
  links. Production: `tools gen-secret` once per relay node.
  **`sub` 里的 `VEILWEAVE_NODES` 必须与 `relay` 的 `SECRET_KEY` 一一对应**。
  填错密钥对应链接会 401。生产环境建议每个 relay 节点各生成一把密钥。
- **`tools gen-link --secret-key` must match the relay's deployed `SECRET_KEY`**,
  or the link is 401 as well. **`gen-link` 的 `--secret-key` 必须与 relay 部署时
  的 `SECRET_KEY` 一致**，否则同样 401。
- **Never commit production secrets.** Use `wrangler secret put SECRET_KEY` for
  production injection. **不要**把生产密钥写进 commit；用
  `wrangler secret put SECRET_KEY` 注入。
- The `sub` KV caches entry IPs (24 h) and rendered subscriptions (1 h); the cold
  path stays under 5 subrequests, far below the free plan's 50/request cap.
  `sub` 的 KV 缓存入口 IP（24 h）与渲染好的订阅（1 h），冷路径 < 5 个子请求，
  远低于免费版 50/请求的上限。

## Common scenarios / 常见组合场景

**A. Single relay + single egress IP — minimal / 单 relay + 单出口 IP（最小部署）**

```
1. tools gen-secret                                    → 1 raw secret
2. relay/wrangler.toml: SECRET_KEY=<raw secret>  →  wrangler deploy
3. tools gen-link --type proxyip --proxy-ip 1.2.3.4 …  → one vless:// link
4. import into client / 客户端导入
```

**B. Single relay + multi entry IP + subscription / 单 relay + 多入口 IP + 订阅分发**

Deploy relay + sub, hand out `https://<sub>/sub?token=<TOKEN>` — sub auto-filters
optimized CT/CU/CMCC edge IPs by the user's CF-ASN.
部署 relay + sub，分发订阅地址——sub 会按用户 CF-ASN 自动筛三网优选 IP。

**C. Multi-relay high availability / 多 relay 节点（高可用）**

One secret per relay, all of them listed comma-separated in `VEILWEAVE_NODES` as
`<domain>|<secret>`. Codecs are per-node independent — links never cross-validate.
每个 relay 一把密钥，以 `<域名>|<密钥>` 逗号分隔写进 `VEILWEAVE_NODES`；不同
节点链接互不通用。（部署器可以直接跨多个账号完成这套拓扑。）

**D. Direct egress (no proxyip) / 纯直连**

```
tools gen-link --type direct --secret-key <raw secret>
```

The UUID's `type_byte=0x00` tells relay to dial the target directly.
UUID 编码里 `type_byte=0x00`，relay 看到后直连目标。

## Performance notes / 性能设计要点

The default plaintext datapath does no handshake and no per-record crypto —
per-frame CPU is essentially just the VLESS header check and the socket copy,
leaving the free plan's 10 ms budget almost entirely unused. The crypto-heavy
rows below matter only for the experimental encryption mode.

默认明文数据面没有握手、没有逐 record 加解密——每帧 CPU 基本只剩 VLESS 头
校验和 socket 转发，免费版 10 ms 预算几乎用不到。下表中与加密相关的优化只
在实验性加密模式下才起作用。

| Optimization / 优化 | Payoff / 收益 | How / 怎么做的 |
|---|---|---|
| WebSocket Hibernation | 10 ms CPU budget per frame / 每帧 10 ms CPU 预算 | `accept_web_socket` + `websocket_message` |
| WebCrypto AES-NI (encryption mode) | 10×+ throughput / 吞吐 10×+ | `crypto.subtle.encrypt` in BoringSSL |
| `+simd128` handshake (encryption mode) | handshake CPU halved / 握手 CPU 减半 | `.cargo/config.toml` + `blake3/wasm32_simd` |
| Pipeline + coalesce download (encryption mode) | WebCrypto calls ÷4 / 调用数 ÷4 | background loop, merge ≤ 16 KiB |
| Zero-copy upload (encryption mode) | no wasm memory growth / wasm 内存不增 | `Uint8Array` straight into WebCrypto |
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

Pushing a `v*` tag (or running the **Release** workflow manually) builds the
deployer for Windows/Linux/macOS and both workers, then publishes per-platform
archives containing everything the no-build flow needs. See
[`.github/workflows/release.yml`](.github/workflows/release.yml).

推送 `v*` tag（或手动触发 **Release** workflow）会构建三平台部署器和两个
worker，并发布包含免编译部署全部所需文件的分平台压缩包。

## Docs / 文档

- [`docs/architecture.md`](docs/architecture.md) — data plane / handshake / protocol design · 数据面/握手/协议设计
- [`docs/deployment.md`](docs/deployment.md) — production deploy, key rotation, monitoring · 生产部署、密钥轮换、监控
- [`docs/protocol.md`](docs/protocol.md) — wire format of signed UUIDs and encrypted records · 签名 UUID 与加密 record 线格式
- [`relay/README.md`](relay/README.md) — data-plane Worker details · 数据面 Worker 细节
- [`sub/README.md`](sub/README.md) — subscription Worker details · 订阅 Worker 细节
- [`tools/README.md`](tools/README.md) — deployer GUI + CLI reference · 部署器（GUI + CLI）参考
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
