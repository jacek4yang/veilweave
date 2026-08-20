<div align="center">

# veilweave

**Post-quantum, forward-secret VLESS over WebSocket — end-to-end through Cloudflare Workers**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 1.81+](https://img.shields.io/badge/Rust-1.81%2B-orange.svg)](https://www.rust-lang.org)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![WASM SIMD](https://img.shields.io/badge/WASM-SIMD128-9cf)](https://webassembly.org/features/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A faithful Rust port of xray-core's `mlkem768x25519plus` VLESS Encryption, designed
to run on the Cloudflare Workers free plan. A per-connection Durable Object terminates
the encrypted stream, the bulk data path runs through WebCrypto AES-NI, and every
on-path observer — including Cloudflare itself — sees only opaque bytes.

</div>

---

## 项目是什么

`veilweave` 是一个**单仓库三件套**：

| 子项目 | 形态 | 作用 |
|--------|------|------|
| **`relay/`** | Cloudflare Worker (Rust → WASM) | **数据面**：终止 VLESS+WS+Encryption 连接，转发到目标站点 |
| **`sub/`** | Cloudflare Worker (Rust → WASM) | **订阅面**：生成 `vless://…` 链接列表，支持多出口 IP/多入口 IP |
| **`tools/`** | 原生 CLI (Rust) | **运维面**：生成配套密钥、签发单条链接 |

三者共用同一套「签名 UUID」编解码（HKDF + HMAC-SHA256 + 5 字节 MAC）。**UUID 只在签名它的密钥下能解码**，所以每个 relay 节点只接受自己的链接；sub 用对应密钥签出 UUID，relay 用同一把密钥验签——天然支持多 relay 节点、统一订阅源。

## 为什么要做这个

普通的「VLESS over WS on Cloudflare Worker」有一个根本问题：

> Worker 跑在 Cloudflare **TLS 终结之后**——Cloudflare 自己就能看到明文的目的地和载荷。

veilweave 的解法：在 **WS 内部**再套一层端到端加密——xray-core 的 `mlkem768x25519plus` 协议，混合后量子前向保密（**ML-KEM-768 + X25519**，每次连接换密钥），BLAKE3 派生，**AES-256-GCM** AEAD。这样：

- 客户端 ↔ Worker 之间的字节是**不可区分的密文**；
- Cloudflare、链路上的任何中间人都看不到目的地和内容；
- 任何一次连接的临时密钥都不会影响其他连接（前向保密）；
- 量子计算机将来也无法回溯（后量子）。

而且整套设计是为 **Workers 免费版 10 ms / 调用的 CPU 上限** 量身打造的：

- 每条入站 WS 帧 = 一次独立 invocation（WebSocket Hibernation API），post-quantum 握手不会和 bulk upload 挤爆同一个 10 ms 窗口；
- bulk AES-GCM 走 WebCrypto（BoringSSL/AES-NI），payload 字节不进入 wasm 线性内存；
- 下载路径 pipeline + 合并 ≤16 KiB/record，WebCrypto 调用次数和 `ws.send` 次数都减半。

## 整体架构

```
                                ┌────────────────────────┐
                                │  veilweave-tools (CLI) │
                                │  gen-secret / gen-link │
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
                  目标站点

            ┌──────────────────────┐
            │   sub  worker        │   GET /sub?token=…   →   vless:// 链接列表
            │  (subscription)      │
            │  ● KV 缓存           │
            └──────────┬───────────┘
                       │  同一份签名 UUID codec
                       ▼
                  客户端导入
```

## 仓库结构

```
veilweave/
├── relay/                    # 数据面 Worker（veilweave crate）
│   ├── src/                  # Rust 源码（enc/session/vless/codec/...）
│   ├── static/               # Apache 伪装页
│   ├── .cargo/config.toml    # +simd128 等 wasm target features
│   ├── Cargo.toml
│   ├── wrangler.toml         # Worker 部署配置
│   └── README.md
│
├── sub/                      # 订阅 Worker（veilweave-sub crate）
│   ├── src/                  # Rust 源码（lib/codec/optimized_ip/...）
│   ├── static/               # Apache 伪装页
│   ├── .cargo/config.toml
│   ├── Cargo.toml
│   ├── wrangler.toml
│   └── README.md
│
├── tools/                    # CLI（veilweave-tools crate，原生二进制）
│   ├── src/
│   ├── Cargo.toml
│   └── README.md
│
├── docs/                     # 设计 / 部署 / 协议文档
│   ├── architecture.md
│   ├── deployment.md
│   └── protocol.md
│
├── .github/                  # Issue 模板、PR 模板、CI workflow
│   ├── ISSUE_TEMPLATE/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/ci.yml
│
├── .editorconfig             # 编辑器风格
├── .gitattributes            # git 属性（行尾、Linguist）
├── .gitignore                # 忽略 target/、.wrangler/、build/、secrets
│
├── CHANGELOG.md              # 版本变更日志
├── CODEOWNERS                # 评审路由
├── CONTRIBUTING.md           # 贡献指南
├── LICENSE                   # MIT
├── README.md                 # 你正在看的文件
└── SECURITY.md               # 安全披露策略
```

> 三个子项目**互相独立**，各自有自己的 `Cargo.toml` / `wrangler.toml` / `README.md`。
> 没有 Cargo workspace 顶层文件——是因为 `relay` 和 `sub` 都是 cdylib，要走 `wasm32-unknown-unknown`；`tools` 是原生二进制走宿主目标，混在一起反而麻烦。每个子目录独立 build / deploy 更清爽。

## 快速开始（端到端 5 步）

> 前置：`rustup`、已安装 `wasm32-unknown-unknown` target、`wrangler ≥ 3`、一个 Cloudflare 账号（免费版即可）。

### 第 1 步：拉代码 & 装工具链

```bash
git clone https://github.com/<owner>/veilweave.git
cd veilweave
rustup target add wasm32-unknown-unknown
cargo install wrangler --locked
```

### 第 2 步：生成配套密钥

```bash
cargo run -p veilweave-tools -- gen-secret
```

输出形如：

```
── veilweave relay ──  set  SECRET_KEY  to:
  VlcxAKSNn…                ← 粘到  relay/wrangler.toml  [vars].SECRET_KEY
── veilweave-sub ──  use in  VEILWEAVE_NODES  as  <domain>|<blob>:
  VlcxAaSNn…                ← 粘到  sub/wrangler.toml    [vars].VEILWEAVE_NODES
```

> 上面这对 blob 共享同一个 UUID 签名密钥 + 一对匹配的 X25519 私/公钥。
> 私钥给 relay 用于 VLESS Encryption PFS 握手，公钥给 sub 用于把公钥写进
> `vless://…&encryption=mlkem768x25519plus.native.1rtt.<pubkey>…`。

### 第 3 步：填入密钥并部署 relay

把上一步的 **relay blob** 填入 `relay/wrangler.toml` 的 `[vars].SECRET_KEY`，
然后：

```bash
cd relay
wrangler deploy
```

部署完会得到一个域名 `https://veilweave.<your-subdomain>.workers.dev`。
记下它——sub 和客户端都要用。

### 第 4 步：填入节点并部署 sub

把 **sub blob** 填入 `sub/wrangler.toml` 的 `[vars].VEILWEAVE_NODES`：

```toml
VEILWEAVE_NODES = "veilweave.example.com|<sub blob>"
```

可以逗号分隔多节点（多 relay 域名），sub 会按用户所在运营商做轮换。

```bash
cd ../sub
# 先建一个 KV namespace 给 sub 用
wrangler kv:namespace create VEILWEAVE_KV
# 把输出的 id 填到 sub/wrangler.toml 的 [[kv_namespaces]].id
wrangler deploy
```

部署完得到 sub worker 的域名，记下访问令牌 `SUBSCRIPTION_TOKEN`（写在 `sub/wrangler.toml` 的 `[vars]` 里）。

### 第 5 步：拉一条测试链接

```bash
cd ..
cargo run -p veilweave-tools -- gen-link \
  --address veilweave.<your-subdomain>.workers.dev \
  --port 443 \
  --type proxyip \
  --proxy-ip 1.2.3.4 \
  --proxy-port 443 \
  --secret-key "<上一步的 relay blob>"
```

把输出的 `vless://…` 链接粘到 v2rayN / NekoBox / mihomo / sing-box 里，
连上即可。客户端握手时会自动协商 `mlkem768x25519plus` 加密。

### 第 6 步（可选）：用 sub worker 发订阅

打开浏览器：

```
https://<sub-worker-domain>/sub?token=<SUBSCRIPTION_TOKEN>
```

会得到一个 base64 文本，就是一组 `vless://` 链接列表（多个 entry IP × 多个 egress IP），
直接粘到客户端订阅栏里。

---

## 三件套怎么搭配

下面这张表是「**谁用谁、谁配谁**」的总览：

| 流程                | 谁生成                          | 谁使用                          |
|---------------------|----------------------------------|----------------------------------|
| UUID 签名密钥       | `tools gen-secret`               | 同时被 `relay`（验签）和 `sub`（签发）使用 |
| X25519 私钥         | `tools gen-secret`（relay blob） | 仅 `relay` 用于 VLESS Encryption 握手 |
| X25519 公钥         | `tools gen-secret`（sub blob）   | `sub` 写进 `vless://` 的 `encryption=...` 字段；客户端据此协商 |
| 单条 `vless://`     | `tools gen-link`                 | 直接喂给客户端（不走 sub）       |
| 整组订阅             | `sub` worker（`GET /sub?token=…`）| 直接喂给客户端（推荐）           |
| Apache 伪装页        | 内置在 `relay` / `sub`           | 浏览器访问非 WS 路径时返回        |

### 关键约束

- **`sub` 里的 `VEILWEAVE_NODES` 必须与 `relay` 的 `SECRET_KEY` 一一对应**。一个 sub 节点填错密钥，对应链接会 401（MAC 验证失败）。生产环境建议 `tools gen-secret` 给每个 relay 节点各生成一对 blob。
- **`tools gen-link` 用的 `--secret-key` 必须与 `relay` 部署时的 `SECRET_KEY` 一致**。否则单条链接也是 401。
- **不要**把生产 blob 写进 commit；用 `wrangler secret put SECRET_KEY` 注入到生产环境。
- `sub` worker 的 KV 是**入口 IP 缓存**（24 h）+ 渲染好的订阅缓存（1 h）。冷路径 < 5 个子请求，远低于免费版 50/请求的上限。

## 常见组合场景

### 场景 A：单 relay + 单出口 IP

最小部署。最快上手。

```
1. tools gen-secret                                       → 拿到 1 对 blob
2. relay/wrangler.toml: SECRET_KEY=<relay blob>           wrangler deploy
3. tools gen-link --type proxyip --proxy-ip 1.2.3.4 …     → vless:// 一条
4. 客户端导入
```

### 场景 B：单 relay + 多 entry IP + 订阅分发

想给一群人发订阅，且希望按运营商自动选最近的 CF 边缘。

```
1. tools gen-secret → blob
2. 部署 relay（同上）
3. 部署 sub，VEILWEAVE_NODES = "relay.example.com|<sub blob>"
4. 客户端订阅地址: https://<sub>/sub?token=<TOKEN>
   sub 会按 CF-ASN 自动给用户筛 CT/CU/CMCC 的优选 IP
```

### 场景 C：多 relay 节点（高可用）

每个节点用 `tools gen-secret` 单独生成一对 blob（一对 blob 共享一个 UUID 签名密钥，
但你可以**给每个 relay 不同的密钥**——只要 sub 知道每个节点配哪个 blob）。

```
sub/wrangler.toml:
  VEILWEAVE_NODES = "a.example.com|<blob-a>, b.example.com|<blob-b>"
  # 注意 sub 的 UUID codec 是节点级独立的——不同 blob 之间的链接互不通用
```

### 场景 D：纯直连（不绕道 proxyip）

只想用 Cloudflare 的中转，不想再走第三方程 IP：

```
tools gen-link --type direct --secret-key <relay blob>
```

UUID 编码里 `type_byte=0x00`，relay 看到后直连目标。

---

## 性能设计要点

| 优化 | 收益 | 怎么做的 |
|------|------|----------|
| WebSocket Hibernation | 每帧 10 ms CPU 预算 | `accept_web_socket` + `websocket_message` 回调 |
| WebCrypto AES-NI | 吞吐 10×+ 提升 | `crypto.subtle.encrypt` 在 BoringSSL 中跑 |
| `+simd128` 握手 | 握手 CPU 减半 | `.cargo/config.toml` + `blake3/wasm32_simd` |
| Pipeline + coalesce 下载 | WebCrypto 调用数 ÷4 | 一个 background loop，已到 chunk 合 ≤16 KiB |
| 零拷贝 upload | wasm 内存不增 | `Uint8Array` 直通 WebCrypto |
| Per-isolate codec | UUID 验签常数时间 | `OnceCell` + LRU 16 项 |
| Direct-first ProxyIP | 多数请求不绕道 | 直连失败才回退 ProxyIP |

完整版见 [`docs/architecture.md`](docs/architecture.md)。

## 协议兼容性

| 客户端              | 兼容 | 备注 |
|---------------------|------|------|
| xray-core (≥ 1.9.x) | ✅  | 推荐 |
| sing-box (≥ 1.9.x)  | ✅  | `flow=...` 留空即可 |
| v2rayN / NekoBox    | ✅  | 用最新 core |
| mihomo              | ✅  | 选 VLESS 节点类型 |
| Clash for Windows   | ⚠️  | Clash Verge Rev 可，原版 Clash 不支持 `encryption=...` |

## 构建 & 测试

```bash
# 三个 crate 全部编译
cargo build --release --target wasm32-unknown-unknown --manifest-path relay/Cargo.toml
cargo build --release --target wasm32-unknown-unknown --manifest-path sub/Cargo.toml
cargo build --release                                       --manifest-path tools/Cargo.toml

# 本地跑 relay（需要 Cloudflare 账户已登录 wrangler）
cd relay && wrangler dev

# 格式化检查（CI 会跑）
cargo fmt --manifest-path relay/Cargo.toml -- --check
cargo fmt --manifest-path sub/Cargo.toml   -- --check
cargo fmt --manifest-path tools/Cargo.toml -- --check
```

## 文档

- [`docs/architecture.md`](docs/architecture.md) — 数据面 / 握手 / 协议的设计
- [`docs/deployment.md`](docs/deployment.md) — 生产部署、密钥轮换、监控
- [`docs/protocol.md`](docs/protocol.md) — 签名 UUID 与加密 record 的线格式
- [`relay/README.md`](relay/README.md) — 数据面 Worker 细节
- [`sub/README.md`](sub/README.md) — 订阅 Worker 细节
- [`tools/README.md`](tools/README.md) — CLI 参考

## 文档分层速查

> 「我想 **X**，应该看哪个文件？」

| 我想知道…                          | 文档                                |
|-------------------------------------|--------------------------------------|
| 项目整体长啥样、怎么用              | `README.md`（本文件）                |
| 怎么部署、密钥怎么轮换              | `docs/deployment.md`                 |
| 为什么这么设计（性能、协议）        | `docs/architecture.md`               |
| 线格式怎么定义                      | `docs/protocol.md`                   |
| relay worker 的细节                  | `relay/README.md`                    |
| sub worker 的细节                    | `sub/README.md`                      |
| CLI 怎么用                          | `tools/README.md`                    |
| 怎么贡献代码                        | `CONTRIBUTING.md`                    |
| 怎么报告安全漏洞                    | `SECURITY.md`                        |
| 这个版本改了什么                    | `CHANGELOG.md`                       |

## 协议 & 法律

[MIT](LICENSE) — 见 `LICENSE`。

**本项目是一个网络代理 / 隧道中继工具**。请在遵守所在国家/地区法律法规和服务条款的前提下使用。
作者不为任何滥用行为承担责任。

## 安全

**请勿在公开 issue 中报告安全敏感问题**。详见 [`SECURITY.md`](SECURITY.md)。

## 贡献

欢迎 PR 和 issue——详见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。
提交请遵循 Conventional Commits；`CODEOWNERS` 会自动路由评审。
