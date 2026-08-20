# `relay/` — 数据面 Worker

Cloudflare Worker 实现的 **VLESS + WS + VLESS Encryption** 终结点。
每个连接在自己的 Durable Object 里跑握手和 bulk crypto，对外只暴露一
条 WSS 端点。

## 它做什么 / 不做什么

**做：**

- 接收来自 xray / sing-box / v2rayN 等客户端的 WSS 升级请求；
- 在自己的 Durable Object 里跑 ML-KEM-768 + X25519 + BLAKE3 混合 PFS 握手；
- 用 WebCrypto AES-NI 加解密 record（AES-256-GCM）；
- 验签 VLESS 头中的 16 字节 UUID（HMAC + HKDF 派生）；
- 按 UUID 编码里的 type byte 直连 / 走 ProxyIP / SOCKS5 / HTTP-CONNECT；
- 把上传字节流到目标、把下载字节封回 record 流给客户端；
- 对非 WS 请求返回 Apache 2.4.62 / Debian 伪装页。

**不做：**

- 不生成链接（那是 [`sub/`](../sub/) 的事）；
- 不管理密钥（那是 [`tools/`](../tools/) 的事）；
- 不持久化任何用户态（DO 是 `new_sqlite_classes` 但实际只用内存）；
- 不做 0-RTT 票证缓存（free plan 也没有跨 isolate 共享状态）；
- 不实现 ChaCha20-Poly1305（WebCrypto 不支持，留 AES-256-GCM 一种）。

## 文件结构

```
relay/
├── src/
│   ├── lib.rs            # #[event(fetch)] 入口：WS 升级 → DO
│   ├── session.rs        # VeilweaveSession Durable Object 状态机
│   ├── enc.rs            # VLESS Encryption (mlkem768x25519plus) 握手 + record 编解码
│   ├── vless.rs          # VLESS 头解析（UUID 验签 + 出口选择）
│   ├── codec.rs          # signed-UUID codec (HMAC-CTR + 5 字节 MAC)
│   ├── conn.rs           # 1 个 cloudflare:sockets TCP 连接的封装
│   ├── egress.rs         # Direct / ProxyIP / SOCKS5 / HTTP-CONNECT 出口
│   ├── datapath.rs       # 下载 loop（pipeline + coalescing）
│   ├── webcrypto.rs      # WebCrypto AES-GCM offload + 一次自检
│   ├── wsio.rs           # 给握手用的内存 reader
│   ├── rng.rs            # crypto.getRandomValues → RngCore 适配器
│   ├── hmac.rs           # 纯 Rust HMAC-SHA256 + HKDF
│   ├── sha256.rs         # 纯 Rust SHA-256（仅给 HMAC 用）
│   ├── secret.rs         # SECRET_KEY 解析（兼容 legacy raw + VW1 blob）
│   ├── apache_mock.rs    # 伪装页
│   └── log.rs            # perf-log feature 开关
│
├── static/                # 包含进 wasm 的静态资源
│   ├── apache_default.html
│   ├── apache_404.html
│   ├── favicon.ico
│   └── icons/openlogo-75.png
│
├── .cargo/config.toml     # wasm target features（+simd128 等）
├── Cargo.toml
├── wrangler.toml
└── README.md              # 你正在看的文件
```

## 快速部署

```bash
# 1. 在项目根目录生成配套密钥
cargo run --manifest-path tools/Cargo.toml -- gen-secret

# 2. 把 "relay blob" 填到 wrangler.toml 的 [vars].SECRET_KEY
#    或更推荐：用 secret 而非 vars
#    wrangler secret put SECRET_KEY
#    （然后把 wrangler.toml 里的 [vars].SECRET_KEY 整行删掉）

# 3. 部署
wrangler deploy
```

部署完你会得到一个 `<name>.<subdomain>.workers.dev` 的域名。把这个域名
填到 [`sub/`](../sub/) 的 `VEILWEAVE_NODES` 或 `tools gen-link` 的
`--address` 里。

## 配置说明

`wrangler.toml` 的关键字段：

| 字段                                | 作用 |
|-------------------------------------|------|
| `name`                              | Worker 名（也是默认域名前缀）|
| `compatibility_date`                | 固定 workerd 行为；尽量别改 |
| `compatibility_flags = ["nodejs_compat"]` | 启用 Node.js 兼容 API |
| `[build].command`                   | 部署时跑 `worker-build --release`（默认带 `perf-log`，生产关掉） |
| `[observability].enabled`           | 启用 Workers Logs（免费版采样） |
| `[vars].SECRET_KEY`                 | **生产必删**，改用 `wrangler secret put SECRET_KEY` |
| `[[durable_objects.bindings]]`      | 把 `VeilweaveSession` 类绑到 `VEILWEAVE_SESSION` 名 |
| `[[migrations]]`                    | `new_sqlite_classes = ["VeilweaveSession"]` —— free plan 强制要求 |

### `SECRET_KEY` 怎么填

只接受两种格式（自动识别）：

1. **新格式（推荐）**：`veilweave-tools gen-secret` 输出的 **relay blob**（以 `VW1` 开头的 base64url）。
   内部 = `VW1‖0‖uuid_secret(32)‖x25519_private(32)`。
   这会同时启用 UUID 签名 + VLESS Encryption（X25519 私钥用于握手）。

2. **旧格式**：任意字符串。UUID 签名正常工作，**不启用** VLESS Encryption。
   适用于老部署，链接会变成 `encryption=none`。

详见 [`../tools/README.md`](../tools/README.md)。

## 性能剖析

`Cargo.toml` 默认开 `perf-log` feature（profile-aware：默认 ON，发布版 ON，
长期生产可以关）。开启后所有 `vlog!` 才会输出。

```bash
# 一次性发布「带日志的镜像」，用来抓现场
cd relay
worker-build --release --features perf-log
wrangler deploy
# 另一个终端：
wrangler tail
```

会看到 `[veilweave]` 前缀的行：握手耗时、target / egress 解析、每帧
record 数 / 字节数、下载 stall 次数、错误关闭原因。

> Workers 的 `Date.now()` 在**两次 I/O 之间**才会推进，纯 CPU 段记录为 0。
> 所以测握手这种纯 CPU 段，要看 `nrec/nbytes/nstall` 这类计数器，不
> 要看 `now_ms` 的差值。详见 `src/log.rs` 的注释。

## 调优点速查

| 想优化 | 看哪里 |
|--------|--------|
| ML-KEM-768 握手 CPU  | `enc.rs::server_handshake`、`.cargo/config.toml` 的 simd128 |
| AEAD seal/open 速率  | `webcrypto.rs::Ctx`（per-isolate handle 缓存）|
| 下载吞吐             | `datapath.rs::relay_download` 的 `WS_SEND_HWM` / `DL_RECORD` |
| UUID 验签            | `vless.rs` 的两层 cache（codec OnceCell + LRU 16）|
| 唤醒 / 上下文切换    | `session.rs::pump` 的 `pumping` 锁 |

## 已知限制

- `Mux` 命令字未实现（`vless.rs::Command::Mux` 直接返回错误）。
- 不接受 ChaCha20-Poly1305 客户端（WebCrypto 不支持，且 wasm 软件实现
  跑不过 10 ms CPU 上限）。
- 不支持 0-RTT 票证（profile 限定为 `1rtt`，`seconds=0`）。
- 仅 IPv4 的 egress 编码在 UUID 里；目标地址本身支持 IPv4 / IPv6 / 域名。

## 测试

```bash
# 编译检查
cargo check --target wasm32-unknown-unknown --manifest-path relay/Cargo.toml

# 跑实测（需要 wrangler 已登录）
cd relay
wrangler dev   # 本地 :8787 模拟 worker 运行时
# 用 xray 客户端连 ws://localhost:8787 测试
```

## 关联文档

- 顶层：[`../README.md`](../README.md)
- 协议细节：[`../docs/protocol.md`](../docs/protocol.md)
- 架构设计：[`../docs/architecture.md`](../docs/architecture.md)
- 部署指南：[`../docs/deployment.md`](../docs/deployment.md)
