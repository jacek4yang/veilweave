# `tools/` — 部署器（GUI + CLI）

`veilweave-tools` 是**原生 Rust 二进制**（不跑在 Worker 里），是整个项目的
运维入口：图形界面部署器、交互式 CLI 部署向导、密钥生成、单条链接签发、
wrangler 部署产物打包。

## 图形界面（无参数运行）

不带任何参数运行 `veilweave-tools`（Windows 下双击 exe 也一样）会打开图形
界面「**veilweave 部署器**」，三个页面：

- **Accounts / 账号**：用 API token 添加一个或多个 Cloudflare 账号；
- **Deploy / 部署**：规划拓扑（sub 放哪个账号、几个 relay、分别放哪些账号），
  一键部署并打印订阅地址；
- **Manage / 管理**：查看已部署的 worker、重新显示订阅地址、删除部署。

这是给大多数用户的**主路径**——全程不需要 wrangler、Node.js 或 Rust
工具链，部署直接走 Cloudflare API。

## 子命令

### `deploy`

交互式 CLI 向导，与 GUI 等价的命令行版本：

```bash
veilweave-tools deploy
```

流程：

1. **添加账号**：程序打开 <https://dash.cloudflare.com/profile/api-tokens>，
   创建一个 Custom Token（权限见下文），粘贴回来；token 验证后选择可见的
   账号并起一个本地标签。可以添加多个账号（多账号拓扑：sub 一个账号，
   relay 分散在其他账号）。
2. **规划拓扑**：选 sub 所在的账号、relay 的数量和各自所在账号——**每个
   relay 自动分配独立密钥**。
3. **确认部署**：自动创建 KV 命名空间、注入随机 nonce（每次部署产物哈希
   唯一）、通过 Cloudflare API 上传 worker，最后打印**订阅地址**。

可选参数 `--bundle-dir <dir>` 指定预编译 worker 目录（默认用 exe 旁边的
`bundle/`，即 release 压缩包内的布局）。

### `manage`

管理已有部署：

```bash
veilweave-tools manage
```

列出所有部署记录（角色 / worker 名 / 域名 / 所在账号），可重新显示某个
部署的订阅地址，或从 Cloudflare 上**删除**某个 worker（sub 会连带删除其
KV 命名空间）。

### `gen-secret [--encryption]`

生成 relay + sub 的配套密钥。

**默认（明文模式，推荐）**：输出**一个** raw 随机密钥，relay 的
`SECRET_KEY` 和 sub 的 `VEILWEAVE_NODES`（`<domain>|<secret>`）用同一把：

```bash
veilweave-tools gen-secret
```

```
# Plaintext VLESS (encryption=none) — one shared raw secret.

# ── veilweave relay ──  set  SECRET_KEY  to:
  <32 字节随机数的 base64url>

# ── veilweave-sub ──  use in  VEILWEAVE_NODES  as  <domain>|<secret>, e.g.:
  my-relay.example.workers.dev|<同一密钥>
```

**`--encryption`（实验性）**：输出 `VW1` blob 对（relay blob 含 UUID 签名
密钥 + X25519 私钥；sub blob 含同一把 UUID 密钥 + X25519 公钥），并打印
实验性警告——`mlkem768x25519plus` 的握手和逐 record AEAD 很吃 CPU，可能
超出 Workers 免费套餐的单次调用 CPU 上限：

```bash
veilweave-tools gen-secret --encryption
```

把：
- **relay 侧**粘到 [`relay/wrangler.toml`](../relay/wrangler.toml) 的
  `[vars].SECRET_KEY`（生产用 `wrangler secret put SECRET_KEY`）。
- **sub 侧**粘到 [`sub/wrangler.toml`](../sub/wrangler.toml) 的
  `[vars].VEILWEAVE_NODES`，格式 `<relay-domain>|<secret>`。

> 每个 relay 节点都应有自己的密钥——`gen-secret` 每个节点跑一次。

### `gen-link`

签发**单条** `vless://` 链接（不走 sub worker）。

```bash
veilweave-tools gen-link \
  --address veilweave.example.com \
  --port 443 \
  --type proxyip \
  --proxy-ip 1.2.3.4 \
  --proxy-port 443 \
  --secret-key "<relay 的 SECRET_KEY>"
```

参数：

| 参数            | 必填 | 说明 |
|-----------------|------|------|
| `--address`     | ✅   | relay worker 的域名（用户实际连接的地址）|
| `--port`        | ✅   | relay worker 的端口（Cloudflare = 443） |
| `--type`        | ✅   | `direct` / `proxyip` / `socks5` / `http` |
| `--proxy-ip`    | 视 type | 对 `proxyip` / `socks5` / `http` 必填 |
| `--proxy-port`  | ❌   | 默认 `proxyip=443`, `socks5=1080`, `http=80` |
| `--sni`         | ❌   | TLS SNI（默认 = `--address`）|
| `--name`        | ❌   | 节点显示名（默认 = `--address`）|
| `--secret-key`  | ✅   | 与 relay worker 配的同一把密钥（raw 或 blob）|

输出会打印一行 `vless://...`，可直接粘到 v2rayN / NekoBox / mihomo /
sing-box。raw 密钥 → 链接带 `encryption=none`；blob → 自动带
`encryption=mlkem768x25519plus.native.1rtt.<pubkey>`（relay blob 也行，
公钥会从私钥推导，私钥不会进链接）。

### `bundle [--encryption]`

把 exe 旁边 `bundle/` 里的预编译 worker 打包成两个可直接 `wrangler deploy`
的目录（`dist/` 下）：

```bash
veilweave-tools bundle
```

每次运行都会：

- 生成全新密钥（默认 raw 明文密钥；`--encryption` 换成实验性 blob 对）；
- 随机化 worker 名称和 **KV binding 名**（如 `kv_x7f2a9`，并在 sub 的
  `wrangler.toml` 里配好对应的 `KV_BINDING` 变量）；
- 随机化订阅令牌；
- 给每个 `index.js` 注入一次性随机 nonce——**你的产物哈希与任何其他人都
  不相同**，不会因批量指纹被标记。

可选参数：`--out <dir>`（默认 `dist`）、`--relay-domain <域名>`、
`--bundle-dir <dir>`。生成后按终端提示 `wrangler deploy` 即可（这是不装
GUI、走 wrangler 的手动路径）。

## API token 权限

部署器（GUI 和 `deploy`/`manage`）需要 **Account 级** Custom Token：

| 资源 | 权限 |
|------|------|
| Account → Workers Scripts | **Edit** |
| Account → Workers KV Storage | **Edit** |
| Account → Account Settings | **Read**（解析 workers.dev 子域用） |

在 <https://dash.cloudflare.com/profile/api-tokens> 选 "Create Custom Token"
配置。token 只存在本机配置文件里，不会上传到任何地方（除了 Cloudflare API
本身）。

## 配置文件

账号和部署记录持久化在平台配置目录：

| 平台 | 路径 |
|------|------|
| Windows | `%APPDATA%\veilweave\config.toml` |
| Linux | `~/.config/veilweave/config.toml` |
| macOS | `~/Library/Application Support/veilweave/config.toml` |

写入是「临时文件 + 重命名」的原子方式。**这个文件里有 API token 和各节点
密钥，注意本机权限，别同步到网盘 / git。**

## 多账号拓扑示例

分散部署（sub 在账号 A，relay 分散在 B / C / D）可以降低单账号被封的
影响面：

```
Accounts:  A (main)  B  C  D
Deploy:
  sub      → account A
  relay 1  → account B   (独立密钥)
  relay 2  → account C   (独立密钥)
  relay 3  → account D   (独立密钥)
```

GUI / `deploy` 向导里按提示逐个选择即可：每个 relay 自动获得自己的密钥，
sub 的 `VEILWEAVE_NODES` 自动汇总全部节点。订阅地址部署完成时打印，之后
可在 Manage / `manage` 里随时重新查看。

## 编译产物

```bash
# Debug
cargo build --manifest-path tools/Cargo.toml

# Release（单文件 < 1 MB）
cargo build --release --manifest-path tools/Cargo.toml
# 产物：target/release/veilweave-tools(.exe)
```

把 release 产物丢到 `~/.local/bin/` 就可以在任意目录调 `veilweave-tools`。

## 关键点

- **同一个 `--secret-key` 必须与 relay worker 的 `SECRET_KEY` 一致**。
  否则 UUID 验签失败，relay 直接关闭连接。
- **`--secret-key` 传 raw 字符串（非 blob）时**，不会生成 `encryption=...`
  字段（即 `encryption=none`），relay 侧也不启用 VLESS Encryption——这是
  默认的明文模式。
- blob 内部布局见 [`../relay/src/secret.rs`](../relay/src/secret.rs)。

## 安全

- 输出是 base64url，**不是明文**——但仍然是高熵密钥，**不要贴到 issue
  / 聊天 / 公开 gist**。
- 生成的 X25519 私钥是 32 字节 CSPRNG 输出，没有弱密钥风险。
- 没有"已知密钥列表"——每个 `gen-secret` 输出都互不相关。

## 关联文档

- 顶层：[`../README.md`](../README.md)
- 协议细节：[`../docs/protocol.md`](../docs/protocol.md)
- 部署：[`../docs/deployment.md`](../docs/deployment.md)
