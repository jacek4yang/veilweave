# `tools/` — 部署 CLI

`veilweave-tools` 是**原生 Rust 命令行二进制**（不跑在 Worker 里）：
交互式部署向导、密钥生成、单条链接签发、wrangler 部署产物打包。

v2 还提供可自动化的控制面命令：

```text
veilweave-tools plan --config veilweave.toml
veilweave-tools apply --config veilweave.toml --yes
veilweave-tools status --json
veilweave-tools update --deployment <uuid>
veilweave-tools rollback --deployment <uuid>
veilweave-tools rotate-token --deployment <sub-uuid>
veilweave-tools doctor
veilweave-tools recover --account <label-or-id>
veilweave-tools recover --account production --adopt-worker edge-one \
  --worker-secret-ref env:EDGE_ONE_WORKER_SECRET \
  --node-secret-ref env:EDGE_ONE_NODE_SECRET
veilweave-tools domain --account <label-or-id>
veilweave-tools config network --mode socks5 --host 127.0.0.1 --port 10808
veilweave-tools proxy test
```

详见 [`../docs/declarative-config.md`](../docs/declarative-config.md) 与
[`../docs/network.md`](../docs/network.md)。Token、Worker 密钥与代理密码不会
写进声明式拓扑或普通配置 TOML。

> **要图形界面？** 那是独立的桌面应用 [`app/`](../app/)（Tauri 2，
> 概览/账号/部署/管理/设置 五个页面，支持用量面板、扫描找回、自动更新）。
> 从 [Releases](https://github.com/jacek4yang/veilweave/releases) 下载对应
> 平台的安装包即可。CLI 不带参数运行时只会打印一条提示：
>
> ```
> veilweave-tools — 部署请运行 / to deploy, run:
>     veilweave-tools deploy
> ```

## 子命令

### `deploy`

交互式 CLI 向导（与桌面应用「部署」页同一套流程）：

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
3. **确认部署**：自动创建或精确复用 KV 命名空间，校验确定性 Worker
   bundle，通过 Cloudflare Versions/Deployments API 事务式发布，最后打印
   **订阅地址**。

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
  `SECRET_KEY`（使用 `wrangler secret put SECRET_KEY`，不写入 TOML）。
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

- 随机化 worker 名称和 **KV binding 名**（如 `kv_x7f2a9`，并在 sub 的
  `wrangler.toml` 里配好对应的 `KV_BINDING` 变量）；
- 从同一份 manifest 验证过的 canonical runtime 复制模块，不包含
  `package.json` 或任何构建元数据；
- 生成不含密钥的 `wrangler.toml`。密钥和订阅令牌需按终端提示用
  `wrangler secret put` 安全注入；不会修改已签名 runtime 的内容哈希。

可选参数：`--out <dir>`（默认 `dist`）、`--relay-domain <域名>`、
`--bundle-dir <dir>`。生成后按终端提示 `wrangler deploy` 即可（这是不用
桌面应用 / API 部署、走 wrangler 的手动路径）。

## API token 权限

部署器（`deploy`/`manage`，以及桌面应用）需要 **Account 级** Custom Token：

| 资源 | 权限 |
|------|------|
| Account → Workers Scripts | **Edit** |
| Account → Workers KV Storage | **Edit** |
| Account → Account Settings | **Read**（解析 workers.dev 子域用） |
| Account → Account Analytics | **Read**（**可选**——仅桌面应用「概览」用量面板需要） |

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

桌面应用 / `deploy` 向导里按提示逐个选择即可：每个 relay 自动获得自己的
密钥，sub 的 `VEILWEAVE_NODES` 自动汇总全部节点。订阅地址部署完成时打印，
之后可在桌面应用「管理」页 / `manage` 里随时重新查看。

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
- 桌面应用：[`../app/README.md`](../app/README.md)
- 协议细节：[`../docs/protocol.md`](../docs/protocol.md)
- 部署：[`../docs/deployment.md`](../docs/deployment.md)
