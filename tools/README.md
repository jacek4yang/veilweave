# `tools/` — 运维 CLI

`veilweave-tools` 是**原生 Rust 二进制**（不跑在 Worker 里），负责生成
配套密钥和单条 `vless://` 链接。

## 子命令

### `gen-secret`

生成 **配套的 relay blob + sub blob**。两者共享同一把 UUID 签名密钥 +
一对匹配的 X25519 私/公钥。

```bash
cargo run -p veilweave-tools -- gen-secret
```

输出形如：

```
── veilweave relay ──  set  SECRET_KEY  to:
  VlcxAKSNnGuowsc10G-RQXpKyMQcye5GSTjG8HYydqBRAIwbBK_mTX4bbUxCzBigZpOJrh32zT9o9ZUU_lFFvacdURI
── veilweave-sub ──  use in  VEILWEAVE_NODES  as  <domain>|<blob>:
  VlcxAaSNnGuowsc10G-RQXpKyMQcye5GSTjG8HYydqBRAIwb8tQyq9AfwncoaXLOphNtT5NIpddTFFPzr0o6crPcr20
```

把：
- **relay blob** 粘到 [`relay/wrangler.toml`](../relay/wrangler.toml) 的
  `[vars].SECRET_KEY`（生产用 `wrangler secret put SECRET_KEY`）。
- **sub blob** 粘到 [`sub/wrangler.toml`](../sub/wrangler.toml) 的
  `[vars].VEILWEAVE_NODES`，格式 `<relay-domain>|<sub blob>`。

### `gen-link`

签发**单条** `vless://` 链接（不走 sub worker）。

```bash
cargo run -p veilweave-tools -- gen-link \
  --address veilweave.example.com \
  --port 443 \
  --type proxyip \
  --proxy-ip 1.2.3.4 \
  --proxy-port 443 \
  --secret-key "<relay blob>"
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
| `--secret-key`  | ✅   | relay blob（与 relay worker 配的同一把）|

输出会打印一行 `vless://...`，可直接粘到 v2rayN / NekoBox / mihomo / sing-box。

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
- **`--secret-key` 也可以是 legacy raw 字符串**（不是 blob）——这时候不会
  生成 `encryption=...` 字段，relay 也不启用 VLESS Encryption。用来测
  老部署。
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
