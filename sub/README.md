# `sub/` — 订阅 Worker

Cloudflare Worker 实现的 **VLESS 订阅生成器**。输入 `?token=…`，
输出一组 base64 编码的 `vless://` 链接列表（按用户所在运营商 / 国家
自动选 CF 入口 IP + egress IP）。

## 它做什么 / 不做什么

**做：**

- `GET /sub?token=…` 返回多 `vless://` 链接（base64 编码的行列表）；
- 解析 `CF-IPCountry` / `CF-ASN` 自动判断用户所在国家 + 运营商（CT / CU / CMCC）；
- 从远端 API 拉优选 IP，按运营商分类（电信 / 联通 / 移动），结果**KV 缓存 24 h**；
- 拉 proxyip 列表（默认 `zip.cm.edu.kg/all.json`），**KV 缓存 24 h**；
- 把渲染好的订阅**KV 缓存 1 h**（按国家 + 运营商 + 过滤条件做 key）；
- 用与 relay **同一份** signed-UUID codec 签发 UUID，把 egress 编码进 UUID；
- 按节点密钥类型写 `encryption=` 字段：raw 密钥节点（默认）→
  `encryption=none`；`VW1` sub blob 节点（实验性加密）→
  `encryption=mlkem768x25519plus.native.1rtt.<pubkey>`；
- 非 `/sub` 路径返回 Apache 2.4.62 / Debian 伪装页。

**不做：**

- 不终止 VLESS 连接（那是 [`relay/`](../relay/) 的事）；
- 不生成 secret（那是 [`tools/`](../tools/) 的事）；
- 不代理用户流量（用户代理连上 relay 之后的事）；
- 不存储任何用户态。

## 文件结构

```
sub/
├── src/
│   ├── lib.rs            # #[event(fetch)] 入口 + 订阅编排（含 KV binding 解析）
│   ├── codec.rs          # 签名 UUID encoder（与 relay 共享 codec）
│   ├── encoding.rs       # percent-encoding + UUID 格式化
│   ├── egress.rs         # proxyip 列表模型 + 解析
│   ├── geo.rs            # CF-ASN → 运营商分类
│   ├── ip_selector.rs    # 同国家 egress 优先
│   ├── optimized_ip.rs   # 拉 + 缓存 CF 优选入口 IP
│   ├── path.rs           # 真实感的 WS path 生成器（chat / live / market / …）
│   ├── hmac.rs           # HMAC-SHA256 + HKDF（与 relay 一致）
│   ├── sha256.rs         # SHA-256
│   ├── secret.rs         # VEILWEAVE_NODES 单节点解析
│   ├── apache_mock.rs    # 伪装页
│   └── ...               # 共享的小工具
│
├── static/                # 包含进 wasm 的静态资源
│   ├── apache_default.html
│   ├── apache_404.html
│   ├── favicon.ico
│   └── icons/openlogo-75.png
│
├── .cargo/config.toml
├── Cargo.toml
├── wrangler.toml
└── README.md              # 你正在看的文件
```

## 快速部署

```bash
# 1. 在项目根目录生成密钥（默认：一个明文模式用的 raw 随机密钥）
cargo run --manifest-path tools/Cargo.toml -- gen-secret
#    实验性加密：gen-secret --encryption（输出 relay blob + sub blob 一对）

# 2. 把同一密钥填到 wrangler.toml 的 [vars].VEILWEAVE_NODES
#    格式：domain|<secret>，多个节点用逗号分隔
#    VEILWEAVE_NODES = "veilweave.example.com|<secret>"

# 3. 建 KV namespace
cd sub
wrangler kv:namespace create VEILWEAVE_KV
# 把输出 id 填到 wrangler.toml 的 [[kv_namespaces]].id
# （用了自定义 binding 名的话，记得同时设 [vars].KV_BINDING，见下文）

# 4. 设访问令牌（推荐用 secret）
#    wrangler secret put SUBSCRIPTION_TOKEN

# 5. 部署
wrangler deploy
```

> **命名建议**：worker 名称、KV 命名空间名称、binding 名都建议改成你自己
> 的（别用默认值）——减少与其他 veilweave 部署的相似度。`veilweave-tools
> bundle` / 部署器会自动随机化这些名字。

## 请求格式

```
GET /sub?token=<SUBSCRIPTION_TOKEN>[&filter=CN,US][&secure=1]
```

| 参数     | 别名 | 必填 | 说明 |
|----------|------|------|------|
| `token`  | `t`  | ✅   | 必须等于 `SUBSCRIPTION_TOKEN` |
| `filter` | `c`  | ❌   | 限制 egress proxyip 国家（逗号分隔） |
| `secure` | —    | ❌   | `1`（默认）发完整 TLS 链接；`0` 发明文 WS |
| `country`| `cc` | ❌   | 强制按指定国家选 IP（默认从 `CF-IPCountry` 读） |

返回 body 是一行一个 base64 编码的 `vless://` 链接（标准订阅格式）。

## 链接形式

明文模式（raw 密钥，默认）：

```
vless://<signed-uuid>@<entry-ip>:443?encryption=none
       &security=tls&type=ws
       &host=<relay-domain>&path=<realistic-ws-path>
       &sni=<relay-domain>&fp=chrome&alpn=http%2F1.1&ech=...
       &insecure=0&allowInsecure=0#<CC-n>
```

实验性加密模式（节点配 `VW1` sub blob）时，`encryption=none` 换成
`encryption=mlkem768x25519plus.native.1rtt.<pubkey>`，客户端握手时自动协商。

- **`<signed-uuid>`**：用本 worker 的 UUID 签名密钥签的，relay 用同一把
  密钥验签。
- **`<entry-ip>`**：按用户运营商筛出的 CF 优选 IP（电信/联通/移动各有
  一个最稳的入口）。
- **`<relay-domain>`**：填在 `VEILWEAVE_NODES` 里的域名（不是入口 IP，
  是给 Cloudflare 边缘路由用的真实 worker 域名）。
- **`<pubkey>`**（仅加密模式）：`VW1` sub blob 内嵌的 X25519 公钥——
  客户端据此协商 `mlkem768x25519plus`。
- `path` 是从 `chat/live/market/socket.io/graphql/signalr/mqtt/...` 里
  随机挑的，看起来像真实应用流量，**不**带 `ed=2048` 早期数据指纹。

## 配置说明

`wrangler.toml` 关键字段：

| 字段                                    | 作用 |
|-----------------------------------------|------|
| `[vars].VEILWEAVE_NODES`                | 节点列表，格式 `domain\|<secret>`，逗号分隔；raw 密钥 = 明文（默认），`VW1` sub blob = 实验性加密 |
| `[vars].SUBSCRIPTION_TOKEN`             | 访问令牌（生产建议用 `wrangler secret put`）|
| `[vars].MAX_NODES`                      | 单次返回节点上限（默认 100）|
| `[vars].FP`                             | 客户端 TLS 指纹（默认 `chrome`）|
| `[vars].DISABLE_BUILTIN_PROXYIP`        | 关闭内置 proxyip API（默认 `false`）|
| `[vars].PROXYIP_LIST`                   | 额外 inline proxyip 列表 |
| `[vars].KV_BINDING`                     | 自定义 KV binding 名（可选；改了 `[[kv_namespaces]].binding` 就设它）|
| `[[kv_namespaces]]`                     | 优选 IP / 渲染结果缓存 |

### KV binding 名解析

KV 不是必须的（没配 KV 就退化为无缓存直出），配了的话 binding 名按以下
顺序解析：

```
[vars].KV_BINDING  →  "VEILWEAVE_KV"  →  "KV"
```

也就是说 binding 名可以完全自定义（推荐，且必须是合法 JS 标识符）——
只要把 `[[kv_namespaces]].binding` 和 `[vars].KV_BINDING` 设成同一个名字
即可。`veilweave-tools bundle` / 部署器生成的配置会自动随机化 binding 名
（例如 `kv_x7f2a9`）并配好 `KV_BINDING`。

### 多 relay 节点

`VEILWEAVE_NODES` 支持任意多个 relay 节点，**每个节点用各自配套的密钥**：

```toml
VEILWEAVE_NODES = """
a.example.com|<secret for node a>,
b.example.com|<secret for node b>,
c.example.com|<secret for node c>
"""
```

> 不同节点用不同密钥时，每个节点 UUID 是独立签的——节点 a 的链接
> 不能被节点 b 验签通过（这是**特性**，不是 bug，避免一个节点密钥泄露
> 影响其他节点）。如果你想要"一密钥多节点"模式，所有节点用同一个密钥
> 也可以，但安全边界相应降低。

## 缓存策略

| 缓存内容         | Key 形态                                | TTL  |
|------------------|-----------------------------------------|------|
| CF 优选 IP       | `optips_<carrier>`                       | 24 h |
| ProxyIP 列表     | `proxyip_cache_v1`                       | 24 h |
| 渲染好的订阅     | `sub_<country>_<asn>_<filter>_<secure>` | 1 h  |

> 同 ISP + 同国家的多个用户共享一个 body，命中率 > 90%——大部分请求就
> 是 1 个 KV 读。冷路径最坏 1（proxyip）+ 3（入口 IP）= 4 个子请求。

## 性能

| 指标                  | 数值                          |
|-----------------------|-------------------------------|
| 冷路径 CPU             | 1 远端 fetch + 1 KV 读 + 链接渲染 |
| 暖路径 CPU             | 1 KV 读                       |
| 冷路径子请求           | 1 ~ 4                         |
| 暖路径子请求           | 1                             |
| 缓存命中延迟           | 单次 KV 读 < 5 ms（CF 边缘）   |
| 冷路径延迟             | 取决于优选 API 源（一般 < 500 ms）|

## 关联文档

- 顶层：[`../README.md`](../README.md)
- 协议细节：[`../docs/protocol.md`](../docs/protocol.md)
- 架构设计：[`../docs/architecture.md`](../docs/architecture.md)
- 部署指南：[`../docs/deployment.md`](../docs/deployment.md)
- CLI：[`../tools/README.md`](../tools/README.md)
