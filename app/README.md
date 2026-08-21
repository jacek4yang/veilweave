# `app/` — 桌面应用（veilweave deployer）

Tauri 2 桌面应用，整个项目的**主路径**：图形化地完成账号管理、部署、
用量监控和更新，全程不需要 wrangler / Node.js / Rust 工具链——预编译的
relay / sub worker 直接嵌在二进制里，部署和更新完全离线可用。

## 功能

侧边栏五个页面：

- **概览**：按账号的用量面板——今日请求数（对照免费版 100k/天上限）、
  错误数、分 worker 明细（需要 token 带可选的 `Account → Analytics → Read`
  权限，没有该权限时其余功能不受影响）；
- **账号**：用一个或多个 Cloudflare API token 管理账号；「**扫描已有
  部署**」通过 API 读取 worker 配置，重装系统后一键重建本地部署清单；
- **部署**：拓扑向导（sub 放哪个账号、几个 relay、分别放哪些账号，每个
  relay 独立密钥），所有名称可自定义，也有一键「随机」；
- **管理**：复制订阅地址、**更新部署**（重新上传内嵌的最新 worker 代码，
  密钥保持不变）、删除 worker（连带 KV）；
- **设置**：界面语言（中文 / English）、检查更新（应用内自动更新）。

Windows 发布版是纯图形窗口（`windows_subsystem = "windows"`），没有控制台
黑框。

## 从源码构建

```bash
# 前置：Rust toolchain + Node.js
cd app

# 1. 放入预编译 worker（build.rs 缺了会直接报错）
#    先在 relay/ 和 sub/ 里跑 worker-build --release，然后：
cp -r ../relay/build src-tauri/bundle/relay/build
cp -r ../sub/build   src-tauri/bundle/sub/build
#    详见 src-tauri/bundle/README.md（该目录被 gitignore，是构建产物）

# 2. 构建
npm ci
npm run tauri -- build
```

产物在 `app/src-tauri/target/release/bundle/` 下（Windows: NSIS + MSI；
macOS: dmg；Linux: AppImage + deb，具体取决于平台与
`tauri.conf.json` 的 `bundle.targets`）。

## 架构

```
app/
├── ui/                  # 静态前端（无框架）：index.html + css/ + js/
│   └── js/              # app.js（页面/交互）、i18n.js（中英双语）
├── src-tauri/
│   ├── src/
│   │   ├── main.rs      # 入口（windows_subsystem）
│   │   ├── lib.rs       # #[tauri::command]：get_config / add_account /
│   │   │                # recover / usage / start_deploy / update_deployment /
│   │   │                # delete_deployment / random_* …
│   │   └── bundle.rs    # include_bytes! 内嵌预编译 worker
│   ├── bundle/          # 预编译 relay/sub（gitignore，见其中 README）
│   └── tauri.conf.json  # 窗口 / CSP / bundle targets / updater 端点
└── package.json         # 仅 @tauri-apps/cli
```

前端通过 `invoke()` 调 Tauri 命令；所有 Cloudflare API 交互、配置持久化、
部署/找回编排在 **`core/`（veilweave-core）** 里实现，与 CLI
（`tools/`）共享同一份逻辑。配置文件与 CLI 相同：平台配置目录下的
`veilweave/config.toml`。

## 自动更新（维护者向）

`tauri.conf.json` 启用了 updater（`createUpdaterArtifacts: true`），发布
流水线用签名私钥为各平台产物生成 `.sig`，并组装 `latest.json` 清单随
release 一起发布。仓库需要配置两个 secrets：

- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`

公钥已内嵌在 `tauri.conf.json` 的 `plugins.updater.pubkey`。轮换密钥时
必须同步更新 pubkey 并保证旧版本能链式升级到新签名。

## 关联文档

- 顶层：[`../README.md`](../README.md)
- CLI 版部署：[`../tools/README.md`](../tools/README.md)
- 部署指南：[`../docs/deployment.md`](../docs/deployment.md)
