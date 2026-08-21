//! egui front-end for the deploy core. All orchestration stays in
//! `deploy::execute` / `config::Config` / `cfapi::CfClient` — this module is
//! pure UI state plus background-job plumbing.
//!
//! Threading: egui's `update()` never blocks. API work (token verification,
//! deploy, deletes) runs on a `std::thread` with its own tokio runtime and
//! reports back through an `mpsc` channel; `update()` drains the channel every
//! frame and repaints while a job is in flight. Action buttons are disabled
//! whenever `job_running` is set, so jobs are effectively serialized.

use crate::cfapi::{AccountSummary, CfClient};
use crate::config::{Account, Config, Role};
use crate::deploy::{self, DeployPlan, LogKind, LogLine, RelaySpec, SubSpec};
use anyhow::{anyhow, Result};
use eframe::egui;
use egui::Color32;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

/// What the background threads report back to the UI thread.
enum GuiMsg {
    Log(LogLine),
    DeployDone(Result<Option<String>, String>),
    /// Carries the token that was actually verified (the field may have changed since).
    TokenChecked(String, Result<Vec<AccountSummary>, String>),
    AccountResolved(Result<Account, String>),
    DeploymentDeleted {
        idx: usize,
        result: Result<(), String>,
    },
}

#[derive(PartialEq, Clone, Copy)]
enum Page {
    Accounts,
    Deploy,
    Manage,
}

struct RelayRow {
    account: usize,
    name: String,
}

pub struct GuiApp {
    cfg: Config,
    page: Page,
    tx: Sender<GuiMsg>,
    rx: Receiver<GuiMsg>,
    job_running: bool,
    /// Transient (is_error, text) shown at the top of each page.
    status: Option<(bool, String)>,

    // ── Accounts page ────────────────────────────────────────────────────
    add_label: String,
    add_token: String,
    /// Set after a successful token check: (token, visible CF accounts, picked index).
    verified: Option<(String, Vec<AccountSummary>, usize)>,
    confirm_delete_account: Option<usize>,

    // ── Deploy page ──────────────────────────────────────────────────────
    sub_account: usize,
    sub_name: String,
    kv_title: String,
    kv_binding: String,
    relays: Vec<RelayRow>,
    encryption: bool,
    log: Vec<LogLine>,
    sub_url: Option<String>,

    // ── Manage page ──────────────────────────────────────────────────────
    confirm_delete_dep: Option<usize>,
}

/// Launch the window. Returns Err when no display/GL context is available.
pub fn launch() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("veilweave 部署器 / veilweave deployer")
            .with_inner_size([900.0, 640.0])
            .with_min_inner_size([720.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native(
        "veilweave",
        options,
        Box::new(|cc| Ok(Box::new(GuiApp::new(cc)))),
    )
    .map_err(|e| anyhow!("{e}"))
}

impl GuiApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let cfg = Config::load().unwrap_or_else(|e| {
            eprintln!("warning: could not load config: {e:#}");
            Config::default()
        });
        Self::with_config(cc, cfg)
    }

    fn with_config(cc: &eframe::CreationContext<'_>, cfg: Config) -> Self {
        load_cjk_fonts(&cc.egui_ctx);
        Self::from_parts(cfg)
    }

    /// Everything except the font setup, which needs an egui context.
    fn from_parts(cfg: Config) -> Self {
        let (tx, rx) = channel();
        Self {
            cfg,
            page: Page::Deploy,
            tx,
            rx,
            job_running: false,
            status: None,
            add_label: String::new(),
            add_token: String::new(),
            verified: None,
            confirm_delete_account: None,
            sub_account: 0,
            sub_name: crate::random_worker_name(),
            kv_title: format!("{}-kv", crate::random_worker_name()),
            kv_binding: crate::random_kv_binding(),
            relays: vec![RelayRow {
                account: 0,
                name: crate::random_worker_name(),
            }],
            encryption: false,
            log: Vec::new(),
            sub_url: None,
            confirm_delete_dep: None,
        }
    }

    fn set_status(&mut self, is_error: bool, text: impl Into<String>) {
        self.status = Some((is_error, text.into()));
    }

    /// Drain background-job messages; returns true if anything changed.
    fn poll_jobs(&mut self) -> bool {
        let mut changed = false;
        while let Ok(msg) = self.rx.try_recv() {
            changed = true;
            match msg {
                GuiMsg::Log(line) => self.log.push(line),
                GuiMsg::DeployDone(result) => {
                    self.job_running = false;
                    match result {
                        Ok(url) => {
                            self.sub_url = url;
                            self.set_status(false, "部署完成 / deploy finished");
                        }
                        Err(e) => self.set_status(true, format!("部署失败 / deploy failed: {e}")),
                    }
                    // execute() already saved; reload to pick up new records.
                    if let Ok(cfg) = Config::load() {
                        self.cfg = cfg;
                    }
                }
                GuiMsg::TokenChecked(token, result) => {
                    self.job_running = false;
                    match result {
                        Ok(accounts) => {
                            self.verified = Some((token, accounts, 0));
                            self.set_status(false, "Token 验证通过 / token verified");
                        }
                        Err(e) => {
                            self.verified = None;
                            self.set_status(true, format!("Token 验证失败 / verify failed: {e}"));
                        }
                    }
                }
                GuiMsg::AccountResolved(result) => {
                    self.job_running = false;
                    match result {
                        Ok(account) => {
                            let label = if self.add_label.trim().is_empty() {
                                account.name.clone()
                            } else {
                                self.add_label.trim().to_string()
                            };
                            if self.cfg.account(&label).is_some() {
                                self.set_status(
                                    true,
                                    format!("账号标签 {label:?} 已存在 / label already exists"),
                                );
                                return changed;
                            }
                            let account = Account {
                                name: label.clone(),
                                ..account
                            };
                            self.cfg.accounts.push(account);
                            match self.cfg.save() {
                                Ok(()) => {
                                    self.set_status(
                                        false,
                                        format!("已添加账号 {label:?} / account added"),
                                    );
                                    self.add_label.clear();
                                    self.add_token.clear();
                                    self.verified = None;
                                }
                                Err(e) => self
                                    .set_status(true, format!("保存配置失败 / save failed: {e:#}")),
                            }
                        }
                        Err(e) => self.set_status(true, format!("添加账号失败 / failed: {e}")),
                    }
                }
                GuiMsg::DeploymentDeleted { idx, result } => {
                    self.job_running = false;
                    match result {
                        Ok(()) => {
                            let name = self
                                .cfg
                                .deployments
                                .get(idx)
                                .map(|d| d.name.clone())
                                .unwrap_or_default();
                            if idx < self.cfg.deployments.len() {
                                self.cfg.deployments.remove(idx);
                            }
                            match self.cfg.save() {
                                Ok(()) => {
                                    self.set_status(false, format!("已删除 {name} / deleted"))
                                }
                                Err(e) => self
                                    .set_status(true, format!("保存配置失败 / save failed: {e:#}")),
                            }
                        }
                        Err(e) => self.set_status(true, format!("删除失败 / delete failed: {e}")),
                    }
                }
            }
        }
        changed
    }

    // ── background job spawners ─────────────────────────────────────────────

    fn spawn_verify_token(&mut self) {
        let token = self.add_token.trim().to_string();
        if token.is_empty() {
            self.set_status(true, "请先粘贴 API Token / paste an API token first");
            return;
        }
        let tx = self.tx.clone();
        self.job_running = true;
        self.verified = None;
        std::thread::spawn(move || {
            let job_token = token.clone();
            let result = run_async(async move {
                let client = CfClient::new(&job_token)?;
                client.verify_token().await?;
                client.list_accounts().await
            });
            let _ = tx.send(GuiMsg::TokenChecked(
                token,
                result.map_err(|e| format!("{e:#}")),
            ));
        });
    }

    fn spawn_add_account(&mut self) {
        let Some((token, accounts, selected)) = self.verified.clone() else {
            return;
        };
        let Some(cf_account) = accounts.get(selected).cloned() else {
            self.set_status(true, "请选择一个 Cloudflare 账号 / pick an account");
            return;
        };
        let tx = self.tx.clone();
        self.job_running = true;
        std::thread::spawn(move || {
            let result = run_async(async move {
                let client = CfClient::new(&token)?;
                let subdomain = client.get_workers_subdomain(&cf_account.id).await?;
                Ok(Account {
                    name: cf_account.name,
                    token,
                    account_id: cf_account.id,
                    workers_dev_subdomain: Some(subdomain),
                })
            });
            let _ = tx.send(GuiMsg::AccountResolved(
                result.map_err(|e| format!("{e:#}")),
            ));
        });
    }

    fn build_plan(&self) -> std::result::Result<DeployPlan, String> {
        if self.cfg.accounts.is_empty() {
            return Err("请先在「账号」页添加 Cloudflare 账号 / add an account first".into());
        }
        if self.relays.is_empty() {
            return Err("至少需要一个 relay / at least one relay is required".into());
        }
        let account_name = |idx: usize| -> std::result::Result<String, String> {
            self.cfg
                .accounts
                .get(idx)
                .map(|a| a.name.clone())
                .ok_or_else(|| "账号选择无效 / invalid account selection".to_string())
        };
        let mut names: Vec<(String, String)> = Vec::new(); // (account, worker name)
        let mut check_name = |account: &str, name: &str| -> std::result::Result<(), String> {
            crate::wizard::validate_worker_name(name)
                .map_err(|e| format!("worker 名称 {name:?} 无效 / invalid: {e}"))?;
            let key = (account.to_string(), name.to_string());
            if names.contains(&key) {
                return Err(format!("同一账号下名称重复 / duplicate name {name:?}"));
            }
            names.push(key);
            Ok(())
        };

        let sub_account = account_name(self.sub_account)?;
        check_name(&sub_account, &self.sub_name)?;
        if !is_valid_binding(&self.kv_binding) {
            return Err(format!(
                "KV binding 名称 {:?} 无效（须为合法 JS 标识符）/ invalid JS identifier",
                self.kv_binding
            ));
        }
        let mut relays = Vec::new();
        for row in &self.relays {
            let account = account_name(row.account)?;
            check_name(&account, &row.name)?;
            relays.push(RelaySpec {
                account,
                worker_name: row.name.clone(),
            });
        }
        Ok(DeployPlan {
            sub: SubSpec {
                account: sub_account,
                worker_name: self.sub_name.clone(),
                kv_title: self.kv_title.clone(),
                kv_binding: self.kv_binding.clone(),
            },
            relays,
            encryption: self.encryption,
        })
    }

    fn spawn_deploy(&mut self) {
        let plan = match self.build_plan() {
            Ok(p) => p,
            Err(e) => {
                self.set_status(true, e);
                return;
            }
        };
        let bundle_dir = deploy::locate_bundle_dir(None);
        let mut cfg = self.cfg.clone();
        let tx = self.tx.clone();
        self.job_running = true;
        self.log.clear();
        self.sub_url = None;
        self.status = None;
        std::thread::spawn(move || {
            let log_tx = tx.clone();
            let result = run_async(async move {
                deploy::execute(&plan, &bundle_dir, &mut cfg, &mut |line| {
                    let _ = log_tx.send(GuiMsg::Log(line));
                })
                .await
            });
            let msg = match result {
                Ok(outcome) => Ok(outcome.subscription_url().map(str::to_owned)),
                Err(e) => Err(format!("{e:#}")),
            };
            let _ = tx.send(GuiMsg::DeployDone(msg));
        });
    }

    fn spawn_delete_deployment(&mut self, idx: usize) {
        let Some(dep) = self.cfg.deployments.get(idx).cloned() else {
            return;
        };
        let Some(account) = self.cfg.account(&dep.account).cloned() else {
            self.set_status(
                true,
                format!("账号 {:?} 已不在配置中 / account gone", dep.account),
            );
            return;
        };
        let tx = self.tx.clone();
        self.job_running = true;
        std::thread::spawn(move || {
            let result = run_async(async move {
                let client = CfClient::new(&account.token)?;
                client.delete_worker(&account.account_id, &dep.name).await?;
                if let Some(sub) = &dep.sub {
                    client
                        .delete_kv_namespace(&account.account_id, &sub.kv_namespace_id)
                        .await?;
                }
                Ok(())
            });
            let _ = tx.send(GuiMsg::DeploymentDeleted {
                idx,
                result: result.map_err(|e| format!("{e:#}")),
            });
        });
    }
}

/// Run an async job on a dedicated tokio runtime (background threads only).
fn run_async<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
    rt.block_on(future)
}

fn is_valid_binding(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
            .unwrap_or(false)
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// egui's bundled fonts lack CJK glyphs; graft the first usable system CJK
/// font onto the end of both font families (Latin stays on the default font).
fn load_cjk_fonts(ctx: &egui::Context) {
    const CANDIDATES: &[&str] = &[
        // Windows
        "C:/Windows/Fonts/msyh.ttc",
        "C:/Windows/Fonts/msyh.ttf",
        "C:/Windows/Fonts/simsun.ttc",
        "C:/Windows/Fonts/simhei.ttf",
        "C:/Windows/Fonts/Deng.ttf",
        // macOS
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/System/Library/Fonts/Hiragino Sans GB.ttc",
        // Linux
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/usr/share/fonts/wenquanyi/wqy-microhei/wqy-microhei.ttc",
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
    ];
    for path in CANDIDATES {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "cjk".to_owned(),
            std::sync::Arc::new(egui::FontData::from_owned(bytes)),
        );
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push("cjk".to_owned());
        }
        ctx.set_fonts(fonts);
        return;
    }
    eprintln!("warning: no system CJK font found; Chinese text may render as boxes");
}

impl eframe::App for GuiApp {
    /// Non-UI per-frame work (0.36 splits this out of `ui`).
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_jobs();
        if self.job_running {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        egui::Panel::left("nav")
            .resizable(false)
            .default_size(150.0)
            .show(ui, |ui| {
                ui.add_space(8.0);
                ui.heading("veilweave");
                ui.add_space(12.0);
                ui.selectable_value(&mut self.page, Page::Accounts, "账号 / Accounts");
                ui.selectable_value(&mut self.page, Page::Deploy, "部署 / Deploy");
                ui.selectable_value(&mut self.page, Page::Manage, "管理 / Manage");
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    if self.job_running {
                        ui.colored_label(Color32::YELLOW, "⏳ 任务进行中… / working");
                    }
                });
            });

        egui::CentralPanel::default().show(ui, |ui| {
            if let Some((is_error, text)) = &self.status {
                let color = if *is_error {
                    Color32::LIGHT_RED
                } else {
                    Color32::LIGHT_GREEN
                };
                ui.colored_label(color, text);
                ui.separator();
            }
            match self.page {
                Page::Accounts => self.ui_accounts(ui),
                Page::Deploy => self.ui_deploy(ui),
                Page::Manage => self.ui_manage(ui),
            }
        });

        self.ui_confirm_modals(&ctx);
    }
}

// ─── Pages ───────────────────────────────────────────────────────────────────

impl GuiApp {
    fn ui_accounts(&mut self, ui: &mut egui::Ui) {
        ui.heading("账号 / Accounts");
        ui.add_space(6.0);

        if self.cfg.accounts.is_empty() {
            ui.label("暂无账号 / no accounts yet");
        } else {
            // Snapshot rows first so the grid closure can mutate `self` freely.
            let rows: Vec<(usize, String, String, String, String, bool)> = self
                .cfg
                .accounts
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    (
                        i,
                        a.name.clone(),
                        a.account_id.clone(),
                        a.workers_dev_subdomain
                            .clone()
                            .unwrap_or_else(|| "?".into()),
                        mask_token(&a.token),
                        self.cfg.deployments.iter().any(|d| d.account == a.name),
                    )
                })
                .collect();
            egui::Grid::new("accounts_grid")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("标签 / Label");
                    ui.strong("Account ID");
                    ui.strong("workers.dev 子域 / subdomain");
                    ui.strong("Token");
                    ui.end_row();
                    for (i, name, account_id, subdomain, token, referenced) in rows {
                        ui.label(&name);
                        ui.label(&account_id);
                        ui.label(&subdomain);
                        ui.label(&token);
                        if ui
                            .add_enabled(!self.job_running, egui::Button::new("删除 / Delete"))
                            .clicked()
                        {
                            if referenced {
                                self.set_status(
                                    true,
                                    format!(
                                        "账号 {name:?} 仍有部署记录，无法删除 / still referenced by deployments"
                                    ),
                                );
                            } else {
                                self.confirm_delete_account = Some(i);
                            }
                        }
                        ui.end_row();
                    }
                });
        }

        ui.add_space(12.0);
        ui.separator();
        ui.heading("添加账号 / Add account");
        ui.label("需要权限 / required permissions:");
        ui.monospace(crate::wizard::TOKEN_PERMISSIONS);
        if ui
            .button("打开 Cloudflare API Token 页面 / Open token page")
            .clicked()
        {
            let _ = open::that(crate::wizard::TOKEN_URL);
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Token:");
            ui.add(
                egui::TextEdit::singleline(&mut self.add_token)
                    .password(true)
                    .desired_width(360.0),
            );
            if ui
                .add_enabled(!self.job_running, egui::Button::new("验证 Token / Verify"))
                .clicked()
            {
                self.spawn_verify_token();
            }
        });
        ui.horizontal(|ui| {
            ui.label("本地标签 / label (可选 / optional):");
            ui.add(egui::TextEdit::singleline(&mut self.add_label).desired_width(200.0));
        });

        if let Some((_, accounts, selected)) = &mut self.verified {
            ui.add_space(6.0);
            let mut add_clicked = false;
            ui.horizontal(|ui| {
                ui.label("Cloudflare 账号 / account:");
                egui::ComboBox::from_id_salt("cf_account_pick")
                    .selected_text(&accounts[*selected].name)
                    .show_ui(ui, |ui| {
                        for (i, a) in accounts.iter().enumerate() {
                            ui.selectable_value(selected, i, format!("{} ({})", a.name, a.id));
                        }
                    });
                if ui
                    .add_enabled(!self.job_running, egui::Button::new("添加 / Add"))
                    .clicked()
                {
                    add_clicked = true;
                }
            });
            // Spawn after the `&mut self.verified` borrow has ended.
            if add_clicked {
                self.spawn_add_account();
            }
        }
    }

    fn ui_deploy(&mut self, ui: &mut egui::Ui) {
        ui.heading("部署 / Deploy");
        ui.add_space(6.0);

        let bundle_dir = deploy::locate_bundle_dir(None);
        let bundle_ok = bundle_dir.join("relay/build/index.js").is_file()
            && bundle_dir.join("sub/build/index.js").is_file();
        if bundle_ok {
            ui.label(format!("预置包 / bundle: {}", bundle_dir.display()));
        } else {
            ui.colored_label(
                Color32::LIGHT_RED,
                format!(
                    "未找到预置 worker 包（{}）。请从完整发行包运行本程序 / bundle not found",
                    bundle_dir.display()
                ),
            );
        }
        ui.add_space(6.0);

        if self.cfg.accounts.is_empty() {
            ui.colored_label(
                Color32::YELLOW,
                "请先在「账号」页添加 Cloudflare 账号 / add an account on the Accounts page first",
            );
            return;
        }

        egui::Grid::new("deploy_grid")
            .num_columns(2)
            .show(ui, |ui| {
                ui.label("Sub 账号 / sub account:");
                account_combo(ui, "sub_account", &self.cfg.accounts, &mut self.sub_account);
                ui.end_row();

                ui.label("Sub 名称 / sub worker name:");
                name_field(ui, "sub_name", &mut self.sub_name);
                ui.end_row();

                ui.label("KV 标题 / KV title:");
                ui.add(egui::TextEdit::singleline(&mut self.kv_title).desired_width(280.0));
                ui.end_row();

                ui.label("KV binding 名 / binding name:");
                ui.add(egui::TextEdit::singleline(&mut self.kv_binding).desired_width(280.0));
                ui.end_row();
            });
        ui.weak("建议使用自定义名称（随机默认值仅用于快速开始）/ custom innocuous names are STRONGLY recommended");

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.strong("Relays:");
            if ui
                .add_enabled(!self.job_running, egui::Button::new("添加 relay / Add"))
                .clicked()
            {
                self.relays.push(RelayRow {
                    account: 0,
                    name: crate::random_worker_name(),
                });
            }
        });
        let can_remove = self.relays.len() > 1;
        let mut remove = None;
        egui::Grid::new("relays_grid")
            .num_columns(4)
            .show(ui, |ui| {
                for (i, row) in self.relays.iter_mut().enumerate() {
                    ui.label(format!("#{}", i + 1));
                    account_combo(
                        ui,
                        format!("relay_account_{i}"),
                        &self.cfg.accounts,
                        &mut row.account,
                    );
                    name_field(ui, format!("relay_name_{i}"), &mut row.name);
                    if can_remove
                        && ui
                            .add_enabled(!self.job_running, egui::Button::new("移除 / Remove"))
                            .clicked()
                    {
                        remove = Some(i);
                    }
                    ui.end_row();
                }
            });
        if let Some(i) = remove {
            self.relays.remove(i);
        }

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.encryption, "启用 VLESS 加密 / enable encryption");
            if self.encryption {
                ui.colored_label(
                    Color32::LIGHT_RED,
                    "⚠ 实验性：mlkem768x25519plus 很耗 CPU，免费套餐可能超限 / EXPERIMENTAL: CPU-heavy on the free plan",
                );
            }
        });

        ui.add_space(10.0);
        if ui
            .add_enabled(
                !self.job_running && bundle_ok,
                egui::Button::new("开始部署 / Deploy").min_size(egui::vec2(160.0, 30.0)),
            )
            .clicked()
        {
            self.spawn_deploy();
        }

        if let Some(url) = &self.sub_url {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.strong("订阅链接 / subscription URL:");
                ui.monospace(url);
                if ui.button("复制 / Copy").clicked() {
                    ui.ctx().copy_text(url.clone());
                }
            });
        }

        if !self.log.is_empty() {
            ui.add_space(8.0);
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt("deploy_log")
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.log {
                        let color = match line.kind {
                            LogKind::Step => Color32::LIGHT_BLUE,
                            LogKind::Info => Color32::LIGHT_GREEN,
                            LogKind::Warn => Color32::GOLD,
                            LogKind::Error => Color32::LIGHT_RED,
                        };
                        ui.colored_label(color, &line.message);
                    }
                });
        }
    }

    fn ui_manage(&mut self, ui: &mut egui::Ui) {
        ui.heading("管理 / Manage");
        ui.add_space(6.0);

        if self.cfg.deployments.is_empty() {
            ui.label("暂无部署记录 / no deployments recorded");
            return;
        }
        // Snapshot rows first so the grid closure can mutate `self` freely.
        let rows: Vec<(usize, Role, String, String, String, Option<String>)> = self
            .cfg
            .deployments
            .iter()
            .enumerate()
            .map(|(i, d)| {
                (
                    i,
                    d.role,
                    d.name.clone(),
                    d.account.clone(),
                    d.domain.clone(),
                    d.subscription_url(),
                )
            })
            .collect();
        egui::Grid::new("manage_grid")
            .num_columns(5)
            .striped(true)
            .show(ui, |ui| {
                ui.strong("角色 / Role");
                ui.strong("名称 / Name");
                ui.strong("账号 / Account");
                ui.strong("域名 / Domain");
                ui.strong("操作 / Actions");
                ui.end_row();
                for (i, role, name, account, domain, url) in rows {
                    ui.label(role.to_string());
                    ui.label(&name);
                    ui.label(&account);
                    ui.label(&domain);
                    ui.horizontal(|ui| {
                        if let Some(url) = url {
                            if ui.button("复制订阅链接 / Copy URL").clicked() {
                                ui.ctx().copy_text(url);
                            }
                        }
                        if ui
                            .add_enabled(!self.job_running, egui::Button::new("删除 / Delete"))
                            .clicked()
                        {
                            self.confirm_delete_dep = Some(i);
                        }
                    });
                    ui.end_row();
                }
            });
    }

    fn ui_confirm_modals(&mut self, ctx: &egui::Context) {
        if let Some(idx) = self.confirm_delete_account {
            let name = self
                .cfg
                .accounts
                .get(idx)
                .map(|a| a.name.clone())
                .unwrap_or_default();
            let mut open = true;
            let mut confirm = false;
            let mut cancel = false;
            egui::Window::new("确认 / Confirm")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "从本地配置删除账号 {name:?}？（不影响 Cloudflare 上的资源）\nRemove from local config only?"
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("删除 / Delete").clicked() {
                            confirm = true;
                        }
                        if ui.button("取消 / Cancel").clicked() {
                            cancel = true;
                        }
                    });
                });
            if confirm {
                self.cfg.accounts.remove(idx);
                match self.cfg.save() {
                    Ok(()) => self.set_status(false, format!("已删除账号 {name:?} / removed")),
                    Err(e) => self.set_status(true, format!("保存配置失败 / save failed: {e:#}")),
                }
            }
            if !open || confirm || cancel {
                self.confirm_delete_account = None;
            }
        }

        if let Some(idx) = self.confirm_delete_dep {
            let Some(dep) = self.cfg.deployments.get(idx).cloned() else {
                self.confirm_delete_dep = None;
                return;
            };
            let what = if dep.role == Role::Sub {
                "worker 及其 KV 命名空间（订阅数据将丢失）/ worker AND its KV namespace"
            } else {
                "worker"
            };
            let mut open = true;
            let mut confirm = false;
            let mut cancel = false;
            egui::Window::new("确认删除 / Confirm delete")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "从 Cloudflare 删除 {} 的 {what}？\nDelete from Cloudflare?",
                        dep.name
                    ));
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(!self.job_running, egui::Button::new("删除 / Delete"))
                            .clicked()
                        {
                            confirm = true;
                        }
                        if ui.button("取消 / Cancel").clicked() {
                            cancel = true;
                        }
                    });
                });
            if confirm {
                self.spawn_delete_deployment(idx);
            }
            if !open || confirm || cancel {
                self.confirm_delete_dep = None;
            }
        }
    }
}

// ─── Small UI helpers ────────────────────────────────────────────────────────

fn account_combo(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    accounts: &[Account],
    selected: &mut usize,
) {
    let current = accounts
        .get(*selected)
        .map(|a| a.name.clone())
        .unwrap_or_else(|| "?".into());
    egui::ComboBox::from_id_salt(id)
        .selected_text(current)
        .show_ui(ui, |ui| {
            for (i, a) in accounts.iter().enumerate() {
                ui.selectable_value(selected, i, &a.name);
            }
        });
}

/// Worker-name text field with a "随机 / random" button beside it.
fn name_field(ui: &mut egui::Ui, _id: impl std::hash::Hash + std::fmt::Debug, name: &mut String) {
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(name).desired_width(220.0));
        if ui.small_button("随机 / Random").clicked() {
            *name = crate::random_worker_name();
        }
    });
}

fn mask_token(token: &str) -> String {
    if token.len() <= 8 {
        return "****".into();
    }
    format!("{}…{}", &token[..4], &token[token.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::kittest::Queryable;

    /// One dummy account, no deployments — enough to unlock the deploy form.
    fn test_config() -> Config {
        Config {
            accounts: vec![Account {
                name: "test".into(),
                token: "tok-12345678-abcd".into(), // gitleaks:allow — dummy test value
                account_id: "acc-0001".into(),
                workers_dev_subdomain: Some("tester".into()),
            }],
            deployments: vec![],
        }
    }

    /// Headless walk through all three pages (no window, no GL, no network).
    #[test]
    fn gui_pages_smoke() {
        let mut harness =
            egui_kittest::Harness::new_eframe(|cc| GuiApp::with_config(cc, test_config()));
        harness.run();

        // Default page is Deploy, with the form unlocked by the dummy account.
        harness.get_by_label("开始部署 / Deploy");
        harness.get_by_label("启用 VLESS 加密 / enable encryption");

        // Accounts page: add-account form with permissions note.
        harness.get_by_label("账号 / Accounts").click();
        harness.run();
        harness.get_by_label("添加账号 / Add account");
        harness.get_by_label("打开 Cloudflare API Token 页面 / Open token page");

        // Manage page: empty-state hint.
        harness.get_by_label("管理 / Manage").click();
        harness.run();
        harness.get_by_label("暂无部署记录 / no deployments recorded");

        // Back to Deploy: enabling encryption shows the red experimental warning.
        harness.get_by_label("部署 / Deploy").click();
        harness.run();
        harness
            .get_by_label("启用 VLESS 加密 / enable encryption")
            .click();
        harness.run();
        harness.get_by_label(
            "⚠ 实验性：mlkem768x25519plus 很耗 CPU，免费套餐可能超限 / EXPERIMENTAL: CPU-heavy on the free plan",
        );
    }

    /// The deploy form validation rejects bad input before any network call.
    #[test]
    fn deploy_plan_validation() {
        let mut app = GuiApp::from_parts(test_config());
        // Valid defaults produce a plan.
        let plan = app.build_plan().expect("default form should be valid");
        assert_eq!(plan.relays.len(), 1);
        assert!(!plan.encryption);

        // Invalid worker name is rejected.
        app.sub_name = "Bad_Name".into();
        assert!(app.build_plan().is_err());
        app.sub_name = "ok-name".into();

        // Duplicate (account, name) across sub and relay is rejected.
        app.relays[0].name = app.sub_name.clone();
        assert!(app.build_plan().is_err());

        // Invalid KV binding (not a JS identifier) is rejected.
        app.relays[0].name = "other-name".into();
        app.kv_binding = "9bad".into();
        assert!(app.build_plan().is_err());
    }

    #[test]
    fn token_masking() {
        assert_eq!(mask_token("short"), "****");
        assert_eq!(mask_token("abcd1234wxyz"), "abcd…wxyz");
    }
}
