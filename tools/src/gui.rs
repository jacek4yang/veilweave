//! egui front-end for the deploy core. All orchestration stays in
//! `deploy::execute` / `config::Config` / `cfapi::CfClient` — this module is
//! pure UI state plus background-job plumbing.
//!
//! Threading: egui's frame callbacks never block. API work (token
//! verification, deploy, deletes) runs on a `std::thread` with its own tokio
//! runtime and reports back through an `mpsc` channel; `logic()` drains the
//! channel every frame and repaints while a job is in flight. Action buttons
//! are disabled whenever `job_running` is set, so jobs are effectively
//! serialized.
//!
//! UI language: auto-detected from the OS locale (Chinese when it starts with
//! "zh", English otherwise), overridable via the sidebar selector; the choice
//! persists in `Config::ui_language`. Every user-visible string goes through
//! `tr(zh, en)` / `trf(zh_fmt, en_fmt)`.

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

/// UI language.
#[derive(PartialEq, Clone, Copy, Debug)]
enum Lang {
    Zh,
    En,
}

impl Lang {
    /// OS locale → language; Chinese when the locale starts with "zh".
    fn detect() -> Self {
        match sys_locale::get_locale() {
            Some(locale) if locale.starts_with("zh") => Lang::Zh,
            _ => Lang::En,
        }
    }

    /// Stored override ("zh"/"en") wins; otherwise auto-detect.
    fn from_config(stored: Option<&str>) -> Self {
        match stored {
            Some("zh") => Lang::Zh,
            Some("en") => Lang::En,
            _ => Lang::detect(),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Lang::Zh => "zh",
            Lang::En => "en",
        }
    }
}

struct RelayRow {
    account: usize,
    name: String,
}

pub struct GuiApp {
    cfg: Config,
    /// Config file path override for tests (None = platform default).
    cfg_path: Option<std::path::PathBuf>,
    lang: Lang,
    /// Refreshed from `ctx.theme()` every frame; drives color picks.
    dark: bool,
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

/// Launch the window. Returns Err when no display is available at all.
///
/// Renderer order: wgpu (DX12 on Windows — works even on DisplayLink / RDP /
/// software-WARP machines, Metal on macOS, Vulkan on Linux; zero runtime
/// dependencies, fully static) → glow (OpenGL, needs GL 2.0+) → Err (caller
/// prints the CLI-wizard fallback message).
pub fn launch() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("veilweave 部署器 / veilweave deployer")
            .with_inner_size([900.0, 640.0])
            .with_min_inner_size([720.0, 480.0]),
        ..Default::default()
    };
    let make_app =
        |cc: &eframe::CreationContext<'_>| Ok(Box::new(GuiApp::new(cc)) as Box<dyn eframe::App>);
    let wgpu = eframe::run_native(
        "veilweave",
        eframe::NativeOptions {
            renderer: eframe::Renderer::Wgpu,
            ..options.clone()
        },
        Box::new(make_app),
    );
    match wgpu {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("wgpu renderer unavailable ({e}), trying glow/OpenGL…");
            eframe::run_native(
                "veilweave",
                eframe::NativeOptions {
                    renderer: eframe::Renderer::Glow,
                    ..options
                },
                Box::new(make_app),
            )
            .map_err(|e| anyhow!("{e}"))
        }
    }
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
        // Dark is the supported default; a stored "light" override wins.
        let theme = match cfg.ui_theme.as_deref() {
            Some("light") => egui::ThemePreference::Light,
            _ => egui::ThemePreference::Dark,
        };
        cc.egui_ctx.set_theme(theme);
        Self::from_parts(cfg)
    }

    /// Everything except the font/theme setup, which needs an egui context.
    fn from_parts(cfg: Config) -> Self {
        let (tx, rx) = channel();
        let lang = Lang::from_config(cfg.ui_language.as_deref());
        Self {
            cfg,
            cfg_path: None,
            lang,
            dark: true,
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

    // ── Theme-aware accent colors (strong contrast on the active theme) ──
    fn c_ok(&self) -> Color32 {
        if self.dark {
            Color32::LIGHT_GREEN
        } else {
            Color32::from_rgb(0, 120, 40)
        }
    }

    fn c_error(&self) -> Color32 {
        if self.dark {
            Color32::from_rgb(255, 110, 110)
        } else {
            Color32::from_rgb(190, 20, 20)
        }
    }

    fn c_warn(&self) -> Color32 {
        if self.dark {
            Color32::GOLD
        } else {
            Color32::from_rgb(170, 95, 0)
        }
    }

    fn c_step(&self) -> Color32 {
        if self.dark {
            Color32::LIGHT_BLUE
        } else {
            Color32::from_rgb(30, 60, 200)
        }
    }

    fn set_status(&mut self, is_error: bool, text: impl Into<String>) {
        self.status = Some((is_error, text.into()));
    }

    /// Persist the current UI preferences (language/theme) to the config file.
    fn save_prefs(&mut self) {
        self.cfg.ui_language = Some(self.lang.as_str().to_string());
        if let Err(e) = self.save_cfg() {
            let msg = trf(
                self.lang,
                format!("保存配置失败：{e:#}"),
                format!("Failed to save config: {e:#}"),
            );
            self.set_status(true, msg);
        }
    }

    /// Save the config, honoring the test override path.
    fn save_cfg(&self) -> Result<()> {
        match &self.cfg_path {
            Some(path) => self.cfg.save_to(path),
            None => self.cfg.save(),
        }
    }

    /// Reload the config from disk, honoring the test override path.
    fn reload_cfg(&self) -> Result<Config> {
        match &self.cfg_path {
            Some(path) => Config::load_from(path),
            None => Config::load(),
        }
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
                            self.set_status(false, tr(self.lang, "部署完成", "Deploy finished"));
                        }
                        Err(e) => self.set_status(
                            true,
                            trf(
                                self.lang,
                                format!("部署失败：{e}"),
                                format!("Deploy failed: {e}"),
                            ),
                        ),
                    }
                    // execute() already saved; reload to pick up new records.
                    if let Ok(cfg) = self.reload_cfg() {
                        self.cfg = cfg;
                    }
                }
                GuiMsg::TokenChecked(token, result) => {
                    self.job_running = false;
                    match result {
                        Ok(accounts) => {
                            self.verified = Some((token, accounts, 0));
                            self.set_status(
                                false,
                                tr(self.lang, "Token 验证通过", "Token verified"),
                            );
                        }
                        Err(e) => {
                            self.verified = None;
                            self.set_status(
                                true,
                                trf(
                                    self.lang,
                                    format!("Token 验证失败：{e}"),
                                    format!("Token verification failed: {e}"),
                                ),
                            );
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
                                    trf(
                                        self.lang,
                                        format!("账号标签 {label:?} 已存在"),
                                        format!("Label {label:?} already exists"),
                                    ),
                                );
                                return changed;
                            }
                            let account = Account {
                                name: label.clone(),
                                ..account
                            };
                            self.cfg.accounts.push(account);
                            match self.save_cfg() {
                                Ok(()) => {
                                    self.set_status(
                                        false,
                                        trf(
                                            self.lang,
                                            format!("已添加账号 {label:?}"),
                                            format!("Account {label:?} added"),
                                        ),
                                    );
                                    self.add_label.clear();
                                    self.add_token.clear();
                                    self.verified = None;
                                }
                                Err(e) => self.set_status(
                                    true,
                                    trf(
                                        self.lang,
                                        format!("保存配置失败：{e:#}"),
                                        format!("Failed to save config: {e:#}"),
                                    ),
                                ),
                            }
                        }
                        Err(e) => self.set_status(
                            true,
                            trf(
                                self.lang,
                                format!("添加账号失败：{e}"),
                                format!("Failed to add account: {e}"),
                            ),
                        ),
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
                            match self.save_cfg() {
                                Ok(()) => self.set_status(
                                    false,
                                    trf(
                                        self.lang,
                                        format!("已删除 {name}"),
                                        format!("Deleted {name}"),
                                    ),
                                ),
                                Err(e) => self.set_status(
                                    true,
                                    trf(
                                        self.lang,
                                        format!("保存配置失败：{e:#}"),
                                        format!("Failed to save config: {e:#}"),
                                    ),
                                ),
                            }
                        }
                        Err(e) => self.set_status(
                            true,
                            trf(
                                self.lang,
                                format!("删除失败：{e}"),
                                format!("Delete failed: {e}"),
                            ),
                        ),
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
            self.set_status(
                true,
                tr(self.lang, "请先粘贴 API Token", "Paste an API token first"),
            );
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
            self.set_status(
                true,
                tr(
                    self.lang,
                    "请选择一个 Cloudflare 账号",
                    "Pick a Cloudflare account",
                ),
            );
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
            return Err(tr(
                self.lang,
                "请先在「账号」页添加 Cloudflare 账号",
                "Add a Cloudflare account on the Accounts page first",
            )
            .into());
        }
        if self.relays.is_empty() {
            return Err(tr(
                self.lang,
                "至少需要一个 relay",
                "At least one relay is required",
            )
            .into());
        }
        let account_name = |idx: usize| -> std::result::Result<String, String> {
            self.cfg
                .accounts
                .get(idx)
                .map(|a| a.name.clone())
                .ok_or_else(|| {
                    tr(self.lang, "账号选择无效", "Invalid account selection").to_string()
                })
        };
        let mut names: Vec<(String, String)> = Vec::new(); // (account, worker name)
        let mut check_name = |account: &str, name: &str| -> std::result::Result<(), String> {
            crate::wizard::validate_worker_name(name).map_err(|e| {
                trf(
                    self.lang,
                    format!("worker 名称 {name:?} 无效：{e}"),
                    format!("Invalid worker name {name:?}: {e}"),
                )
            })?;
            let key = (account.to_string(), name.to_string());
            if names.contains(&key) {
                return Err(trf(
                    self.lang,
                    format!("同一账号下名称重复：{name:?}"),
                    format!("Duplicate name {name:?} on the same account"),
                ));
            }
            names.push(key);
            Ok(())
        };

        let sub_account = account_name(self.sub_account)?;
        check_name(&sub_account, &self.sub_name)?;
        if !is_valid_binding(&self.kv_binding) {
            return Err(trf(
                self.lang,
                format!(
                    "KV binding 名称 {:?} 无效（须为合法 JS 标识符）",
                    self.kv_binding
                ),
                format!(
                    "Invalid KV binding name {:?} (must be a valid JS identifier)",
                    self.kv_binding
                ),
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
                trf(
                    self.lang,
                    format!("账号 {:?} 已不在配置中", dep.account),
                    format!("Account {:?} is no longer in the config", dep.account),
                ),
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

/// Pick a user-visible string by UI language.
fn tr(lang: Lang, zh: &'static str, en: &'static str) -> &'static str {
    match lang {
        Lang::Zh => zh,
        Lang::En => en,
    }
}

/// Same for interpolated messages (both sides are cheap format!s).
fn trf(lang: Lang, zh: String, en: String) -> String {
    match lang {
        Lang::Zh => zh,
        Lang::En => en,
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
        self.dark = matches!(ctx.theme(), egui::Theme::Dark);
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
                ui.selectable_value(
                    &mut self.page,
                    Page::Accounts,
                    tr(self.lang, "账号", "Accounts"),
                );
                ui.selectable_value(
                    &mut self.page,
                    Page::Deploy,
                    tr(self.lang, "部署", "Deploy"),
                );
                ui.selectable_value(
                    &mut self.page,
                    Page::Manage,
                    tr(self.lang, "管理", "Manage"),
                );

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    if self.job_running {
                        ui.colored_label(
                            self.c_warn(),
                            tr(self.lang, "⏳ 任务进行中…", "⏳ Working…"),
                        );
                    }
                    ui.add_space(4.0);
                    // Language override (persisted in the config file).
                    ui.horizontal(|ui| {
                        for (lang, label) in [(Lang::Zh, "中文"), (Lang::En, "English")] {
                            if ui.selectable_label(self.lang == lang, label).clicked() {
                                self.lang = lang;
                                self.save_prefs();
                            }
                        }
                    });
                    // Theme toggle (persisted; dark is the default).
                    ui.horizontal(|ui| {
                        let light = !self.dark;
                        if ui
                            .selectable_label(!light, tr(self.lang, "深色", "Dark"))
                            .clicked()
                        {
                            ui.ctx().set_theme(egui::ThemePreference::Dark);
                            self.cfg.ui_theme = Some("dark".into());
                            self.save_prefs();
                        }
                        if ui
                            .selectable_label(light, tr(self.lang, "浅色", "Light"))
                            .clicked()
                        {
                            ui.ctx().set_theme(egui::ThemePreference::Light);
                            self.cfg.ui_theme = Some("light".into());
                            self.save_prefs();
                        }
                    });
                });
            });

        egui::CentralPanel::default().show(ui, |ui| {
            if let Some((is_error, text)) = &self.status {
                let color = if *is_error {
                    self.c_error()
                } else {
                    self.c_ok()
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
        ui.heading(tr(self.lang, "账号", "Accounts"));
        ui.add_space(6.0);

        if self.cfg.accounts.is_empty() {
            ui.label(tr(self.lang, "暂无账号", "No accounts yet"));
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
            let (h_label, h_subdomain, delete_label) = (
                tr(self.lang, "标签", "Label"),
                tr(self.lang, "workers.dev 子域", "workers.dev subdomain"),
                tr(self.lang, "删除", "Delete"),
            );
            egui::Grid::new("accounts_grid")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong(h_label);
                    ui.strong("Account ID");
                    ui.strong(h_subdomain);
                    ui.strong("Token");
                    ui.end_row();
                    for (i, name, account_id, subdomain, token, referenced) in rows {
                        ui.label(&name);
                        ui.label(&account_id);
                        ui.label(&subdomain);
                        ui.label(&token);
                        if ui
                            .add_enabled(!self.job_running, egui::Button::new(delete_label))
                            .clicked()
                        {
                            if referenced {
                                self.set_status(
                                    true,
                                    trf(
                                        self.lang,
                                        format!("账号 {name:?} 仍有部署记录，无法删除"),
                                        format!(
                                            "Account {name:?} is still referenced by deployments"
                                        ),
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
        ui.heading(tr(self.lang, "添加账号", "Add account"));
        ui.label(tr(self.lang, "需要权限：", "Required permissions:"));
        ui.monospace(crate::wizard::TOKEN_PERMISSIONS);
        if ui
            .button(tr(
                self.lang,
                "打开 Cloudflare API Token 页面",
                "Open Cloudflare API token page",
            ))
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
                .add_enabled(
                    !self.job_running,
                    egui::Button::new(tr(self.lang, "验证 Token", "Verify token")),
                )
                .clicked()
            {
                self.spawn_verify_token();
            }
        });
        ui.horizontal(|ui| {
            ui.label(tr(
                self.lang,
                "本地标签（可选）：",
                "Local label (optional):",
            ));
            ui.add(egui::TextEdit::singleline(&mut self.add_label).desired_width(200.0));
        });

        if let Some((_, accounts, selected)) = &mut self.verified {
            ui.add_space(6.0);
            let mut add_clicked = false;
            ui.horizontal(|ui| {
                ui.label(tr(self.lang, "Cloudflare 账号：", "Cloudflare account:"));
                egui::ComboBox::from_id_salt("cf_account_pick")
                    .selected_text(&accounts[*selected].name)
                    .show_ui(ui, |ui| {
                        for (i, a) in accounts.iter().enumerate() {
                            ui.selectable_value(selected, i, format!("{} ({})", a.name, a.id));
                        }
                    });
                if ui
                    .add_enabled(
                        !self.job_running,
                        egui::Button::new(tr(self.lang, "添加", "Add")),
                    )
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
        ui.heading(tr(self.lang, "部署", "Deploy"));
        ui.add_space(6.0);

        let bundle_dir = deploy::locate_bundle_dir(None);
        let bundle_ok = bundle_dir.join("relay/build/index.js").is_file()
            && bundle_dir.join("sub/build/index.js").is_file();
        if bundle_ok {
            ui.label(trf(
                self.lang,
                format!("预置包：{}", bundle_dir.display()),
                format!("Bundle: {}", bundle_dir.display()),
            ));
        } else {
            ui.colored_label(
                self.c_error(),
                trf(self.lang,
                    format!(
                        "未找到预置 worker 包（{}）。请从完整发行包运行本程序",
                        bundle_dir.display()
                    ),
                    format!(
                        "Prebuilt worker bundle not found ({}). Run this program from the full release archive",
                        bundle_dir.display()
                    ),
                ),
            );
        }
        ui.add_space(6.0);

        if self.cfg.accounts.is_empty() {
            ui.colored_label(
                self.c_warn(),
                tr(
                    self.lang,
                    "请先在「账号」页添加 Cloudflare 账号",
                    "Add an account on the Accounts page first",
                ),
            );
            return;
        }

        let (l_sub_account, l_sub_name, l_kv_title, l_kv_binding) = (
            tr(self.lang, "Sub 账号：", "Sub account:"),
            tr(self.lang, "Sub 名称：", "Sub worker name:"),
            tr(self.lang, "KV 标题：", "KV title:"),
            tr(self.lang, "KV binding 名：", "KV binding name:"),
        );
        egui::Grid::new("deploy_grid")
            .num_columns(2)
            .show(ui, |ui| {
                ui.label(l_sub_account);
                account_combo(ui, "sub_account", &self.cfg.accounts, &mut self.sub_account);
                ui.end_row();

                ui.label(l_sub_name);
                name_field(ui, "sub_name", &mut self.sub_name, self.lang);
                ui.end_row();

                ui.label(l_kv_title);
                ui.add(egui::TextEdit::singleline(&mut self.kv_title).desired_width(280.0));
                ui.end_row();

                ui.label(l_kv_binding);
                ui.add(egui::TextEdit::singleline(&mut self.kv_binding).desired_width(280.0));
                ui.end_row();
            });
        ui.weak(tr(self.lang,
            "建议使用自定义名称（随机默认值仅用于快速开始）",
            "Custom innocuous names are STRONGLY recommended (random defaults are for quick starts only)",
        ));

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.strong("Relays:");
            if ui
                .add_enabled(
                    !self.job_running,
                    egui::Button::new(tr(self.lang, "添加 relay", "Add relay")),
                )
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
        let (lang, remove_label) = (self.lang, tr(self.lang, "移除", "Remove"));
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
                    name_field(ui, format!("relay_name_{i}"), &mut row.name, lang);
                    if can_remove
                        && ui
                            .add_enabled(!self.job_running, egui::Button::new(remove_label))
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
            ui.checkbox(
                &mut self.encryption,
                tr(self.lang, "启用 VLESS 加密", "Enable VLESS encryption"),
            );
            if self.encryption {
                ui.colored_label(
                    self.c_error(),
                    tr(self.lang,
                        "⚠ 实验性：mlkem768x25519plus 很耗 CPU，免费套餐可能超限",
                        "⚠ EXPERIMENTAL: mlkem768x25519plus is CPU-heavy and may exceed the free plan",
                    ),
                );
            }
        });

        ui.add_space(10.0);
        if ui
            .add_enabled(
                !self.job_running && bundle_ok,
                egui::Button::new(tr(self.lang, "开始部署", "Start deploy"))
                    .min_size(egui::vec2(160.0, 30.0)),
            )
            .clicked()
        {
            self.spawn_deploy();
        }

        if let Some(url) = &self.sub_url {
            ui.add_space(8.0);
            let copy_label = tr(self.lang, "复制", "Copy");
            ui.horizontal(|ui| {
                ui.strong(tr(self.lang, "订阅链接：", "Subscription URL:"));
                ui.monospace(url);
                if ui.button(copy_label).clicked() {
                    ui.ctx().copy_text(url.clone());
                }
            });
        }

        if !self.log.is_empty() {
            ui.add_space(8.0);
            ui.separator();
            let (c_step, c_info, c_warn, c_error) =
                (self.c_step(), self.c_ok(), self.c_warn(), self.c_error());
            egui::ScrollArea::vertical()
                .id_salt("deploy_log")
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.log {
                        let color = match line.kind {
                            LogKind::Step => c_step,
                            LogKind::Info => c_info,
                            LogKind::Warn => c_warn,
                            LogKind::Error => c_error,
                        };
                        ui.colored_label(color, &line.message);
                    }
                });
        }
    }

    fn ui_manage(&mut self, ui: &mut egui::Ui) {
        ui.heading(tr(self.lang, "管理", "Manage"));
        ui.add_space(6.0);

        if self.cfg.deployments.is_empty() {
            ui.label(tr(self.lang, "暂无部署记录", "No deployments recorded"));
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
        let (h_role, h_name, h_account, h_domain, h_actions, copy_label, delete_label) = (
            tr(self.lang, "角色", "Role"),
            tr(self.lang, "名称", "Name"),
            tr(self.lang, "账号", "Account"),
            tr(self.lang, "域名", "Domain"),
            tr(self.lang, "操作", "Actions"),
            tr(self.lang, "复制订阅链接", "Copy URL"),
            tr(self.lang, "删除", "Delete"),
        );
        egui::Grid::new("manage_grid")
            .num_columns(5)
            .striped(true)
            .show(ui, |ui| {
                ui.strong(h_role);
                ui.strong(h_name);
                ui.strong(h_account);
                ui.strong(h_domain);
                ui.strong(h_actions);
                ui.end_row();
                for (i, role, name, account, domain, url) in rows {
                    ui.label(role.to_string());
                    ui.label(&name);
                    ui.label(&account);
                    ui.label(&domain);
                    ui.horizontal(|ui| {
                        if let Some(url) = url {
                            if ui.button(copy_label).clicked() {
                                ui.ctx().copy_text(url);
                            }
                        }
                        if ui
                            .add_enabled(!self.job_running, egui::Button::new(delete_label))
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
            let body = trf(self.lang,
                format!("从本地配置删除账号 {name:?}？（不影响 Cloudflare 上的资源）"),
                format!("Remove account {name:?} from the local config? (Cloudflare resources are not affected)"),
            );
            let (title, delete_label, cancel_label) = (
                tr(self.lang, "确认", "Confirm"),
                tr(self.lang, "删除", "Delete"),
                tr(self.lang, "取消", "Cancel"),
            );
            let mut open = true;
            let mut confirm = false;
            let mut cancel = false;
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(body);
                    ui.horizontal(|ui| {
                        if ui.button(delete_label).clicked() {
                            confirm = true;
                        }
                        if ui.button(cancel_label).clicked() {
                            cancel = true;
                        }
                    });
                });
            if confirm {
                self.cfg.accounts.remove(idx);
                match self.save_cfg() {
                    Ok(()) => self.set_status(
                        false,
                        trf(
                            self.lang,
                            format!("已删除账号 {name:?}"),
                            format!("Account {name:?} removed"),
                        ),
                    ),
                    Err(e) => self.set_status(
                        true,
                        trf(
                            self.lang,
                            format!("保存配置失败：{e:#}"),
                            format!("Failed to save config: {e:#}"),
                        ),
                    ),
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
                tr(
                    self.lang,
                    "worker 及其 KV 命名空间（订阅数据将丢失）",
                    "worker AND its KV namespace (subscription data will be lost)",
                )
            } else {
                "worker"
            };
            let body = trf(
                self.lang,
                format!("从 Cloudflare 删除 {}（{what}）？", dep.name),
                format!("Delete {} ({what}) from Cloudflare?", dep.name),
            );
            let (title, delete_label, cancel_label) = (
                tr(self.lang, "确认删除", "Confirm delete"),
                tr(self.lang, "删除", "Delete"),
                tr(self.lang, "取消", "Cancel"),
            );
            let mut open = true;
            let mut confirm = false;
            let mut cancel = false;
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(body);
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(!self.job_running, egui::Button::new(delete_label))
                            .clicked()
                        {
                            confirm = true;
                        }
                        if ui.button(cancel_label).clicked() {
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

/// Worker-name text field with a randomize button beside it.
fn name_field(
    ui: &mut egui::Ui,
    _id: impl std::hash::Hash + std::fmt::Debug,
    name: &mut String,
    lang: Lang,
) {
    let random_label = match lang {
        Lang::Zh => "随机",
        Lang::En => "Random",
    };
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(name).desired_width(220.0));
        if ui.small_button(random_label).clicked() {
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
            ui_language: None,
            ui_theme: None,
        }
    }

    /// Headless walk through all three pages in English (no window, no network).
    #[test]
    fn gui_pages_smoke_en() {
        let mut harness =
            egui_kittest::Harness::new_eframe(|cc| GuiApp::with_config(cc, test_config()));
        harness.state_mut().lang = Lang::En;
        harness.run();

        // Default page is Deploy, with the form unlocked by the dummy account.
        // ("Deploy" alone would be ambiguous: nav, heading and button.)
        harness.get_by_label("Start deploy");
        harness.get_by_label("Enable VLESS encryption");

        // Accounts page: add-account form with permissions note.
        harness.get_by_label("Accounts").click();
        harness.run();
        harness.get_by_label("Add account");
        harness.get_by_label("Open Cloudflare API token page");

        // Manage page: empty-state hint.
        harness.get_by_label("Manage").click();
        harness.run();
        harness.get_by_label("No deployments recorded");

        // Back to Deploy: enabling encryption shows the experimental warning.
        harness.get_by_label("Deploy").click();
        harness.run();
        harness.get_by_label("Enable VLESS encryption").click();
        harness.run();
        harness.get_by_label(
            "⚠ EXPERIMENTAL: mlkem768x25519plus is CPU-heavy and may exceed the free plan",
        );
    }

    /// Same walk in Chinese.
    #[test]
    fn gui_pages_smoke_zh() {
        let mut harness =
            egui_kittest::Harness::new_eframe(|cc| GuiApp::with_config(cc, test_config()));
        harness.state_mut().lang = Lang::Zh;
        harness.run();

        harness.get_by_label("开始部署");
        harness.get_by_label("启用 VLESS 加密");

        harness.get_by_label("账号").click();
        harness.run();
        harness.get_by_label("添加账号");
        harness.get_by_label("打开 Cloudflare API Token 页面");

        harness.get_by_label("管理").click();
        harness.run();
        harness.get_by_label("暂无部署记录");

        harness.get_by_label("部署").click();
        harness.run();
        harness.get_by_label("启用 VLESS 加密").click();
        harness.run();
        harness.get_by_label("⚠ 实验性：mlkem768x25519plus 很耗 CPU，免费套餐可能超限");
    }

    /// The language selector persists its choice into the config.
    #[test]
    fn language_selector_persists() {
        // Redirect config writes to a temp path — never touch the real one.
        let tmp = std::env::temp_dir().join(format!("vw-gui-test-{}.toml", std::process::id()));
        let mut harness =
            egui_kittest::Harness::new_eframe(|cc| GuiApp::with_config(cc, test_config()));
        harness.state_mut().lang = Lang::Zh;
        harness.state_mut().cfg_path = Some(tmp.clone());
        harness.run();
        // Switch to English via the sidebar selector.
        harness.get_by_label("English").click();
        harness.run();
        let app = harness.state();
        assert_eq!(app.lang, Lang::En);
        assert_eq!(app.cfg.ui_language.as_deref(), Some("en"));
        // The override must have been written to the (temp) config file.
        let saved = Config::load_from(&tmp).unwrap();
        assert_eq!(saved.ui_language.as_deref(), Some("en"));
        std::fs::remove_file(&tmp).ok();
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
