//! Interactive CLI front-end for the deploy core (`veilweave-tools deploy`
//! and `veilweave-tools manage`). All prompts live here; `deploy.rs` stays
//! UI-agnostic so the GUI can drive it directly.

use anyhow::{bail, Context, Result};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use veilweave_core::config::{Config, Role};
use veilweave_core::deploy::{self, BundleSource, DeployPlan, LogKind, RelaySpec, SubSpec};

pub const TOKEN_URL: &str = "https://dash.cloudflare.com/profile/api-tokens";
pub const TOKEN_PERMISSIONS: &str = "\
  · Account → Workers Scripts → Edit
  · Account → Workers KV Storage → Edit
  · Account → Account Settings → Read   (for the workers.dev subdomain)
  · Account → Analytics → Read          (可选 / optional — for usage stats)";

pub async fn run_deploy(bundle_dir: Option<String>) -> Result<()> {
    let theme = ColorfulTheme::default();
    let mut cfg = Config::load()?;

    println!("veilweave deploy — direct-to-Cloudflare, no wrangler required.");
    println!();

    // ── Accounts ────────────────────────────────────────────────────────────
    while cfg.accounts.is_empty() {
        println!("No Cloudflare accounts configured yet.");
        add_account(&theme, &mut cfg).await?;
    }
    while Confirm::with_theme(&theme)
        .with_prompt(
            "Add another Cloudflare account? (multi-account setups: sub on one, relays on others)",
        )
        .default(false)
        .interact()?
    {
        add_account(&theme, &mut cfg).await?;
    }

    // ── Topology ────────────────────────────────────────────────────────────
    let account_names: Vec<String> = cfg.accounts.iter().map(|a| a.name.clone()).collect();

    println!();
    let sub_account = pick(
        &theme,
        "Which account hosts the SUB worker (subscription endpoint)?",
        &account_names,
    )?;

    let relay_count: usize = Input::with_theme(&theme)
        .with_prompt("How many relay workers?")
        .default(1usize)
        .validate_with(|n: &usize| {
            if (1..=20).contains(n) {
                Ok(())
            } else {
                Err("between 1 and 20")
            }
        })
        .interact_text()?;

    let mut relays = Vec::new();
    for i in 0..relay_count {
        println!();
        let account = if relay_count > 1 || account_names.len() > 1 {
            pick(
                &theme,
                &format!("Account for relay #{}?", i + 1),
                &account_names,
            )?
        } else {
            account_names[0].clone()
        };
        let name = worker_name_prompt(&theme, &format!("Relay #{} worker name", i + 1))?;
        relays.push(RelaySpec {
            account,
            worker_name: name,
        });
    }

    println!();
    let sub_name = worker_name_prompt(&theme, "Sub worker name")?;
    let kv_binding: String = Input::with_theme(&theme)
        .with_prompt(
            "KV binding name (valid JS identifier; the worker reads it from the KV_BINDING var)",
        )
        .default(veilweave_core::util::random_kv_binding())
        .interact_text()?;

    // ── Encryption ──────────────────────────────────────────────────────────
    println!();
    let encryption = Confirm::with_theme(&theme)
        .with_prompt(
            "Enable EXPERIMENTAL VLESS Encryption (mlkem768x25519plus)? \
             CPU-heavy on the Workers free plan — default plaintext is recommended",
        )
        .default(false)
        .interact()?;

    // ── Confirm & run ───────────────────────────────────────────────────────
    let sub_domain = preview_domain(&cfg, &sub_account, &sub_name);
    println!();
    println!("Plan:");
    println!("  sub   {sub_name}  on account {sub_account}  →  https://{sub_domain}");
    for r in &relays {
        println!(
            "  relay {}  on account {}  →  https://{}",
            r.worker_name,
            r.account,
            preview_domain(&cfg, &r.account, &r.worker_name)
        );
    }
    println!(
        "  mode  {}",
        if encryption {
            "EXPERIMENTAL encryption (mlkem768x25519plus)"
        } else {
            "plaintext (encryption=none)"
        }
    );
    println!();
    if !Confirm::with_theme(&theme)
        .with_prompt("Deploy now?")
        .default(true)
        .interact()?
    {
        println!("Aborted; nothing was deployed.");
        return Ok(());
    }

    let plan = DeployPlan {
        sub: SubSpec {
            account: sub_account,
            worker_name: sub_name,
            kv_title: format!("{}-kv", veilweave_core::util::random_worker_name()),
            kv_binding,
        },
        relays,
        encryption,
    };

    let source = BundleSource::Dir(deploy::locate_bundle_dir(bundle_dir.as_deref()));
    println!();
    let outcome = deploy::execute(&plan, &source, &mut cfg, &mut |line| match line.kind {
        LogKind::Step => println!("▸ {}", line.message),
        LogKind::Info => println!("  ✔ {}", line.message),
        LogKind::Warn => eprintln!("  ⚠ {}", line.message),
        LogKind::Error => eprintln!("  ✖ {}", line.message),
    })
    .await?;

    println!();
    if let Some(url) = outcome.subscription_url() {
        println!("Deployment complete. Subscription URL (import into your client):");
        println!();
        println!("  {url}");
        println!();
        println!("Re-show it any time with:  veilweave-tools manage");
    }
    Ok(())
}

pub async fn run_manage() -> Result<()> {
    let theme = ColorfulTheme::default();
    let mut cfg = Config::load()?;

    if cfg.deployments.is_empty() {
        println!("No deployments recorded yet. Run `veilweave-tools deploy` first.");
        return Ok(());
    }

    loop {
        println!();
        let items: Vec<String> = cfg
            .deployments
            .iter()
            .map(|d| {
                format!(
                    "[{}] {}  →  https://{}  ({})",
                    d.role, d.name, d.domain, d.account
                )
            })
            .collect();
        let mut menu = items.clone();
        menu.push("Quit".to_string());
        let sel = Select::with_theme(&theme)
            .with_prompt("Deployments (select one)")
            .items(&menu)
            .default(0)
            .interact()?;
        if sel == items.len() {
            return Ok(());
        }

        let d = &cfg.deployments[sel];
        let mut actions = Vec::new();
        if d.role == Role::Sub {
            actions.push("Show subscription URL");
        }
        actions.push("Delete from Cloudflare");
        actions.push("Back");
        let action = Select::with_theme(&theme)
            .with_prompt(format!("{} ({})", d.name, d.role))
            .items(&actions)
            .default(0)
            .interact()?;

        match actions[action] {
            "Show subscription URL" => {
                if let Some(url) = cfg.deployments[sel].subscription_url() {
                    println!();
                    println!("  {url}");
                }
            }
            "Delete from Cloudflare" => {
                delete_deployment(&theme, &mut cfg, sel).await?;
            }
            _ => {}
        }
    }
}

/// Delete a deployment's Cloudflare resources and its local record.
async fn delete_deployment(theme: &ColorfulTheme, cfg: &mut Config, idx: usize) -> Result<()> {
    let d = cfg.deployments[idx].clone();
    let what = if d.role == Role::Sub {
        "worker AND its KV namespace (subscription data lost)"
    } else {
        "worker"
    };
    if !Confirm::with_theme(theme)
        .with_prompt(format!("Delete {} {what}?", d.name))
        .default(false)
        .interact()?
    {
        return Ok(());
    }

    let account = cfg
        .account(&d.account)
        .with_context(|| format!("account {:?} no longer in config", d.account))?
        .clone();
    let client = veilweave_core::cfapi::CfClient::new(&account.token)?;
    client.delete_worker(&account.account_id, &d.name).await?;
    println!("  ✔ deleted worker {}", d.name);
    if let Some(sub) = &d.sub {
        client
            .delete_kv_namespace(&account.account_id, &sub.kv_namespace_id)
            .await?;
        println!("  ✔ deleted KV namespace {}", sub.kv_title);
    }
    cfg.deployments.remove(idx);
    cfg.save()?;
    Ok(())
}

/// Guided token + account setup: open the dashboard, verify the pasted token,
/// pick the account, resolve the workers.dev subdomain, save.
async fn add_account(theme: &ColorfulTheme, cfg: &mut Config) -> Result<()> {
    println!();
    println!("Create an API token at:");
    println!("  {TOKEN_URL}");
    println!("(\"Create Custom Token\") with these permissions:");
    println!("{TOKEN_PERMISSIONS}");
    open_browser(TOKEN_URL);

    let token = Password::with_theme(theme)
        .with_prompt("Paste the API token")
        .interact()?;
    let client = veilweave_core::cfapi::CfClient::new(&token)?;
    println!("Verifying token…");
    client.verify_token().await?;

    let accounts = client.list_accounts().await?;
    if accounts.is_empty() {
        bail!("token is valid but sees no accounts — grant it account-level permissions");
    }
    let account = if accounts.len() == 1 {
        println!("Account: {}", accounts[0].name);
        &accounts[0]
    } else {
        let names: Vec<String> = accounts.iter().map(|a| a.name.clone()).collect();
        let sel = Select::with_theme(theme)
            .with_prompt("Which Cloudflare account?")
            .items(&names)
            .default(0)
            .interact()?;
        &accounts[sel]
    };

    println!("Resolving workers.dev subdomain…");
    let subdomain = client.get_workers_subdomain(&account.id).await?;

    let label: String = Input::with_theme(theme)
        .with_prompt("Local label for this account")
        .default(account.name.clone())
        .validate_with(|name: &String| {
            if cfg.account(name).is_some() {
                Err("an account with this label already exists")
            } else {
                Ok(())
            }
        })
        .interact_text()?;

    cfg.accounts.push(veilweave_core::config::Account {
        name: label.clone(),
        token,
        account_id: account.id.clone(),
        workers_dev_subdomain: Some(subdomain.clone()),
    });
    cfg.save()?;
    println!(
        "  ✔ saved account {label:?} ({}, workers.dev subdomain: {subdomain})",
        account.name
    );
    Ok(())
}

/// Prompt for a worker name with a random default; custom names are strongly
/// recommended since the name appears in the public workers.dev hostname.
fn worker_name_prompt(theme: &ColorfulTheme, prompt: &str) -> Result<String> {
    let name: String = Input::with_theme(theme)
        .with_prompt(format!(
            "{prompt} (random default; a custom innocuous name is STRONGLY recommended)"
        ))
        .default(veilweave_core::util::random_worker_name())
        .validate_with(|name: &String| validate_worker_name(name))
        .interact_text()?;
    Ok(name)
}

/// Cloudflare worker naming rules: lowercase letters, digits, dashes; must
/// start with a letter; ≤ 63 chars. Shared with the GUI deploy form.
pub fn validate_worker_name(name: &str) -> std::result::Result<(), &'static str> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok {
        Ok(())
    } else {
        Err("lowercase letters, digits and dashes only; must start with a letter; ≤ 63 chars")
    }
}

fn pick(theme: &ColorfulTheme, prompt: &str, items: &[String]) -> Result<String> {
    let sel = Select::with_theme(theme)
        .with_prompt(prompt)
        .items(items)
        .default(0)
        .interact()?;
    Ok(items[sel].clone())
}

/// Best-effort domain preview (subdomain is stored when the account is added).
fn preview_domain(cfg: &Config, account: &str, worker: &str) -> String {
    match cfg
        .account(account)
        .and_then(|a| a.workers_dev_subdomain.as_ref())
    {
        Some(sub) => format!("{worker}.{sub}.workers.dev"),
        None => format!("{worker}.<subdomain>.workers.dev"),
    }
}

/// Best-effort browser open; silently ignored on failure (the URL is printed
/// right above anyway).
fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    let cmd = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(target_os = "macos")]
    let cmd = ("open", vec![url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let cmd = ("xdg-open", vec![url]);
    let _ = std::process::Command::new(cmd.0).args(&cmd.1).spawn();
}
