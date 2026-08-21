//! Account recovery: rebuild `Deployment` config records from what actually
//! exists on a Cloudflare account. Works because the script settings endpoint
//! exposes `plain_text` binding values — SECRET_KEY, VEILWEAVE_NODES,
//! SUBSCRIPTION_TOKEN, KV_BINDING are all recoverable (secret_text values
//! would NOT be; the deployer never uses them).

use crate::cfapi::{BindingInfo, CfClient};
use crate::config::{Deployment, Role, SubDetails};
use anyhow::Result;

/// What was recovered from one account.
pub struct RecoverOutcome {
    pub deployments: Vec<Deployment>,
    /// Human-readable per-worker notes (e.g. unreadable secrets, skipped
    /// non-veilweave workers are omitted entirely).
    pub summary: Vec<String>,
}

/// List every worker on the account, fetch its settings, and classify
/// veilweave relays (Durable Object binding `VEILWEAVE_SESSION` /
/// class `VeilweaveSession`, or a SECRET_KEY var) and subs (VEILWEAVE_NODES
/// var) into Deployment records. Domains are assumed to be
/// `<name>.<subdomain>.workers.dev` (workers.dev enabled — every worker this
/// tool deploys has it on).
pub async fn recover_account(
    client: &CfClient,
    account_id: &str,
    account_name: &str,
    subdomain: &str,
) -> Result<RecoverOutcome> {
    let workers = client.list_workers(account_id).await?;
    let mut deployments = Vec::new();
    let mut summary = Vec::new();
    for w in workers {
        let bindings = client.get_script_settings(account_id, &w.id).await?;
        if let Some(dep) = classify_worker(
            &w.id,
            w.created_on.as_deref(),
            account_name,
            subdomain,
            &bindings,
            &mut summary,
        ) {
            deployments.push(dep);
        }
    }
    Ok(RecoverOutcome {
        deployments,
        summary,
    })
}

/// Pure classification of one worker from its settings bindings; pushes notes
/// into `summary`. Returns None for workers that aren't veilweave deployments.
fn classify_worker(
    name: &str,
    created_on: Option<&str>,
    account_name: &str,
    subdomain: &str,
    bindings: &[BindingInfo],
    summary: &mut Vec<String>,
) -> Option<Deployment> {
    let var = |var_name: &str| {
        bindings
            .iter()
            .find(|b| b.kind == "plain_text" && b.name == var_name)
            .and_then(|b| b.text.clone())
    };
    let domain = format!("{name}.{subdomain}.workers.dev");
    let created_at = created_on
        .map(str::to_string)
        .unwrap_or_else(crate::config::now_utc_string);

    let is_relay = bindings.iter().any(|b| {
        b.kind == "durable_object_namespace" && b.class_name.as_deref() == Some("VeilweaveSession")
    }) || var("SECRET_KEY").is_some()
        || bindings
            .iter()
            .any(|b| b.kind == "secret_text" && b.name == "SECRET_KEY");
    if is_relay {
        let secret = match var("SECRET_KEY") {
            Some(s) => s,
            None => {
                summary.push(format!(
                    "relay {name:?}: SECRET_KEY is a secret_text — value not recoverable via API"
                ));
                String::new()
            }
        };
        summary.push(format!("relay {name:?} → https://{domain}"));
        return Some(Deployment {
            role: Role::Relay,
            name: name.to_string(),
            account: account_name.to_string(),
            domain,
            secret,
            created_at,
            sub: None,
        });
    }

    if let Some(nodes) = var("VEILWEAVE_NODES") {
        let kv = bindings.iter().find(|b| b.kind == "kv_namespace");
        let token = match var("SUBSCRIPTION_TOKEN") {
            Some(t) => t,
            None => {
                summary.push(format!(
                    "sub {name:?}: SUBSCRIPTION_TOKEN not readable — subscription URL incomplete"
                ));
                String::new()
            }
        };
        summary.push(format!("sub {name:?} → https://{domain}"));
        return Some(Deployment {
            role: Role::Sub,
            name: name.to_string(),
            account: account_name.to_string(),
            domain,
            secret: nodes,
            created_at,
            sub: Some(SubDetails {
                kv_namespace_id: kv.and_then(|b| b.namespace_id.clone()).unwrap_or_default(),
                // The KV title isn't visible in bindings; the binding name is
                // the useful handle here.
                kv_title: String::new(),
                kv_binding: var("KV_BINDING")
                    .or_else(|| kv.map(|b| b.name.clone()))
                    .unwrap_or_default(),
                subscription_token: token,
            }),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(name: &str, text: &str) -> BindingInfo {
        BindingInfo {
            name: name.into(),
            kind: "plain_text".into(),
            text: Some(text.into()),
            ..Default::default()
        }
    }

    #[test]
    fn classifies_relay_with_do_binding() {
        let bindings = vec![
            var("SECRET_KEY", "raw-secret"),
            BindingInfo {
                name: "VEILWEAVE_SESSION".into(),
                kind: "durable_object_namespace".into(),
                class_name: Some("VeilweaveSession".into()),
                ..Default::default()
            },
        ];
        let mut summary = Vec::new();
        let dep = classify_worker(
            "edge-worker-a1b2",
            Some("2026-08-20T12:00:00.000Z"),
            "personal",
            "alice",
            &bindings,
            &mut summary,
        )
        .expect("relay");
        assert_eq!(dep.role, Role::Relay);
        assert_eq!(dep.secret, "raw-secret");
        assert_eq!(dep.domain, "edge-worker-a1b2.alice.workers.dev");
        assert_eq!(dep.created_at, "2026-08-20T12:00:00.000Z");
        assert!(dep.sub.is_none());
    }

    #[test]
    fn classifies_sub_with_kv_and_token() {
        let bindings = vec![
            var("KV_BINDING", "kv_x7f2a9"),
            var("VEILWEAVE_NODES", "a.dev|s1,b.dev|s2"),
            var("SUBSCRIPTION_TOKEN", "tok123"),
            BindingInfo {
                name: "kv_x7f2a9".into(),
                kind: "kv_namespace".into(),
                namespace_id: Some("ns-id-9".into()),
                ..Default::default()
            },
        ];
        let mut summary = Vec::new();
        let dep = classify_worker(
            "hub-svc",
            None,
            "personal",
            "alice",
            &bindings,
            &mut summary,
        )
        .expect("sub");
        assert_eq!(dep.role, Role::Sub);
        assert_eq!(dep.secret, "a.dev|s1,b.dev|s2");
        assert_eq!(
            dep.subscription_url().unwrap(),
            "https://hub-svc.alice.workers.dev/sub?token=tok123"
        );
        let sub = dep.sub.unwrap();
        assert_eq!(sub.kv_namespace_id, "ns-id-9");
        assert_eq!(sub.kv_binding, "kv_x7f2a9");
        assert_eq!(sub.subscription_token, "tok123");
    }

    #[test]
    fn skips_unrelated_and_warns_on_secret_text() {
        let mut summary = Vec::new();
        assert!(classify_worker(
            "random-app",
            None,
            "a",
            "s",
            &[var("FOO", "bar")],
            &mut summary
        )
        .is_none());

        // Relay whose SECRET_KEY was stored via `wrangler secret put`.
        let bindings = vec![BindingInfo {
            name: "SECRET_KEY".into(),
            kind: "secret_text".into(),
            ..Default::default()
        }];
        let dep = classify_worker("r2", None, "a", "s", &bindings, &mut summary).expect("relay");
        assert_eq!(dep.role, Role::Relay);
        assert!(dep.secret.is_empty());
        assert!(summary.iter().any(|l| l.contains("not recoverable")));
    }
}
