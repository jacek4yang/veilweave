//! Singleton Durable Object for CPU-safe, serialized proxyIP refreshes.

use worker::*;

use crate::proxyip::SOURCE_URL;
use crate::{
    json_response, refresh_and_record, refresh_failure, resolve_kv, unavailable, RefreshResult,
};

#[durable_object]
pub struct ProxyIpRefresher {
    _state: State,
    env: Env,
}

impl DurableObject for ProxyIpRefresher {
    fn new(state: State, env: Env) -> Self {
        Self { _state: state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("not found", 404);
        }
        let Some(kv) = resolve_kv(&self.env) else {
            console_error!("event=proxyip_refresh status=failed code=KvBindingMissing");
            return unavailable("ProxyIP cache binding is unavailable.");
        };

        match req.path().as_str() {
            "/refresh" => refresh_authoritative(&kv).await,
            "/optimized" => refresh_optional_entry_ips(&kv).await,
            _ => Response::error("not found", 404),
        }
    }
}

async fn refresh_authoritative(kv: &KvStore) -> Result<Response> {
    match refresh_and_record(kv).await {
        Ok(dataset) => {
            console_log!(
                "event=proxyip_refresh status=ok revision={} accepted={} rejected={} stored={}",
                dataset.revision,
                dataset.accepted_count,
                dataset.rejected_count,
                dataset.stored_count
            );
            json_response(
                &RefreshResult {
                    source: SOURCE_URL,
                    revision: &dataset.revision,
                    accepted_count: dataset.accepted_count,
                    rejected_count: dataset.rejected_count,
                    stored_count: dataset.stored_count,
                    country_count: dataset.countries.len(),
                },
                200,
            )
        }
        Err(error) => {
            console_error!(
                "event=proxyip_refresh status=failed code={} detail={}",
                error.code.as_str(),
                error.detail
            );
            // This route is reachable externally only through the
            // bearer-authenticated management endpoint. Returning the
            // bounded structured diagnostic avoids racing KV propagation
            // when a fresh deployment needs to explain bootstrap failure.
            json_response(&refresh_failure(&error), 503)
        }
    }
}

async fn refresh_optional_entry_ips(kv: &KvStore) -> Result<Response> {
    match crate::optimized_ip::refresh_optimized_ips(Some(kv)).await {
        Ok(ips) => {
            console_log!(
                "event=optimized_ip_refresh status=ok ct={} cu={} cmcc={}",
                ips.ct.len(),
                ips.cu.len(),
                ips.cmcc.len()
            );
            json_response(&ips, 200)
        }
        Err(error) => {
            console_warn!("event=optimized_ip_refresh status=failed detail={error}");
            unavailable("Optional optimized entry IP refresh failed.")
        }
    }
}
