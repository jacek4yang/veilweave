//! Singleton Durable Object for CPU-safe, serialized proxyIP refreshes.

use worker::*;

use crate::proxyip::SOURCE_URL;
use crate::{json_response, refresh_and_record, resolve_kv, unavailable, RefreshResult};

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
        if req.method() != Method::Post || req.path() != "/refresh" {
            return Response::error("not found", 404);
        }
        let Some(kv) = resolve_kv(&self.env) else {
            console_error!("event=proxyip_refresh status=failed code=KvBindingMissing");
            return unavailable("ProxyIP cache binding is unavailable.");
        };

        let response = match refresh_and_record(&kv).await {
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
                unavailable(error.public_message())
            }
        };

        // Carrier-specific entry IPs are an optional optimization and run in
        // the same scheduled compute context. Failure never changes the
        // authoritative proxyIP refresh result.
        if let Err(error) = crate::optimized_ip::refresh_optimized_ips(Some(&kv)).await {
            console_warn!("event=optimized_ip_refresh status=failed detail={error}");
        }
        response
    }
}
