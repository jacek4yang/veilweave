use worker::*;

use crate::log::vlog;

mod apache_mock;
mod codec;
mod conn;
mod datapath;
mod egress;
mod enc;
mod hmac;
mod log;
mod rng;
mod secret;
mod session;
mod sha256;
mod vless;
mod webcrypto;
mod wsio;

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let upgrade = req.headers().get("Upgrade").ok().flatten();
    if upgrade.as_deref() == Some("websocket") {
        vlog!("fetch: ws upgrade → routing to VeilweaveSession DO");
        // Two modes, selected by `SECRET_KEY`: a raw secret string serves
        // plaintext VLESS — the default and recommended mode under the Workers
        // free CPU limits; a "VW1" blob opts into VLESS Encryption
        // (post-quantum, forward-secret, end-to-end through Cloudflare's WSS) —
        // experimental and CPU-heavy on the free plan. Either way the whole WS
        // is handed to a per-connection `VeilweaveSession` Durable Object so
        // each inbound frame runs as its own hibernatable invocation with its
        // own CPU budget — the free-plan-friendly way to absorb the ML-KEM
        // handshake and bulk crypto. The DO performs the upgrade and returns
        // the 101 itself.
        let ns = env.durable_object("VEILWEAVE_SESSION")?;
        let stub = ns.unique_id()?.get_stub()?;
        return stub.fetch_with_request(req).await;
    }

    // Anything that is not a WebSocket upgrade gets the Apache camouflage page.
    apache_mock::apache_default_page(req)
}
