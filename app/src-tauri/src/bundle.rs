//! Prebuilt relay/sub workers embedded into the binary. The bytes are git-
//! ignored build outputs (see `bundle/README.md`); CI refreshes them and
//! `build.rs` fails the compile with a clear message when they're missing.

use veilweave_core::cfapi::{self, UploadFile};
use veilweave_core::deploy::EmbeddedBundle;
use veilweave_core::util;

macro_rules! embed_unit {
    ($unit:literal) => {
        vec![
            (
                "index.js".to_string(),
                include_bytes!(concat!("../bundle/", $unit, "/build/index.js")).to_vec(),
            ),
            (
                "index_bg.wasm".to_string(),
                include_bytes!(concat!("../bundle/", $unit, "/build/index_bg.wasm")).to_vec(),
            ),
            (
                "package.json".to_string(),
                include_bytes!(concat!("../bundle/", $unit, "/build/package.json")).to_vec(),
            ),
            (
                "worker/shim.mjs".to_string(),
                include_bytes!(concat!("../bundle/", $unit, "/build/worker/shim.mjs")).to_vec(),
            ),
        ]
    };
}

pub fn embedded_bundle() -> EmbeddedBundle {
    EmbeddedBundle {
        relay: embed_unit!("relay"),
        sub: embed_unit!("sub"),
    }
}

/// Upload-ready files for one unit ("relay"/"sub") with the per-run nonce
/// injected into `index.js` — mirrors `BundleSource::files` (which is private
/// to core) so `update_deployment` can rebuild uploads without a `DeployPlan`.
pub fn upload_files(unit: &str) -> anyhow::Result<Vec<UploadFile>> {
    let bundle = embedded_bundle();
    let entries = if unit == "relay" {
        &bundle.relay
    } else {
        &bundle.sub
    };
    let mut files: Vec<UploadFile> = entries
        .iter()
        .map(|(name, bytes)| UploadFile {
            name: name.clone(),
            contents: bytes.clone(),
            content_type: cfapi::content_type_for(name),
        })
        .collect();
    for f in &mut files {
        if f.name == "index.js" {
            let js = String::from_utf8(std::mem::take(&mut f.contents))
                .map_err(|_| anyhow::anyhow!("{unit}/index.js is not valid UTF-8"))?;
            f.contents = util::inject_nonce(&js).into_bytes();
        }
    }
    Ok(files)
}
