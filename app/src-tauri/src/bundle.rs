//! Prebuilt relay/sub workers embedded into the binary. The bytes are git-
//! ignored build outputs (see `bundle/README.md`); CI refreshes them and
//! `build.rs` fails the compile with a clear message when they're missing.

use veilweave_core::deploy::{EmbeddedBundle, EmbeddedWorkerBundle};

macro_rules! embed_unit {
    ($unit:literal) => {
        EmbeddedWorkerBundle {
            manifest_json: include_bytes!(concat!("../bundle/", $unit, "/worker-manifest.json"))
                .to_vec(),
            modules: vec![
                (
                    "index.js".to_string(),
                    include_bytes!(concat!("../bundle/", $unit, "/index.js")).to_vec(),
                ),
                (
                    "index_bg.wasm".to_string(),
                    include_bytes!(concat!("../bundle/", $unit, "/index_bg.wasm")).to_vec(),
                ),
                (
                    "worker/shim.mjs".to_string(),
                    include_bytes!(concat!("../bundle/", $unit, "/worker/shim.mjs")).to_vec(),
                ),
            ],
        }
    };
}

pub fn embedded_bundle() -> EmbeddedBundle {
    EmbeddedBundle {
        relay: embed_unit!("relay"),
        sub: embed_unit!("sub"),
    }
}
