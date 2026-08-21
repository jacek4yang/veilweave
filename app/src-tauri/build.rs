//! Compile-time sanity check for the embedded worker bundles. The app embeds
//! prebuilt relay/sub workers via `include_bytes!`; if they're missing the
//! binary would compile but be useless, so fail here with a clear message.

use std::path::Path;

fn main() -> anyhow::Result<()> {
    // Embeds the Windows manifest (common-controls v6 + PerMonitorV2 DPI
    // awareness) — without comctl32 v6 the app fails to launch with
    // STATUS_ENTRYPOINT_NOT_FOUND, and without DPI awareness the WebView2
    // content renders scaled-up against a physically-sized window.
    let attrs = tauri_build::Attributes::new().windows_attributes(
        tauri_build::WindowsAttributes::new().app_manifest(include_str!("window-manifest.xml")),
    );
    tauri_build::try_build(attrs).expect("tauri-build codegen");

    println!("cargo:rerun-if-changed=bundle");
    for unit in ["relay", "sub"] {
        for file in ["index.js", "index_bg.wasm", "worker/shim.mjs"] {
            let p = Path::new("bundle").join(unit).join("build").join(file);
            if !p.is_file() {
                anyhow::bail!(
                    "embedded bundle missing {} — copy prebuilt workers first:\n  \
                     cp -r ../{unit}/build app/src-tauri/bundle/{unit}/build\n  \
                     (see bundle/README.md)",
                    p.display()
                );
            }
        }
    }
    Ok(())
}
