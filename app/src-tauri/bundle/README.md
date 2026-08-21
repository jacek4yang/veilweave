# Prebuilt worker bundles (release artifacts)

The Tauri app embeds these files into the binary at compile time
(`include_bytes!` in `src/bundle.rs`), so every deploy/update operation can
run fully offline from the installed app.

Contents are refreshed by CI from `relay/build/` and `sub/build/` (produced by
`worker-build --release` in each worker crate). For local development, copy
them manually:

    cp -r ../relay/build app/src-tauri/bundle/relay/build
    cp -r ../sub/build   app/src-tauri/bundle/sub/build

`build.rs` fails with a clear error if either unit is missing. This directory
is git-ignored — the bytes are build outputs, not source.
