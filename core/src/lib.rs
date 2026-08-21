//! veilweave deploy core — UI-agnostic library shared by the `veilweave-tools`
//! CLI and the Tauri app.
//!
//! - [`cfapi`]: async Cloudflare API v4 client (workers, KV, usage GraphQL)
//! - [`config`]: persistent local config (accounts + deployments)
//! - [`deploy`]: deploy orchestration (`DeployPlan` → `execute` → `DeployOutcome`)
//! - [`recover`]: rebuild config records from what exists on an account
//! - [`util`]: secret generation, VW1 blob codec, randomizers, nonce injection

pub mod cfapi;
pub mod config;
pub mod deploy;
pub mod recover;
pub mod util;
