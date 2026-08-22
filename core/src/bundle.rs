//! Canonical, validated Cloudflare Worker runtime bundles.
//!
//! `worker-build` emits both executable modules and build metadata.  Only the
//! modules named by this manifest are ever handed to the Cloudflare uploader.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const BUNDLE_FORMAT_VERSION: u32 = 1;
pub const MANIFEST_FILE: &str = "worker-manifest.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerRole {
    Relay,
    Sub,
}

impl WorkerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Sub => "sub",
        }
    }
}

impl std::str::FromStr for WorkerRole {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "relay" => Ok(Self::Relay),
            "sub" => Ok(Self::Sub),
            _ => bail!("unknown worker role {value:?}; expected relay or sub"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerModuleKind {
    EsModule,
    Wasm,
    Text,
    Data,
    SourceMap,
}

impl WorkerModuleKind {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::EsModule => "application/javascript+module",
            Self::Wasm => "application/wasm",
            Self::Text => "text/plain",
            Self::Data => "application/octet-stream",
            Self::SourceMap => "application/source-map",
        }
    }

    pub fn for_path(path: &str) -> Result<Self> {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".js") || lower.ends_with(".mjs") {
            Ok(Self::EsModule)
        } else if lower.ends_with(".wasm") {
            Ok(Self::Wasm)
        } else if lower.ends_with(".txt") {
            Ok(Self::Text)
        } else if lower.ends_with(".bin") {
            Ok(Self::Data)
        } else if lower.ends_with(".map") {
            Ok(Self::SourceMap)
        } else {
            bail!(
                "unsupported Worker runtime module {path:?}; supported extensions are .js, .mjs, .wasm, .txt, .bin, and .map"
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerBundleModuleManifest {
    pub path: String,
    pub kind: WorkerModuleKind,
    pub content_type: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerBundleManifest {
    pub format_version: u32,
    pub role: WorkerRole,
    pub main_module: String,
    pub modules: Vec<WorkerBundleModuleManifest>,
    pub bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerModule {
    pub path: String,
    pub kind: WorkerModuleKind,
    pub contents: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerBundle {
    manifest: WorkerBundleManifest,
    modules: Vec<WorkerModule>,
}

impl WorkerBundle {
    /// Convert the known `worker-build` output contract into a canonical
    /// runtime bundle. Build metadata such as package.json is inspected but
    /// intentionally never copied into the runtime module set.
    pub fn from_worker_build(build_dir: &Path, role: WorkerRole) -> Result<Self> {
        if !build_dir.is_dir() {
            bail!(
                "worker-build output does not exist: {}",
                build_dir.display()
            );
        }

        let required = ["index.js", "index_bg.wasm", "worker/shim.mjs"];
        let optional = ["index.js.map", "worker/shim.mjs.map"];
        let allowed_runtime = required
            .iter()
            .chain(optional.iter())
            .copied()
            .collect::<BTreeSet<_>>();
        let mut observed = Vec::new();
        collect_relative_files(build_dir, build_dir, &mut observed)?;
        for path in &observed {
            if allowed_runtime.contains(path.as_str()) || is_known_build_metadata(path) {
                continue;
            }
            bail!(
                "unrecognized file {path:?} in worker-build output; regenerate with the supported worker-build version or declare the runtime module explicitly"
            );
        }

        let mut entries = Vec::new();
        for path in required {
            let absolute = build_dir.join(path.replace('/', std::path::MAIN_SEPARATOR_STR));
            let contents = std::fs::read(&absolute)
                .with_context(|| format!("required Worker runtime module is missing: {path}"))?;
            entries.push((path.to_string(), contents));
        }
        for path in optional {
            let absolute = build_dir.join(path.replace('/', std::path::MAIN_SEPARATOR_STR));
            if absolute.is_file() {
                entries.push((path.to_string(), std::fs::read(&absolute)?));
            }
        }
        Self::from_entries(role, "index.js", entries)
    }

    /// Load the exact on-disk format shipped in release archives.
    pub fn from_directory(root: &Path, expected_role: WorkerRole) -> Result<Self> {
        let manifest_path = root.join(MANIFEST_FILE);
        let manifest_bytes = std::fs::read(&manifest_path)
            .with_context(|| format!("read bundle manifest {}", manifest_path.display()))?;
        let manifest: WorkerBundleManifest = serde_json::from_slice(&manifest_bytes)
            .with_context(|| format!("parse bundle manifest {}", manifest_path.display()))?;
        if manifest.role != expected_role {
            bail!(
                "bundle role mismatch: expected {}, manifest says {}",
                expected_role.as_str(),
                manifest.role.as_str()
            );
        }
        let mut entries = Vec::new();
        for module in &manifest.modules {
            let path = normalize_module_path(&module.path)?;
            entries.push((
                path.clone(),
                std::fs::read(root.join(path.replace('/', std::path::MAIN_SEPARATOR_STR)))
                    .with_context(|| format!("read bundle module {path:?}"))?,
            ));
        }
        reject_unmanifested_files(root, &manifest)?;
        Self::from_manifest_and_entries(manifest, entries)
    }

    /// Load a compile-time embedded bundle. The desktop adapter only embeds
    /// bytes; all validation remains here in core.
    pub fn from_embedded(
        manifest_json: &[u8],
        entries: Vec<(String, Vec<u8>)>,
        expected_role: WorkerRole,
    ) -> Result<Self> {
        let manifest: WorkerBundleManifest = serde_json::from_slice(manifest_json)
            .context("parse embedded Worker bundle manifest")?;
        if manifest.role != expected_role {
            bail!(
                "embedded bundle role mismatch: expected {}, manifest says {}",
                expected_role.as_str(),
                manifest.role.as_str()
            );
        }
        Self::from_manifest_and_entries(manifest, entries)
    }

    pub fn write_to(&self, root: &Path) -> Result<()> {
        if root.exists()
            && std::fs::read_dir(root)
                .with_context(|| format!("inspect bundle output directory {}", root.display()))?
                .next()
                .is_some()
        {
            bail!(
                "canonical bundle output {} is not empty; choose a fresh directory to prevent stale modules from shipping",
                root.display()
            );
        }
        std::fs::create_dir_all(root)
            .with_context(|| format!("create bundle directory {}", root.display()))?;
        for module in &self.modules {
            let destination = root.join(module.path.replace('/', std::path::MAIN_SEPARATOR_STR));
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&destination, &module.contents)
                .with_context(|| format!("write bundle module {}", destination.display()))?;
        }
        let manifest = serde_json::to_vec_pretty(&self.manifest)?;
        std::fs::write(root.join(MANIFEST_FILE), manifest)
            .with_context(|| format!("write {MANIFEST_FILE}"))?;
        Self::from_directory(root, self.role())
            .context("validate canonical bundle after writing")?;
        Ok(())
    }

    pub fn write_runtime_to(&self, root: &Path) -> Result<()> {
        for module in &self.modules {
            let destination = root.join(module.path.replace('/', std::path::MAIN_SEPARATOR_STR));
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&destination, &module.contents)
                .with_context(|| format!("write runtime module {}", destination.display()))?;
        }
        Ok(())
    }

    pub fn manifest(&self) -> &WorkerBundleManifest {
        &self.manifest
    }

    pub fn modules(&self) -> &[WorkerModule] {
        &self.modules
    }

    pub fn role(&self) -> WorkerRole {
        self.manifest.role
    }

    fn from_entries(
        role: WorkerRole,
        main_module: &str,
        entries: Vec<(String, Vec<u8>)>,
    ) -> Result<Self> {
        let main_module = normalize_module_path(main_module)?;
        let mut modules = Vec::new();
        let mut seen = BTreeSet::new();
        for (raw_path, contents) in entries {
            let path = normalize_module_path(&raw_path)?;
            if !seen.insert(path.clone()) {
                bail!("duplicate Worker module path {path:?}");
            }
            modules.push(WorkerModule {
                kind: WorkerModuleKind::for_path(&path)?,
                path,
                contents,
            });
        }
        modules.sort_by(|a, b| a.path.cmp(&b.path));
        validate_main_module(&main_module, &modules)?;
        let module_manifests = modules.iter().map(module_manifest).collect::<Vec<_>>();
        let bundle_sha256 = compute_bundle_hash(role, &main_module, &module_manifests);
        Ok(Self {
            manifest: WorkerBundleManifest {
                format_version: BUNDLE_FORMAT_VERSION,
                role,
                main_module,
                modules: module_manifests,
                bundle_sha256,
            },
            modules,
        })
    }

    fn from_manifest_and_entries(
        mut manifest: WorkerBundleManifest,
        entries: Vec<(String, Vec<u8>)>,
    ) -> Result<Self> {
        if manifest.format_version != BUNDLE_FORMAT_VERSION {
            bail!(
                "unsupported Worker bundle format {}; expected {}",
                manifest.format_version,
                BUNDLE_FORMAT_VERSION
            );
        }
        manifest.main_module = normalize_module_path(&manifest.main_module)?;
        let declared = manifest
            .modules
            .iter()
            .map(|m| Ok((normalize_module_path(&m.path)?, m)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        if declared.len() != manifest.modules.len() {
            bail!("duplicate module names in Worker bundle manifest");
        }
        let mut seen = BTreeSet::new();
        let mut modules = Vec::new();
        for (raw_path, contents) in entries {
            let path = normalize_module_path(&raw_path)?;
            if !seen.insert(path.clone()) {
                bail!("duplicate Worker module path {path:?}");
            }
            let expected = declared
                .get(&path)
                .ok_or_else(|| anyhow!("module {path:?} is not declared by the bundle manifest"))?;
            let kind = WorkerModuleKind::for_path(&path)?;
            if kind != expected.kind || expected.content_type != kind.content_type() {
                bail!("module {path:?} has inconsistent type metadata");
            }
            if expected.size != contents.len() as u64 {
                bail!("module {path:?} size does not match the bundle manifest");
            }
            let actual_hash = sha256_hex(&contents);
            if expected.sha256 != actual_hash {
                bail!("module {path:?} SHA-256 does not match the bundle manifest");
            }
            modules.push(WorkerModule {
                path,
                kind,
                contents,
            });
        }
        if seen.len() != declared.len() {
            let missing = declared
                .keys()
                .filter(|path| !seen.contains(*path))
                .cloned()
                .collect::<Vec<_>>();
            bail!(
                "bundle is missing declared module(s): {}",
                missing.join(", ")
            );
        }
        modules.sort_by(|a, b| a.path.cmp(&b.path));
        validate_main_module(&manifest.main_module, &modules)?;

        let normalized_manifests = modules.iter().map(module_manifest).collect::<Vec<_>>();
        let hash = compute_bundle_hash(manifest.role, &manifest.main_module, &normalized_manifests);
        if hash != manifest.bundle_sha256 {
            bail!("Worker bundle hash does not match the manifest");
        }
        manifest.modules = normalized_manifests;
        Ok(Self { manifest, modules })
    }
}

pub fn normalize_module_path(raw: &str) -> Result<String> {
    if raw.is_empty() || raw.starts_with('/') || raw.starts_with('\\') {
        bail!("Worker module path must be relative: {raw:?}");
    }
    let normalized = raw.replace('\\', "/");
    let mut parts = Vec::new();
    for part in normalized.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(':') {
            bail!("unsafe Worker module path {raw:?}");
        }
        parts.push(part);
    }
    Ok(parts.join("/"))
}

fn module_manifest(module: &WorkerModule) -> WorkerBundleModuleManifest {
    WorkerBundleModuleManifest {
        path: module.path.clone(),
        kind: module.kind,
        content_type: module.kind.content_type().to_string(),
        size: module.contents.len() as u64,
        sha256: sha256_hex(&module.contents),
    }
}

fn validate_main_module(main: &str, modules: &[WorkerModule]) -> Result<()> {
    let Some(module) = modules.iter().find(|module| module.path == main) else {
        bail!("main_module {main:?} is not present in the Worker bundle");
    };
    if module.kind != WorkerModuleKind::EsModule {
        bail!("main_module {main:?} must be an ES module");
    }
    Ok(())
}

fn compute_bundle_hash(
    role: WorkerRole,
    main_module: &str,
    modules: &[WorkerBundleModuleManifest],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!(
        "veilweave-worker-bundle-v{BUNDLE_FORMAT_VERSION}\0"
    ));
    hasher.update(role.as_str());
    hasher.update([0]);
    hasher.update(main_module);
    hasher.update([0]);
    for module in modules {
        hasher.update(&module.path);
        hasher.update([0]);
        hasher.update(format!("{:?}", module.kind));
        hasher.update([0]);
        hasher.update(module.size.to_le_bytes());
        hasher.update([0]);
        hasher.update(&module.sha256);
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_known_build_metadata(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name == "package.json"
        || name == "Cargo.toml"
        || name == "Cargo.lock"
        || name.eq_ignore_ascii_case("README")
        || name.to_ascii_lowercase().starts_with("readme.")
        || name.ends_with(".lock")
        || name.ends_with(".tmp")
        || name.starts_with('.')
}

fn collect_relative_files(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_relative_files(root, &path, out)?;
        } else {
            let relative = path.strip_prefix(root).expect("path is below root");
            out.push(normalize_module_path(&relative.to_string_lossy())?);
        }
    }
    out.sort();
    Ok(())
}

fn reject_unmanifested_files(root: &Path, manifest: &WorkerBundleManifest) -> Result<()> {
    let declared = manifest
        .modules
        .iter()
        .map(|module| normalize_module_path(&module.path))
        .collect::<Result<BTreeSet<_>>>()?;
    let mut observed = Vec::new();
    collect_relative_files(root, root, &mut observed)?;
    for path in observed {
        if path != MANIFEST_FILE && !declared.contains(&path) {
            bail!("unmanifested file {path:?} in canonical Worker bundle");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<(String, Vec<u8>)> {
        vec![
            ("index.js".into(), b"export default {};".to_vec()),
            ("index_bg.wasm".into(), b"\0asm".to_vec()),
            ("worker/shim.mjs".into(), b"export {};".to_vec()),
        ]
    }

    #[test]
    fn module_mime_types_are_explicit() {
        assert_eq!(
            WorkerModuleKind::for_path("index.js")
                .unwrap()
                .content_type(),
            "application/javascript+module"
        );
        assert_eq!(
            WorkerModuleKind::for_path("index_bg.wasm")
                .unwrap()
                .content_type(),
            "application/wasm"
        );
        assert_eq!(
            WorkerModuleKind::for_path("worker/shim.mjs")
                .unwrap()
                .content_type(),
            "application/javascript+module"
        );
        assert!(WorkerModuleKind::for_path("package.json").is_err());
    }

    #[test]
    fn paths_are_normalized_without_escaping() {
        assert_eq!(
            normalize_module_path("worker\\shim.mjs").unwrap(),
            "worker/shim.mjs"
        );
        for path in ["../x.js", "worker/../x.js", "/x.js", "C:\\x.js", "./x.js"] {
            assert!(normalize_module_path(path).is_err(), "accepted {path:?}");
        }
    }

    #[test]
    fn duplicate_and_missing_main_modules_are_rejected() {
        let mut duplicate = entries();
        duplicate.push(("worker\\shim.mjs".into(), vec![]));
        assert!(WorkerBundle::from_entries(WorkerRole::Relay, "index.js", duplicate).is_err());
        assert!(WorkerBundle::from_entries(WorkerRole::Relay, "missing.js", entries()).is_err());
    }

    #[test]
    fn bundle_hash_is_deterministic() {
        let first = WorkerBundle::from_entries(WorkerRole::Relay, "index.js", entries()).unwrap();
        let mut reversed = entries();
        reversed.reverse();
        let second = WorkerBundle::from_entries(WorkerRole::Relay, "index.js", reversed).unwrap();
        assert_eq!(first.manifest.bundle_sha256, second.manifest.bundle_sha256);
    }

    #[test]
    fn manifest_rejects_unknown_runtime_files_and_tampering() {
        let bundle = WorkerBundle::from_entries(WorkerRole::Sub, "index.js", entries()).unwrap();
        let manifest = serde_json::to_vec(bundle.manifest()).unwrap();
        let mut with_unknown = entries();
        with_unknown.push(("package.json".into(), b"{}".to_vec()));
        assert!(WorkerBundle::from_embedded(&manifest, with_unknown, WorkerRole::Sub).is_err());

        let mut tampered = entries();
        tampered[0].1.push(1);
        assert!(WorkerBundle::from_embedded(&manifest, tampered, WorkerRole::Sub).is_err());
    }

    #[test]
    fn worker_build_package_json_is_excluded() {
        let root = std::env::temp_dir().join(format!("vw-bundle-test-{}", std::process::id()));
        std::fs::create_dir_all(root.join("worker")).unwrap();
        for (path, bytes) in entries() {
            let destination = root.join(path.replace('/', std::path::MAIN_SEPARATOR_STR));
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(destination, bytes).unwrap();
        }
        std::fs::write(root.join("package.json"), "{}").unwrap();
        let bundle = WorkerBundle::from_worker_build(&root, WorkerRole::Relay).unwrap();
        assert!(!bundle.modules().iter().any(|m| m.path == "package.json"));
        assert!(bundle
            .modules()
            .iter()
            .all(|m| m.kind.content_type() != "application/json"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_writer_refuses_a_stale_output_directory() {
        let root =
            std::env::temp_dir().join(format!("vw-canonical-output-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("package.json"), "{}").unwrap();
        let bundle = WorkerBundle::from_entries(WorkerRole::Relay, "index.js", entries()).unwrap();
        let error = bundle.write_to(&root).unwrap_err().to_string();
        assert!(error.contains("not empty"));
        assert!(root.join("package.json").is_file());
        std::fs::remove_dir_all(root).unwrap();
    }
}
