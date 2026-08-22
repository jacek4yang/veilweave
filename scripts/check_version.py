#!/usr/bin/env python3
"""Fail CI when a shipped Veilweave component drifts from VERSION."""

from pathlib import Path
import json
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def cargo_version(path: Path) -> str:
    match = re.search(r'^version\s*=\s*"([^"]+)"', path.read_text(encoding="utf-8"), re.M)
    if not match:
        raise ValueError(f"missing package version in {path}")
    return match.group(1)


actual = {
    "core/Cargo.toml": cargo_version(ROOT / "core/Cargo.toml"),
    "tools/Cargo.toml": cargo_version(ROOT / "tools/Cargo.toml"),
    "relay/Cargo.toml": cargo_version(ROOT / "relay/Cargo.toml"),
    "sub/Cargo.toml": cargo_version(ROOT / "sub/Cargo.toml"),
    "app/src-tauri/Cargo.toml": cargo_version(ROOT / "app/src-tauri/Cargo.toml"),
    "app/package.json": json.loads((ROOT / "app/package.json").read_text(encoding="utf-8"))["version"],
    "app/package-lock.json": json.loads((ROOT / "app/package-lock.json").read_text(encoding="utf-8"))["version"],
    "app/src-tauri/tauri.conf.json": json.loads((ROOT / "app/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))["version"],
}

lock_packages = {
    "core/Cargo.lock": {"veilweave-core"},
    "tools/Cargo.lock": {"veilweave-core", "veilweave-tools"},
    "relay/Cargo.lock": {"veilweave"},
    "sub/Cargo.lock": {"veilweave-sub"},
    "app/src-tauri/Cargo.lock": {"veilweave-app", "veilweave-core"},
}
for relative, names in lock_packages.items():
    packages = tomllib.loads((ROOT / relative).read_text(encoding="utf-8"))["package"]
    versions = {package["name"]: package["version"] for package in packages if package["name"] in names}
    for name in names:
        actual[f"{relative}:{name}"] = versions.get(name, "<missing>")

package_lock = json.loads((ROOT / "app/package-lock.json").read_text(encoding="utf-8"))
actual['app/package-lock.json:packages[""]'] = package_lock["packages"][""]["version"]

errors = [f"{path}: {value} != {VERSION}" for path, value in actual.items() if value != VERSION]
changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
if f"## [{VERSION}]" not in changelog:
    errors.append(f"CHANGELOG.md has no [{VERSION}] release heading")

compatibility = re.search(
    r'COMPATIBILITY_DATE: &str = "([^"]+)"',
    (ROOT / "core/src/cfapi.rs").read_text(encoding="utf-8"),
).group(1)
for relative in [
    "relay/wrangler.toml",
    "relay/wrangler.example.toml",
    "sub/wrangler.toml",
    "sub/wrangler.example.toml",
]:
    value = re.search(
        r'compatibility_date\s*=\s*"([^"]+)"',
        (ROOT / relative).read_text(encoding="utf-8"),
    ).group(1)
    if value != compatibility:
        errors.append(f"{relative}: compatibility_date {value} != {compatibility}")

if errors:
    print("version consistency check failed:", file=sys.stderr)
    print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
    raise SystemExit(1)
print(f"all shipped components are version {VERSION}; compatibility date {compatibility}")
