//! Secret generation, VW1 blob codec, randomizers, and the per-run nonce —
//! shared by the deploy orchestration and the CLI/Tauri front-ends.

use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;

/// Random raw shared secret for plaintext mode: 32 bytes, base64url (no pad).
/// Used as the relay's SECRET_KEY and in the sub's VEILWEAVE_NODES verbatim.
pub fn gen_raw_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// EXPERIMENTAL encryption mode: a matched blob pair — (relay blob with the
/// X25519 private key, sub blob with the public key), sharing one UUID secret.
pub fn gen_secret_pair() -> (String, String) {
    use x25519_dalek::{PublicKey, StaticSecret};
    let mut uuid_secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut uuid_secret);
    let x = StaticSecret::random_from_rng(rand::thread_rng());
    let relay = encode_blob(0, &uuid_secret, &x.to_bytes());
    let sub = encode_blob(1, &uuid_secret, &PublicKey::from(&x).to_bytes());
    (relay, sub)
}

// ─── Combined secret blob (must match veilweave/src/secret.rs) ───────────────
// Layout (base64url, no pad): "VW1" ‖ kind(1) ‖ uuid_secret(32) ‖ x25519(32)
//   kind 0 = relay (x25519 private),  kind 1 = sub (x25519 public)

pub fn encode_blob(kind: u8, uuid_secret: &[u8; 32], key: &[u8; 32]) -> String {
    let mut b = Vec::with_capacity(68);
    b.extend_from_slice(b"VW1");
    b.push(kind);
    b.extend_from_slice(uuid_secret);
    b.extend_from_slice(key);
    general_purpose::URL_SAFE_NO_PAD.encode(&b)
}

pub fn decode_blob(s: &str) -> Option<(u8, [u8; 32], [u8; 32])> {
    let b = general_purpose::URL_SAFE_NO_PAD.decode(s.trim()).ok()?;
    if b.len() != 68 || &b[0..3] != b"VW1" {
        return None;
    }
    let mut uuid = [0u8; 32];
    uuid.copy_from_slice(&b[4..36]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&b[36..68]);
    Some((b[3], uuid, key))
}

/// Prepend a per-run nonce comment so every user's artifact has a unique
/// content hash. Shared by `bundle` and the direct-deploy path.
pub fn inject_nonce(js: &str) -> String {
    format!("/* vw:{} */\n{js}", generate_hex_id(64))
}

/// Random, innocuous worker name — a new one every run.
pub fn random_worker_name() -> String {
    use rand::Rng;
    const WORDS: &[&str] = &[
        "edge", "api", "cdn", "cache", "media", "data", "sync", "hub", "core", "node", "link",
        "stream", "relay", "proxy", "gate", "mesh", "orbit",
    ];
    const KINDS: &[&str] = &[
        "service", "worker", "backend", "endpoint", "gateway", "bridge", "feed",
    ];
    let mut rng = rand::thread_rng();
    format!(
        "{}-{}-{}",
        WORDS[rng.gen_range(0..WORDS.len())],
        KINDS[rng.gen_range(0..KINDS.len())],
        generate_hex_id(4)
    )
}

/// Random KV binding name, e.g. `kv_x7f2a9` — always a valid JS identifier.
/// The sub worker resolves its KV namespace via the `KV_BINDING` var, so the
/// binding name itself can (and should) vary per deployment.
pub fn random_kv_binding() -> String {
    format!("kv_{}", generate_hex_id(6))
}

pub fn generate_hex_id(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    const HEX: &[u8] = b"0123456789abcdef";
    (0..len)
        .map(|_| HEX[rng.gen_range(0..HEX.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_round_trip_and_kinds() {
        let uuid = [7u8; 32];
        let key = [9u8; 32];
        for kind in [0u8, 1] {
            let blob = encode_blob(kind, &uuid, &key);
            let (k, u, x) = decode_blob(&blob).expect("decodes");
            assert_eq!(k, kind);
            assert_eq!(u, uuid);
            assert_eq!(x, key);
        }
        assert!(decode_blob("not-a-blob").is_none());
    }

    #[test]
    fn raw_secret_is_not_a_blob() {
        // A raw plaintext secret must never parse as a VW1 blob (the relay
        // distinguishes the two by exact length + magic).
        let raw = gen_raw_secret();
        assert!(decode_blob(&raw).is_none());
        assert_eq!(raw.len(), 43); // 32 bytes base64url-no-pad
    }

    #[test]
    fn randomizers_shape() {
        let name = random_worker_name();
        assert!(name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        let binding = random_kv_binding();
        assert!(binding.starts_with("kv_"));
        assert!(binding
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'));
        assert!(inject_nonce("x").starts_with("/* vw:"));
    }
}
