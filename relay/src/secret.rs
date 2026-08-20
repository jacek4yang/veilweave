// Shared verbatim by veilweave and veilweave-sub; each uses only one accessor.
#![allow(dead_code)]

// secret.rs
// One opaque string carries everything a worker needs: the UUID-signing secret
// AND (optionally) the VLESS Encryption X25519 key. `veilweave-tools gen-secret`
// emits a matched pair — a relay blob (private key) and a sub blob (public key) —
// sharing the same UUID secret, so the existing single-value fill stays unchanged
// (`SECRET_KEY` on the relay, `domain|<blob>` in `VEILWEAVE_NODES` on the sub).
//
// Blob layout (base64url, no pad): "VW1" ‖ kind(1) ‖ uuid_secret(32) ‖ x25519(32)
//   kind 0 = relay (x25519 private),  kind 1 = sub (x25519 public)
//
// Anything that is not a valid blob is treated as a legacy raw secret: its bytes
// seed the UUID codec and encryption stays off — so old configs keep working.
//
// `kind` is exposed so each side only ever uses the key for its intended role: the
// relay treats a kind-0 key as its private key; the sub treats a kind-1 key as the
// public key it publishes — a guard against a private key ever leaking into a link.

use base64::{engine::general_purpose, Engine as _};

pub const KIND_RELAY: u8 = 0;
pub const KIND_SUB: u8 = 1;
const BLOB_MAGIC: &[u8; 3] = b"VW1";
const BLOB_LEN: usize = 3 + 1 + 32 + 32; // 68

pub struct Secret {
    /// Key material to seed the UUID codec (32 blob bytes, or raw legacy bytes).
    pub uuid_key: Vec<u8>,
    /// `kind` byte from the blob (`None` for legacy secrets).
    pub kind: Option<u8>,
    /// X25519 key from the blob (`None` for legacy secrets).
    pub key: Option<[u8; 32]>,
}

impl Secret {
    /// The relay's X25519 private key, iff this is a relay blob.
    pub fn relay_private(&self) -> Option<[u8; 32]> {
        match (self.kind, self.key) {
            (Some(KIND_RELAY), Some(k)) => Some(k),
            _ => None,
        }
    }

    /// The sub's published X25519 public key, iff this is a sub blob.
    pub fn sub_public(&self) -> Option<[u8; 32]> {
        match (self.kind, self.key) {
            (Some(KIND_SUB), Some(k)) => Some(k),
            _ => None,
        }
    }
}

/// Parse a configured secret string into its UUID + encryption parts.
pub fn parse(s: &str) -> Secret {
    if let Some((kind, uuid, key)) = decode_blob(s) {
        Secret { uuid_key: uuid.to_vec(), kind: Some(kind), key: Some(key) }
    } else {
        Secret { uuid_key: s.as_bytes().to_vec(), kind: None, key: None }
    }
}

fn decode_blob(s: &str) -> Option<(u8, [u8; 32], [u8; 32])> {
    let b = general_purpose::URL_SAFE_NO_PAD.decode(s.trim()).ok()?;
    if b.len() != BLOB_LEN || &b[0..3] != BLOB_MAGIC {
        return None;
    }
    let kind = b[3];
    let mut uuid = [0u8; 32];
    uuid.copy_from_slice(&b[4..36]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&b[36..68]);
    Some((kind, uuid, key))
}
