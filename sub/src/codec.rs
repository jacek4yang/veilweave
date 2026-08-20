// UUID encoder — the inverse of veilweave/src/codec.rs `decode`. Produces a signed
// 16-byte UUID that bakes the egress (type + IPv4 + port) and is authenticated by a
// SECRET_KEY-derived MAC. The relay validates and decodes it with the same key.
//
// Layout (matches veilweave-tools exactly):
//   bytes[0..4]   nonce
//   bytes[4..11]  ciphertext = plaintext XOR keystream[0..7]
//                   plaintext[0]   = type_byte (0=direct,1=proxyip,2=socks5,3=http)
//                   plaintext[1..5]= IPv4 octets
//                   plaintext[5..7]= port (big-endian)
//   bytes[11..16] mac[0..5]
//
// Keys: HKDF over the SECRET_KEY *string bytes* (the relay uses `secret.as_bytes()`).
// keystream = HMAC(k_enc, nonce || 0x00); mac = HMAC(k_mac, nonce || ciphertext)
// with empty context (the relay decodes with empty context).

use crate::hmac::{hkdf_expand, hkdf_extract, hmac_sha256};

const MAC_LEN: usize = 5;
const NONCE_LEN: usize = 4;
const PLAINTEXT_LEN: usize = 7;
const MAC_INPUT_LEN: usize = NONCE_LEN + PLAINTEXT_LEN;

pub const TYPE_DIRECT: u8 = 0x00;
pub const TYPE_PROXYIP: u8 = 0x01;
#[allow(dead_code)]
pub const TYPE_SOCKS5: u8 = 0x02;
#[allow(dead_code)]
pub const TYPE_HTTP: u8 = 0x03;

fn derive_keys(master_key: &[u8]) -> ([u8; 32], [u8; 32]) {
    const HKDF_SALT: &[u8] = b"signed-uuid-hkdf-salt-v1-20250629";
    let prk = hkdf_extract(HKDF_SALT, master_key);
    let k_enc = hkdf_expand(&prk, b"uuid-enc-v1");
    let k_mac = hkdf_expand(&prk, b"uuid-mac-v1");
    (k_enc, k_mac)
}

fn generate_keystream(k_enc: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let mut input = [0u8; NONCE_LEN + 1];
    input[0..NONCE_LEN].copy_from_slice(nonce);
    input[NONCE_LEN] = 0;
    hmac_sha256(k_enc, &input)
}

fn compute_mac(
    k_mac: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8; PLAINTEXT_LEN],
) -> [u8; 32] {
    // Empty context: derived_key == k_mac (matches relay's `decode`).
    let mut input = [0u8; MAC_INPUT_LEN];
    input[0..NONCE_LEN].copy_from_slice(nonce);
    input[NONCE_LEN..MAC_INPUT_LEN].copy_from_slice(ciphertext);
    hmac_sha256(k_mac, &input)
}

pub struct UuidCodec {
    k_enc: [u8; 32],
    k_mac: [u8; 32],
}

impl UuidCodec {
    pub fn new(master_key: &[u8]) -> Self {
        let (k_enc, k_mac) = derive_keys(master_key);
        Self { k_enc, k_mac }
    }

    /// Encode an egress into a signed 16-byte UUID. `nonce` must be 4 fresh bytes.
    pub fn encode(
        &self,
        type_byte: u8,
        ipv4: [u8; 4],
        port: u16,
        nonce: &[u8; NONCE_LEN],
    ) -> [u8; 16] {
        let mut plaintext = [0u8; PLAINTEXT_LEN];
        plaintext[0] = type_byte;
        plaintext[1..5].copy_from_slice(&ipv4);
        plaintext[5..7].copy_from_slice(&port.to_be_bytes());

        let keystream = generate_keystream(&self.k_enc, nonce);
        let mut ciphertext = [0u8; PLAINTEXT_LEN];
        for i in 0..PLAINTEXT_LEN {
            ciphertext[i] = plaintext[i] ^ keystream[i];
        }

        let mac = compute_mac(&self.k_mac, nonce, &ciphertext);

        let mut bytes = [0u8; 16];
        bytes[0..NONCE_LEN].copy_from_slice(nonce);
        bytes[NONCE_LEN..NONCE_LEN + PLAINTEXT_LEN].copy_from_slice(&ciphertext);
        bytes[NONCE_LEN + PLAINTEXT_LEN..16].copy_from_slice(&mac[..MAC_LEN]);
        bytes
    }
}
