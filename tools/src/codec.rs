use crate::hmac::{hkdf_expand, hkdf_extract, hmac_sha256};
use std::net::Ipv4Addr;
use std::str::FromStr;

use rand::RngCore;

const MAC_LEN: usize = 5;
const NONCE_LEN: usize = 4;
const PLAINTEXT_LEN: usize = 7;
const MAC_INPUT_LEN: usize = NONCE_LEN + PLAINTEXT_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidFormat,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidFormat => write!(f, "Invalid UUID format"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Uuid([u8; 16]);

impl Uuid {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Uuid({})", self)
    }
}

impl std::fmt::Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3],
            self.0[4], self.0[5], self.0[6], self.0[7],
            self.0[8], self.0[9], self.0[10], self.0[11],
            self.0[12], self.0[13], self.0[14], self.0[15]
        )
    }
}

impl FromStr for Uuid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex: String = s.chars().filter(|&c| c != '-').collect();
        if hex.len() != 32 {
            return Err(Error::InvalidFormat);
        }
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] =
                u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| Error::InvalidFormat)?;
        }
        Ok(Self(bytes))
    }
}

fn secure_zero(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::hint::black_box(bytes);
}

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
    context: &[u8],
) -> [u8; 32] {
    let derived_key = if context.is_empty() {
        *k_mac
    } else {
        hmac_sha256(k_mac, context)
    };
    let mut input = [0u8; MAC_INPUT_LEN];
    input[0..NONCE_LEN].copy_from_slice(nonce);
    input[NONCE_LEN..MAC_INPUT_LEN].copy_from_slice(ciphertext);
    hmac_sha256(&derived_key, &input)
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

    pub fn encode(&self, type_byte: u8, ipv4: Ipv4Addr, port: u16) -> Uuid {
        self.encode_with_context(type_byte, ipv4, port, b"")
    }

    pub fn encode_with_context(
        &self,
        type_byte: u8,
        ipv4: Ipv4Addr,
        port: u16,
        context: &[u8],
    ) -> Uuid {
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let mut plaintext = [0u8; PLAINTEXT_LEN];
        plaintext[0] = type_byte;
        plaintext[1..5].copy_from_slice(&ipv4.octets());
        plaintext[5..7].copy_from_slice(&port.to_be_bytes());

        let keystream = generate_keystream(&self.k_enc, &nonce);

        let mut ciphertext = [0u8; PLAINTEXT_LEN];
        for i in 0..PLAINTEXT_LEN {
            ciphertext[i] = plaintext[i] ^ keystream[i];
        }

        let mac = compute_mac(&self.k_mac, &nonce, &ciphertext, context);

        let mut bytes = [0u8; 16];
        bytes[0..NONCE_LEN].copy_from_slice(&nonce);
        bytes[NONCE_LEN..NONCE_LEN + PLAINTEXT_LEN].copy_from_slice(&ciphertext);
        bytes[NONCE_LEN + PLAINTEXT_LEN..16].copy_from_slice(&mac[..MAC_LEN]);

        Uuid::from_bytes(bytes)
    }
}

impl std::fmt::Debug for UuidCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UuidCodec")
            .field("k_enc", &"[REDACTED]")
            .field("k_mac", &"[REDACTED]")
            .finish()
    }
}

impl Drop for UuidCodec {
    fn drop(&mut self) {
        secure_zero(&mut self.k_enc);
        secure_zero(&mut self.k_mac);
    }
}
