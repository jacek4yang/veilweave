use crate::hmac::{hkdf_expand, hkdf_extract, hmac_sha256};
use core::str::FromStr;

const MAC_LEN: usize = 5;
const NONCE_LEN: usize = 4;
const PLAINTEXT_LEN: usize = 7;
const MAC_INPUT_LEN: usize = NONCE_LEN + PLAINTEXT_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidFormat,
    InvalidMac,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidFormat => write!(f, "Invalid UUID format"),
            Error::InvalidMac => write!(f, "Invalid MAC: UUID may be tampered or forged"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload {
    pub type_byte: u8,
    pub ipv4: [u8; 4],
    pub port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Uuid([u8; 16]);

impl Uuid {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Debug for Uuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Uuid({})", self)
    }
}

impl core::fmt::Display for Uuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
        let mut hex = [0u8; 32];
        let mut hi = None;
        let mut idx = 0;
        for c in s.bytes() {
            if c == b'-' {
                continue;
            }
            let n = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(Error::InvalidFormat),
            };
            if let Some(h) = hi {
                if idx >= 32 {
                    return Err(Error::InvalidFormat);
                }
                hex[idx] = (h << 4) | n;
                idx += 1;
                hi = None;
            } else {
                hi = Some(n);
            }
        }
        if hi.is_some() || idx != 16 {
            return Err(Error::InvalidFormat);
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hex[..16]);
        Ok(Self(bytes))
    }
}

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut v = 0u8;
    for i in 0..a.len() {
        v |= a[i] ^ b[i];
    }
    core::hint::black_box(v) == core::hint::black_box(0)
}

fn derive_keys(master_key: &[u8]) -> ([u8; 32], [u8; 32]) {
    const HKDF_SALT: &[u8] = b"signed-uuid-hkdf-salt-v1-20250629";
    let prk = hkdf_extract(HKDF_SALT, master_key);
    let k_enc = hkdf_expand(&prk, b"uuid-enc-v1");
    let k_mac = hkdf_expand(&prk, b"uuid-mac-v1");
    (k_enc, k_mac)
}

#[inline]
fn generate_keystream(k_enc: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let mut input = [0u8; NONCE_LEN + 1];
    input[0..NONCE_LEN].copy_from_slice(nonce);
    input[NONCE_LEN] = 0;
    hmac_sha256(k_enc, &input)
}

#[inline]
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

    pub fn decode(&self, uuid: &Uuid) -> Result<Payload, Error> {
        self.decode_with_context(uuid, b"")
    }

    pub fn decode_with_context(&self, uuid: &Uuid, context: &[u8]) -> Result<Payload, Error> {
        let bytes = uuid.as_bytes();

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[0..NONCE_LEN]);

        let mut ciphertext = [0u8; PLAINTEXT_LEN];
        ciphertext.copy_from_slice(&bytes[NONCE_LEN..NONCE_LEN + PLAINTEXT_LEN]);

        let mac = &bytes[NONCE_LEN + PLAINTEXT_LEN..16];

        let expected_mac = compute_mac(&self.k_mac, &nonce, &ciphertext, context);
        if !constant_time_eq(mac, &expected_mac[..MAC_LEN]) {
            return Err(Error::InvalidMac);
        }

        let keystream = generate_keystream(&self.k_enc, &nonce);

        let mut plaintext = [0u8; PLAINTEXT_LEN];
        for i in 0..PLAINTEXT_LEN {
            plaintext[i] = ciphertext[i] ^ keystream[i];
        }

        let type_byte = plaintext[0];
        let ipv4 = [plaintext[1], plaintext[2], plaintext[3], plaintext[4]];
        let port = u16::from_be_bytes([plaintext[5], plaintext[6]]);

        Ok(Payload {
            type_byte,
            ipv4,
            port,
        })
    }
}

impl core::fmt::Debug for UuidCodec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UuidCodec")
            .field("k_enc", &"[REDACTED]")
            .field("k_mac", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0xa4, 0xcb, 0x66, 0x0a, 0x88, 0x1b, 0xb2, 0x75, 0xd3, 0x97, 0x06,
        0x5b,
    ];

    #[test]
    fn sub_v1_golden_uuid_decodes_proxyip_payload() {
        let payload = UuidCodec::new(b"veilweave-golden-v1")
            .decode(&Uuid::from_bytes(GOLDEN))
            .unwrap();
        assert_eq!(payload.type_byte, 0x01);
        assert_eq!(payload.ipv4, [203, 0, 113, 9]);
        assert_eq!(payload.port, 443);
    }

    #[test]
    fn wrong_secret_and_modified_mac_are_rejected() {
        assert_eq!(
            UuidCodec::new(b"wrong-relay-secret").decode(&Uuid::from_bytes(GOLDEN)),
            Err(Error::InvalidMac)
        );
        let mut modified = GOLDEN;
        modified[15] ^= 1;
        assert_eq!(
            UuidCodec::new(b"veilweave-golden-v1").decode(&Uuid::from_bytes(modified)),
            Err(Error::InvalidMac)
        );
    }

    #[test]
    fn uuid_text_parser_accepts_canonical_golden_value() {
        let uuid: Uuid = "01234567-a4cb-660a-881b-b275d397065b".parse().unwrap();
        assert_eq!(uuid.as_bytes(), &GOLDEN);
        assert_eq!(uuid.to_string(), "01234567-a4cb-660a-881b-b275d397065b");
    }
}
