use crate::sha256::{sha256, Sha256};

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];

    if key.len() > 64 {
        let hash = sha256(key);
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

pub fn hkdf_expand(prk: &[u8], info: &[u8]) -> [u8; 32] {
    let mut input = [0u8; 64];
    let len = info.len();
    input[..len].copy_from_slice(info);
    input[len] = 1;
    hmac_sha256(prk, &input[..len + 1])
}
