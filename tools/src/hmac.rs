use crate::sha256::{sha256, Sha256};

// 纯 Rust 实现的 HMAC-SHA256（RFC 2104）
//
// HMAC 提供消息认证，确保消息的完整性和真实性。
// 在量子计算机上，HMAC-SHA256 的安全性约为 128 位（基于 SHA-256）。

/// 使用密钥和消息计算 HMAC-SHA256
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];

    // 如果密钥长度超过 64 字节，先对其做 SHA-256
    if key.len() > 64 {
        let hash = sha256(key);
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    // 创建 ipad 和 opad
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    // inner = SHA-256(ipad || message)
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    // outer = SHA-256(opad || inner)
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

/// 基于 HMAC-SHA256 的 HKDF-Extract（RFC 5869）
///
/// PRK = HMAC-SHA256(salt, IKM)
///
/// salt 应该是非空的固定值，且可以公开。它的作用是确保不同上下文
/// 下即使使用相同的 master_key，也不会派生出相同的密钥。
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// 基于 HMAC-SHA256 的 HKDF-Expand（RFC 5869，简化版，只产生 32 字节输出）
///
/// OKM = HMAC-SHA256(PRK, info || 0x01)
pub fn hkdf_expand(prk: &[u8], info: &[u8]) -> [u8; 32] {
    let mut input = [0u8; 64]; // 足够大的栈缓冲区
    let len = info.len();
    input[..len].copy_from_slice(info);
    input[len] = 1; // counter
    hmac_sha256(prk, &input[..len + 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        let result = hmac_sha256(&key, msg);
        let expected = hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case7() {
        let key = [0x0cu8; 20];
        let msg = b"Test With Truncation";
        let result = hmac_sha256(&key, msg);
        let expected = hex_to_bytes("a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5");
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_hmac_sha256_empty_key() {
        let result = hmac_sha256(b"", b"");
        let expected = hex_to_bytes("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_hmac_sha256_long_key() {
        let key = [0xaa; 131];
        let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let result = hmac_sha256(&key, msg);
        let expected = hex_to_bytes("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        assert_eq!(&result[..], &expected[..]);
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
