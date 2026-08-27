//! Cloudflare WebCrypto-backed randomness for signed-UUID nonces.
//!
//! There is deliberately no weak fallback. A predictable UUID nonce makes the
//! already-short v1 authentication tag easier to attack, so subscription
//! rendering fails if the host CSPRNG is unavailable.

use js_sys::{Function, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};

pub fn random_bytes(length: usize) -> Result<Vec<u8>, String> {
    if length > 65_536 {
        return Err("requested random byte count exceeds WebCrypto limit".to_string());
    }

    let global = js_sys::global();
    let crypto = Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|_| "crypto.getRandomValues unavailable".to_string())?;
    if crypto.is_null() || crypto.is_undefined() {
        return Err("crypto.getRandomValues unavailable".to_string());
    }
    let getter = Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))
        .map_err(|_| "crypto.getRandomValues unavailable".to_string())?
        .dyn_into::<Function>()
        .map_err(|_| "crypto.getRandomValues unavailable".to_string())?;
    let array = Uint8Array::new_with_length(length as u32);
    getter
        .call1(&crypto, &array)
        .map_err(|_| "crypto.getRandomValues failed".to_string())?;
    Ok(array.to_vec())
}
