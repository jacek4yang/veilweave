// webcrypto.rs
// Offload the per-record AES-256-GCM to the host's WebCrypto (`crypto.subtle`),
// which in workerd is BoringSSL/C++ with AES-NI — an order of magnitude faster
// (and far cheaper on the Worker CPU budget) than RustCrypto's software AES in
// wasm32, which has no AES instructions.
//
// Only the data-record AEAD moves here; the ML-KEM-768 + X25519 + BLAKE3 handshake
// stays in Rust (WebCrypto has none of those). WebCrypto also lacks
// ChaCha20-Poly1305, so the profile is AES-256-GCM only.
//
// `crypto.subtle`, its method functions, and the constant algorithm strings are
// resolved **once per isolate** (`Ctx`), so each record only pays for the small
// per-call `iv`/`additionalData` buffers and the `apply` — not a fresh chain of
// `Reflect.get` lookups. The fast path is gated by a one-time self-test that
// byte-compares WebCrypto's output against RustCrypto's.

use std::cell::{Cell, OnceCell};

use js_sys::{Array, ArrayBuffer, Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{Error, Result};

#[inline(always)]
fn fb() -> Error {
    Error::RustError(String::new())
}

/// Per-isolate WebCrypto handles. `crypto.subtle` and its methods are stable for
/// the isolate's life, so binding them once removes a handful of `Reflect.get`
/// lookups and `JsString` allocations from every record on the hot path.
struct Ctx {
    subtle: JsValue,
    encrypt: Function,
    decrypt: Function,
    import_key: Function,
    // Cached constant JsValues used to assemble the per-call algorithm object.
    alg_name: JsValue, // "AES-GCM"
    tag_len: JsValue,  // 128.0
    k_name: JsValue,   // "name"
    k_iv: JsValue,     // "iv"
    k_ad: JsValue,     // "additionalData"
    k_tag: JsValue,    // "tagLength"
}

impl Ctx {
    /// Build a fresh `{ name, iv, additionalData, tagLength }` algorithm object.
    ///
    /// Intentionally **not** a shared/mutated object: a reused object would risk a
    /// data race if its `iv` were changed while a prior `encrypt` promise was still
    /// reading it, and correctness under sustained load outranks the few ops saved.
    fn gcm_params(&self, nonce: &[u8; 12], aad: &[u8]) -> Object {
        let p = Object::new();
        let iv: JsValue = Uint8Array::from(&nonce[..]).into();
        let ad: JsValue = Uint8Array::from(aad).into();
        let _ = Reflect::set(&p, &self.k_name, &self.alg_name);
        let _ = Reflect::set(&p, &self.k_iv, &iv);
        let _ = Reflect::set(&p, &self.k_ad, &ad);
        let _ = Reflect::set(&p, &self.k_tag, &self.tag_len);
        p
    }
}

thread_local! {
    // `None` once probed and found unavailable (never happens in a real Worker,
    // which always exposes `crypto.subtle`); resolved handles otherwise.
    static CTX: OnceCell<Option<Ctx>> = const { OnceCell::new() };
}

fn build_ctx() -> Option<Ctx> {
    let crypto = Reflect::get(&js_sys::global(), &JsValue::from_str("crypto")).ok()?;
    let subtle = Reflect::get(&crypto, &JsValue::from_str("subtle")).ok()?;
    if subtle.is_undefined() || subtle.is_null() {
        return None;
    }
    let func = |name: &str| -> Option<Function> {
        Reflect::get(&subtle, &JsValue::from_str(name))
            .ok()?
            .dyn_into::<Function>()
            .ok()
    };
    Some(Ctx {
        encrypt: func("encrypt")?,
        decrypt: func("decrypt")?,
        import_key: func("importKey")?,
        subtle,
        alg_name: JsValue::from_str("AES-GCM"),
        tag_len: JsValue::from_f64(128.0),
        k_name: JsValue::from_str("name"),
        k_iv: JsValue::from_str("iv"),
        k_ad: JsValue::from_str("additionalData"),
        k_tag: JsValue::from_str("tagLength"),
    })
}

/// Run `subtle.<encrypt|decrypt>(params, key, data)` and await the result. The
/// synchronous part (assemble args, `apply`) holds the `CTX` borrow; the await
/// happens after, on the returned Promise — so no borrow is held across `await`.
async fn run(key: &JsValue, nonce: &[u8; 12], aad: &[u8], data: &JsValue, enc: bool) -> Result<JsValue> {
    let promise = CTX.with(|c| -> Result<Promise> {
        let ctx = c.get_or_init(build_ctx).as_ref().ok_or_else(fb)?;
        let args = Array::of3(&ctx.gcm_params(nonce, aad), key, data);
        let f = if enc { &ctx.encrypt } else { &ctx.decrypt };
        Reflect::apply(f, &ctx.subtle, &args)
            .map_err(|_| fb())?
            .dyn_into::<Promise>()
            .map_err(|_| fb())
    })?;
    JsFuture::from(promise).await.map_err(|_| fb())
}

/// Import a raw 32-byte key as a non-extractable AES-GCM `CryptoKey`.
pub async fn import_aes_gcm_key(raw: &[u8; 32]) -> Result<JsValue> {
    let promise = CTX.with(|c| -> Result<Promise> {
        let ctx = c.get_or_init(build_ctx).as_ref().ok_or_else(fb)?;
        let usages = Array::of2(&JsValue::from_str("encrypt"), &JsValue::from_str("decrypt"));
        let key_data: JsValue = Uint8Array::from(&raw[..]).into();
        let args = Array::of5(
            &JsValue::from_str("raw"),
            &key_data,
            &ctx.alg_name,
            &JsValue::from_bool(false),
            &usages.into(),
        );
        Reflect::apply(&ctx.import_key, &ctx.subtle, &args)
            .map_err(|_| fb())?
            .dyn_into::<Promise>()
            .map_err(|_| fb())
    })?;
    JsFuture::from(promise).await.map_err(|_| fb())
}

// ─── JS-handle fast path — payload never enters WASM ──────────────────────────────
//
// `data` is a JS `Uint8Array`/`ArrayBuffer` view straight from the socket / WS, and
// the result is the raw `ArrayBuffer` from BoringSSL. The payload bytes stay in the
// V8 heap end-to-end; only the 5-byte AAD header and 12-byte nonce ever cross into
// wasm. This is the bulk data path.

/// Seal a JS buffer source → ciphertext`‖`tag `ArrayBuffer` (no WASM copy).
pub async fn encrypt_view(key: &JsValue, nonce: &[u8; 12], aad: &[u8], data: &JsValue) -> Result<JsValue> {
    run(key, nonce, aad, data, true).await
}

/// Open a JS buffer source (`ciphertext‖tag`) → plaintext `ArrayBuffer` (no WASM copy).
pub async fn decrypt_view(key: &JsValue, nonce: &[u8; 12], aad: &[u8], data: &JsValue) -> Result<JsValue> {
    run(key, nonce, aad, data, false).await
}

// ─── Small one-shot helpers (handshake / VLESS-response path) ─────────────────────

/// AES-256-GCM seal: returns `ciphertext ‖ tag`. Used only for the tiny one-shot
/// VLESS-response / proxy-leftover records and the self-test.
pub async fn encrypt(key: &JsValue, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let data: JsValue = Uint8Array::from(plaintext).into();
    let out = run(key, nonce, aad, &data, true).await?;
    let ab = out.dyn_into::<ArrayBuffer>().map_err(|_| fb())?;
    Ok(Uint8Array::new(&ab).to_vec())
}

/// AES-256-GCM open of `ciphertext ‖ tag` → plaintext. Self-test only.
pub async fn decrypt(key: &JsValue, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let data: JsValue = Uint8Array::from(ciphertext).into();
    let out = run(key, nonce, aad, &data, false).await?;
    let ab = out.dyn_into::<ArrayBuffer>().map_err(|_| fb())?;
    Ok(Uint8Array::new(&ab).to_vec())
}

// ─── One-time per-isolate self-test ────────────────────────────────────────────────

thread_local! {
    // -1 = not yet probed, 0 = unusable, 1 = verified usable.
    static STATUS: Cell<i8> = const { Cell::new(-1) };
}

/// Whether the WebCrypto AES-GCM fast path is available *and* byte-identical to the
/// Rust reference. Cached per isolate; the first call runs the probe.
pub async fn aes_gcm_usable() -> bool {
    if let s @ (0 | 1) = STATUS.with(Cell::get) {
        return s == 1;
    }
    let ok = self_test().await;
    STATUS.with(|c| c.set(ok as i8));
    ok
}

async fn self_test() -> bool {
    let key = [0x42u8; 32];
    let nonce = [0x07u8; 12];
    let aad = [23u8, 3, 3, 0, 30];
    let pt = b"veilweave vless-encryption webcrypto self-test";

    // Reference AES-256-GCM via RustCrypto — the ground truth the wire depends on.
    let reference = rust_reference(&key, &nonce, &aad, pt);

    let key_js = match import_aes_gcm_key(&key).await {
        Ok(k) => k,
        Err(_) => return false,
    };
    // Seal must match the reference byte-for-byte (validates iv/aad/tag wiring).
    match encrypt(&key_js, &nonce, &aad, pt).await {
        Ok(v) if v == reference => {}
        _ => return false,
    }
    // And open must round-trip the reference ciphertext back to the plaintext.
    matches!(decrypt(&key_js, &nonce, &aad, &reference).await, Ok(d) if d == pt)
}

fn rust_reference(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::Aes256Gcm;
    let c = Aes256Gcm::new(GenericArray::from_slice(key));
    let mut buf = pt.to_vec();
    let tag = c
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, &mut buf)
        .expect("ref seal");
    buf.extend_from_slice(&tag);
    buf
}
