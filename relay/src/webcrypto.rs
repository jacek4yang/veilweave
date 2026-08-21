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

/// AAD length for every data-path call: the 5-byte VLESS Encryption record
/// header. Typed into the signatures below so the reused `ad_buf` (see `Ctx`)
/// is provably the right size — the protocol fixes this, no caller can vary it.
const AAD_LEN: usize = 5;

/// Per-isolate WebCrypto handles. `crypto.subtle` and its methods are stable for
/// the isolate's life, so binding them once removes a handful of `Reflect.get`
/// lookups and `JsString` allocations from every record on the hot path.
///
/// `params` / `iv_buf` / `ad_buf` / `args` are the per-call machinery, built once
/// and **reused for every record** — this removes four per-record allocations
/// (a params `Object`, two `Uint8Array` buffers and the args `Array`) that the
/// old code paid for each call. Reuse is safe because of a WebCrypto guarantee:
/// the algorithm dictionary and the data buffer are read ("get a copy of the
/// bytes", WebIDL conversion) **synchronously during the call**, before the
/// returned promise exists — so rewriting these buffers between calls can never
/// disturb an in-flight operation, and there is no `await` between the rewrite
/// and the `apply` (workers are single-threaded, so nothing else runs in that
/// window either). The old comment rejected reuse out of a race concern; the
/// synchronous-copy semantics are exactly what close that race.
struct Ctx {
    subtle: JsValue,
    encrypt: Function,
    decrypt: Function,
    import_key: Function,
    // Cached constant JsValue used by `importKey` (twice per connection).
    alg_name: JsValue, // "AES-GCM"
    // Reused `{ name, iv, additionalData, tagLength }` params object: built once
    // in `build_ctx` (constant fields set there, `iv`/`ad` permanently bound to
    // the two views below), then owned by slot 0 of `args` — no Rust handle to
    // it is needed after that.
    iv_buf: Uint8Array, // 12-byte nonce view, rewritten per call
    ad_buf: Uint8Array, // 5-byte record-header AAD view, rewritten per call
    // Reused `(params, key, data)` argument list: slot 0 fixed, 1/2 set per call.
    args: Array,
}

impl Ctx {
    /// Rewrite the reused iv/AAD views and fill the reused argument list for one
    /// `subtle.<encrypt|decrypt>` call. Zero allocation; see `Ctx` for why the
    /// reuse is sound. The returned borrow is consumed synchronously by `apply`.
    fn gcm_args(
        &self,
        nonce: &[u8; 12],
        aad: &[u8; AAD_LEN],
        key: &JsValue,
        data: &JsValue,
    ) -> &Array {
        // `Uint8Array::view` wraps the wasm bytes with NO copy; it is read only by
        // the immediately following `set`, which copies the bytes into the cached
        // JS buffer. No wasm allocation can grow (and thus move) linear memory in
        // that window, so the aliasing is sound.
        self.iv_buf.set(unsafe { &Uint8Array::view(nonce) }, 0);
        self.ad_buf.set(unsafe { &Uint8Array::view(aad) }, 0);
        self.args.set(1, key.clone());
        self.args.set(2, data.clone());
        &self.args
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
    let alg_name = JsValue::from_str("AES-GCM");
    // Build the reused params object once: constant fields set here, the two
    // variable fields permanently bound to the cached views (rewritten per call).
    // The object itself is then owned by `args` slot 0, so no Rust field holds it.
    let params = Object::new();
    let iv_buf = Uint8Array::new_with_length(12);
    let ad_buf = Uint8Array::new_with_length(AAD_LEN as u32);
    let _ = Reflect::set(&params, &JsValue::from_str("name"), &alg_name);
    let _ = Reflect::set(&params, &JsValue::from_str("iv"), &iv_buf);
    let _ = Reflect::set(&params, &JsValue::from_str("additionalData"), &ad_buf);
    let _ = Reflect::set(
        &params,
        &JsValue::from_str("tagLength"),
        &JsValue::from_f64(128.0),
    );
    let args = Array::new();
    args.set(0, params.clone().into());
    Some(Ctx {
        encrypt: func("encrypt")?,
        decrypt: func("decrypt")?,
        import_key: func("importKey")?,
        subtle,
        alg_name,
        iv_buf,
        ad_buf,
        args,
    })
}

/// Run `subtle.<encrypt|decrypt>(params, key, data)` and await the result. The
/// synchronous part (rewrite views, fill args, `apply`) holds the `CTX` borrow;
/// the await happens after, on the returned Promise — so no borrow is held
/// across `await`.
async fn run(
    key: &JsValue,
    nonce: &[u8; 12],
    aad: &[u8; AAD_LEN],
    data: &JsValue,
    enc: bool,
) -> Result<JsValue> {
    let promise = CTX.with(|c| -> Result<Promise> {
        let ctx = c.get_or_init(build_ctx).as_ref().ok_or_else(fb)?;
        let args = ctx.gcm_args(nonce, aad, key, data);
        let f = if enc { &ctx.encrypt } else { &ctx.decrypt };
        Reflect::apply(f, &ctx.subtle, args)
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
pub async fn encrypt_view(
    key: &JsValue,
    nonce: &[u8; 12],
    aad: &[u8; AAD_LEN],
    data: &JsValue,
) -> Result<JsValue> {
    run(key, nonce, aad, data, true).await
}

/// Open a JS buffer source (`ciphertext‖tag`) → plaintext `ArrayBuffer` (no WASM copy).
pub async fn decrypt_view(
    key: &JsValue,
    nonce: &[u8; 12],
    aad: &[u8; AAD_LEN],
    data: &JsValue,
) -> Result<JsValue> {
    run(key, nonce, aad, data, false).await
}

// ─── Small one-shot helpers (handshake / VLESS-response path) ─────────────────────

/// AES-256-GCM seal: returns `ciphertext ‖ tag`. Used only for the tiny one-shot
/// VLESS-response / proxy-leftover records and the self-test.
pub async fn encrypt(
    key: &JsValue,
    nonce: &[u8; 12],
    aad: &[u8; AAD_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let data: JsValue = Uint8Array::from(plaintext).into();
    let out = run(key, nonce, aad, &data, true).await?;
    let ab = out.dyn_into::<ArrayBuffer>().map_err(|_| fb())?;
    Ok(Uint8Array::new(&ab).to_vec())
}

/// AES-256-GCM open of `ciphertext ‖ tag` → plaintext. Self-test only.
pub async fn decrypt(
    key: &JsValue,
    nonce: &[u8; 12],
    aad: &[u8; AAD_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
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
