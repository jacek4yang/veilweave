// rng.rs
// A `RngCore + CryptoRng` adapter over the Web Crypto `crypto.getRandomValues`,
// the only CSPRNG available inside a Cloudflare Worker isolate. ML-KEM-768
// encapsulation, the ephemeral X25519 key, the session ticket and the handshake
// padding all draw their randomness from here.
//
// `getRandomValues` caps each call at 65536 bytes, so larger fills are chunked.
// We reach the global `crypto` object via `Reflect` rather than a `web-sys`
// feature so the dependency surface stays minimal and worker-runtime-agnostic.

use js_sys::{Function, Reflect, Uint8Array};
use rand_core::{CryptoRng, RngCore};
use wasm_bindgen::{JsCast, JsValue};

/// Fill `dest` with cryptographically secure random bytes from the host CSPRNG.
pub fn fill_random(dest: &mut [u8]) {
    thread_local! {
        // `crypto` and its `getRandomValues` are stable for the isolate's life;
        // resolve them once and keep the bound function handle around.
        static GETTER: Option<(JsValue, Function)> = resolve_getter();
    }

    GETTER.with(|g| {
        let (crypto, get) = match g {
            Some(pair) => pair,
            // No host CSPRNG: there is no safe fallback for key material, so make
            // the failure loud rather than emit predictable bytes.
            None => panic!("crypto.getRandomValues unavailable"),
        };
        for chunk in dest.chunks_mut(65536) {
            let arr = Uint8Array::new_with_length(chunk.len() as u32);
            // getRandomValues fills and returns the same typed array in place.
            get.call1(crypto, &arr).expect("getRandomValues failed");
            arr.copy_to(chunk);
        }
    });
}

fn resolve_getter() -> Option<(JsValue, Function)> {
    let global = js_sys::global();
    let crypto = Reflect::get(&global, &JsValue::from_str("crypto")).ok()?;
    if crypto.is_undefined() || crypto.is_null() {
        return None;
    }
    let get = Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))
        .ok()?
        .dyn_into::<Function>()
        .ok()?;
    Some((crypto, get))
}

/// Zero-sized CSPRNG handle implementing the `rand_core` traits required by
/// `ml-kem` and `x25519-dalek`.
#[derive(Clone, Copy, Default)]
pub struct WebRng;

impl RngCore for WebRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_random(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        fill_random(dest);
        Ok(())
    }
}

impl CryptoRng for WebRng {}
