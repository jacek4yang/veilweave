// enc.rs
// Server-side VLESS Encryption for xray-core's `mlkem768x25519plus`, implementing
// the single best-performance / best-security profile only:
//
//   mode    = native   (no record-header XOR — zero per-byte obfuscation overhead;
//                        we already run inside Cloudflare's WSS, so the stream is
//                        camouflaged at the transport)
//   session = 1-RTT     (Worker isolates are ephemeral; no 0-RTT ticket store)
//   PFS     = ML-KEM-768 + X25519 hybrid, per connection (post-quantum forward
//                        secrecy), keyed with BLAKE3, sealed with AES-256-GCM /
//                        ChaCha20-Poly1305.
//
// This is a faithful, byte-compatible subset of xray-core's
// proxy/vless/encryption/{common,server}.go — the parts an up-to-date client
// negotiates for this profile — deliberately omitting the xorpub/random modes and
// configurable padding/0-RTT machinery, which only add overhead.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use kem::Encapsulate;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use wasm_bindgen::JsValue;
use web_sys::WebSocket;
use worker::{Error, Result};

use crate::rng::WebRng;
use crate::wsio::WsReader;

#[inline(always)]
fn fb() -> Error {
    Error::RustError(String::new())
}

// ML-KEM-768 sizes (FIPS 203): encapsulation key, ciphertext, shared secret.
const MLKEM_EK: usize = 1184;
const MLKEM_CT: usize = 1088;
const MLKEM_SS: usize = 32;
const X25519_LEN: usize = 32;

const MAX_NONCE: [u8; 12] = [0xFF; 12];

// ─── BLAKE3 key derivation (matches Go's lukechampine.com/blake3.DeriveKey) ──────

/// `blake3::derive_key` with an arbitrary-byte context. The protocol uses raw
/// public-key bytes as the KDF context; Go reinterprets them via `string(ctx)`,
/// which we mirror with an unchecked UTF-8 view (BLAKE3 only hashes the bytes).
#[inline]
fn derive_key(ctx: &[u8], key: &[u8]) -> [u8; 32] {
    blake3::derive_key(unsafe { core::str::from_utf8_unchecked(ctx) }, key)
}

// ─── Handshake AEAD cipher (AES-256-GCM, software) ───────────────────────────────
//
// Used only for the handshake messages (interleaved with ML-KEM/X25519 in wasm, so
// it stays in Rust). The bulk data path is WebCrypto AES-NI; ChaCha20-Poly1305 is
// not supported (rejected at the first length-decrypt).

struct Aead {
    cipher: Box<Aes256Gcm>,
    nonce: [u8; 12],
}

#[inline]
fn increase_nonce(n: &mut [u8; 12]) {
    for i in 0..12 {
        let idx = 11 - i;
        n[idx] = n[idx].wrapping_add(1);
        if n[idx] != 0 {
            break;
        }
    }
}

impl Aead {
    fn new(ctx: &[u8], key: &[u8]) -> Self {
        let k = derive_key(ctx, key);
        Aead {
            cipher: Box::new(Aes256Gcm::new(GenericArray::from_slice(&k))),
            nonce: [0u8; 12],
        }
    }

    #[inline]
    fn seal_detached(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let n = GenericArray::from_slice(nonce);
        let tag = self
            .cipher
            .encrypt_in_place_detached(n, aad, data)
            .expect("AEAD seal");
        let mut t = [0u8; 16];
        t.copy_from_slice(&tag);
        t
    }

    #[inline]
    fn open_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<()> {
        let n = GenericArray::from_slice(nonce);
        let t = GenericArray::from_slice(tag);
        self.cipher
            .decrypt_in_place_detached(n, aad, data, t)
            .map_err(|_| fb())
    }

    /// Seal with the auto-incrementing nonce; `out` must be `plaintext+16` bytes.
    fn seal(&mut self, plaintext: &[u8], aad: &[u8], out: &mut [u8]) {
        increase_nonce(&mut self.nonce);
        let nonce = self.nonce;
        let pl = plaintext.len();
        out[..pl].copy_from_slice(plaintext);
        let tag = self.seal_detached(&nonce, aad, &mut out[..pl]);
        out[pl..pl + 16].copy_from_slice(&tag);
    }

    /// Seal with a caller-supplied nonce, without touching the counter (used for
    /// the NFS-AEAD-sealed PFS public key, which xray seals at `MaxNonce`).
    fn seal_with_nonce(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8], out: &mut [u8]) {
        let pl = plaintext.len();
        out[..pl].copy_from_slice(plaintext);
        let tag = self.seal_detached(nonce, aad, &mut out[..pl]);
        out[pl..pl + 16].copy_from_slice(&tag);
    }

    /// Open a `ciphertext‖tag` buffer in place with the auto-incrementing nonce;
    /// returns the plaintext length (`data.len() - 16`).
    fn open(&mut self, data: &mut [u8], aad: &[u8]) -> Result<usize> {
        increase_nonce(&mut self.nonce);
        let nonce = self.nonce;
        if data.len() < 16 {
            return Err(fb());
        }
        let pl = data.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[pl..]);
        self.open_detached(&nonce, aad, &mut data[..pl], &tag)?;
        Ok(pl)
    }
}

// ─── Header / length codecs ───────────────────────────────────────────────────────

#[inline]
fn encode_length(l: usize) -> [u8; 2] {
    [(l >> 8) as u8, l as u8]
}
#[inline]
fn decode_length(b: &[u8]) -> usize {
    ((b[0] as usize) << 8) | b[1] as usize
}
#[inline]
fn encode_header(h: &mut [u8], l: usize) {
    h[0] = 23;
    h[1] = 3;
    h[2] = 3;
    h[3] = (l >> 8) as u8;
    h[4] = l as u8;
}
#[inline]
fn decode_header(h: &[u8]) -> Result<usize> {
    let mut l = ((h[3] as usize) << 8) | h[4] as usize;
    if h[0] != 23 || h[1] != 3 || h[2] != 3 {
        l = 0;
    }
    if !(17..=16640).contains(&l) {
        return Err(fb());
    }
    Ok(l)
}

// ─── Configuration ─────────────────────────────────────────────────────────────────

/// The only encryption config: the server's long-term X25519 NFS private key.
/// Mode/padding/session are fixed by the chosen profile, so there is nothing else
/// to configure.
pub struct EncConfig {
    nfs_secret: StaticSecret,
}

impl EncConfig {
    pub fn new(private_key: [u8; 32]) -> EncConfig {
        EncConfig {
            nfs_secret: StaticSecret::from(private_key),
        }
    }
}

/// Light handshake padding: a random 100..1000-byte sealed block (size variation
/// with no inter-fragment gaps), kept minimal because the outer WSS already hides
/// the traffic shape. Always ≥18 so the wire-mandatory length prefix fits.
fn padding_len() -> usize {
    let mut b = [0u8; 2];
    crate::rng::fill_random(&mut b);
    100 + (u16::from_le_bytes(b) as usize) % 901
}

// ─── Header / nonce codecs exposed to the JS-handle data path ────────────────────

/// Big-endian 12-byte nonce increment (xray's `IncreaseNonce`).
#[inline]
pub fn next_nonce(n: &mut [u8; 12]) {
    increase_nonce(n);
}

/// Write the 5-byte TLS-record header for an `l`-byte AEAD record body.
#[inline]
pub fn put_header(h: &mut [u8; 5], l: usize) {
    encode_header(h, l);
}

/// Parse + validate a 5-byte record header, returning the body length (17..16640).
#[inline]
pub fn get_header(h: &[u8; 5]) -> Result<usize> {
    decode_header(h)
}

// ─── Established connection: keys + nonce state for the JS-handle data path ───────
//
// The handshake (ML-KEM-768 + X25519 + BLAKE3, in wasm) hands off the two derived
// AES-256-GCM keys and the per-direction nonce counters. From here the bulk data
// path runs entirely on WebCrypto over JS buffer handles — payload never re-enters
// wasm — so only the handshake and the first (VLESS-header) record touch wasm.

pub struct Handshake {
    /// Encrypted data-stream bytes already buffered past the handshake.
    pub leftover: Vec<u8>,
    /// Download (server→client) AES-256-GCM key + its next nonce.
    pub key_w: [u8; 32],
    pub nonce_w: [u8; 12],
    /// Upload (client→server) AES-256-GCM key + its next nonce.
    pub key_r: [u8; 32],
    pub nonce_r: [u8; 12],
}

/// Build one encrypted record `[header ‖ ciphertext ‖ tag]` for `plaintext` — used
/// for the VLESS response and the proxy-handshake leftover (small, one-shot).
pub async fn seal_record_wasm(
    key: &JsValue,
    nonce: &mut [u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 5];
    encode_header(&mut hdr, plaintext.len() + 16);
    increase_nonce(nonce);
    let ct = crate::webcrypto::encrypt(key, nonce, &hdr, plaintext).await?;
    let mut rec = Vec::with_capacity(5 + ct.len());
    rec.extend_from_slice(&hdr);
    rec.extend_from_slice(&ct);
    Ok(rec)
}

// ─── Server handshake ─────────────────────────────────────────────────────────────

/// Perform the server side of the VLESS Encryption handshake over an in-memory
/// `reader` (the buffered clientHello) and `ws` (server→client).
///
/// `Ok(Some(_))` — handshake complete; returns derived keys + nonce state + any
/// data-stream leftover. `Ok(None)` — the buffer does not yet hold the whole
/// clientHello; **nothing has been sent**, so the caller retries with more bytes.
/// `Err` — protocol violation / ChaCha-only client (rejected).
///
/// All clientHello reads happen before any `ws.send`, so a partial buffer is a
/// clean no-op — this is what makes the handshake safe to run per `websocket_message`.
pub async fn server_handshake(
    cfg: &EncConfig,
    mut reader: WsReader,
    ws: &WebSocket,
) -> Result<Option<Handshake>> {
    let mut rng = WebRng;

    // (1) NFS key exchange. Single X25519 key → relays section is the client's
    //     ephemeral X25519 public key (32 bytes); native mode sends it as-is.
    let mut iv_relays = [0u8; 16 + X25519_LEN];
    if !reader.read_exact(&mut iv_relays).await? {
        return Ok(None);
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&iv_relays[..16]);
    let mut relay = [0u8; X25519_LEN];
    relay.copy_from_slice(&iv_relays[16..]);

    // Reject non-canonical X25519 (high bit must be clear) — observer-tamper guard.
    if relay[31] > 127 {
        return Err(fb());
    }
    let client_nfs_pub = PublicKey::from(relay);
    let nfs_key = cfg.nfs_secret.diffie_hellman(&client_nfs_pub).to_bytes();

    let mut nfs_aead = Aead::new(&iv, &nfs_key);

    // (2) Encrypted length prefix. AES-256-GCM only: a failed open means a
    //     ChaCha-only client (or garbage) — reject (no software ChaCha path).
    let mut len_buf = [0u8; 18];
    if !reader.read_exact(&mut len_buf).await? {
        return Ok(None);
    }
    nfs_aead.open(&mut len_buf, &[])?;
    let length = decode_length(&len_buf[..2]);

    // 0-RTT (ticket) is never offered by this server (seconds=0). A `32` here
    // means a stale client ticket — refuse so it falls back to a full handshake.
    if length == 32 {
        return Err(fb());
    }
    if !(MLKEM_EK + X25519_LEN + 16..=16 + MLKEM_EK + X25519_LEN + 16).contains(&length) {
        return Err(fb());
    }

    // PFS public key from client: ML-KEM-768 encapsulation key ‖ X25519 public.
    let mut enc_pfs = vec![0u8; length];
    if !reader.read_exact(&mut enc_pfs).await? {
        return Ok(None);
    }
    let pl = nfs_aead.open(&mut enc_pfs, &[])?; // nfs nonce: 2nd use
    enc_pfs.truncate(pl);
    if enc_pfs.len() < MLKEM_EK + X25519_LEN {
        return Err(fb());
    }
    let client_pfs_public = enc_pfs[..MLKEM_EK + X25519_LEN].to_vec();

    // (3) Client's trailing padding (sealed by nfsAEAD): length + body. Read it now
    //     — before any send — so an incomplete clientHello is a clean retry.
    let mut cpad_len = [0u8; 18];
    if !reader.read_exact(&mut cpad_len).await? {
        return Ok(None);
    }
    nfs_aead.open(&mut cpad_len, &[])?; // nfs nonce: 3rd use
    let cplen = decode_length(&cpad_len[..2]);
    if cplen > 16 + 65535 {
        return Err(fb());
    }
    if cplen > 0 {
        let mut cpad = vec![0u8; cplen];
        if !reader.read_exact(&mut cpad).await? {
            return Ok(None);
        }
        nfs_aead.open(&mut cpad, &[])?; // nfs nonce: 4th use
    }

    // From here the whole clientHello is in hand — commit (ML-KEM, build & send the
    // serverHello). ML-KEM-768 encapsulation against the client's encapsulation key.
    let (mlkem_ct, mlkem_ss) = mlkem_encapsulate(&enc_pfs[..MLKEM_EK], &mut rng)?;
    // Ephemeral X25519 for the PFS leg.
    let mut peer_x = [0u8; 32];
    peer_x.copy_from_slice(&enc_pfs[MLKEM_EK..MLKEM_EK + X25519_LEN]);
    let server_eph = EphemeralSecret::random_from_rng(rng);
    let server_eph_pub = PublicKey::from(&server_eph).to_bytes();
    let x_ss = server_eph
        .diffie_hellman(&PublicKey::from(peer_x))
        .to_bytes();

    // pfsKey = mlkemShared ‖ x25519Shared ; unitedKey = pfsKey ‖ nfsKey
    let mut pfs_key = Vec::with_capacity(MLKEM_SS + X25519_LEN);
    pfs_key.extend_from_slice(&mlkem_ss);
    pfs_key.extend_from_slice(&x_ss);
    // serverPfsPublic = mlkemCiphertext ‖ serverEphemeralX25519Public
    let mut pfs_public = Vec::with_capacity(MLKEM_CT + X25519_LEN);
    pfs_public.extend_from_slice(&mlkem_ct);
    pfs_public.extend_from_slice(&server_eph_pub);

    let mut united_key = Vec::with_capacity(pfs_key.len() + 32);
    united_key.extend_from_slice(&pfs_key);
    united_key.extend_from_slice(&nfs_key);

    // Write AEAD ctx = our PFS public (also the download data key); the read/upload
    // key is derived below from the client's PFS public. The differing context
    // lengths bind upload≠download and client≠server roles.
    let mut write_aead = Aead::new(&pfs_public, &united_key);

    // Session ticket: 16 bytes, first two = seconds. seconds=0 ⇒ client won't cache.
    let mut ticket = [0u8; 16];
    crate::rng::fill_random(&mut ticket);
    ticket[0] = 0;
    ticket[1] = 0;

    // (3) Build serverHello = sealedPfsPublic ‖ sealedTicket ‖ sealedPadding, then
    //     send it in one shot (no fragmentation/gaps — pure latency win, the client
    //     reads exact byte counts regardless of framing).
    let pfs_kex_len = MLKEM_CT + X25519_LEN + 16; // 1136
    let ticket_len = 32;
    let pad_total = padding_len();
    let mut hello = vec![0u8; pfs_kex_len + ticket_len + pad_total];

    // pfsPublic sealed by nfsAEAD at MaxNonce (does not advance the nfs counter).
    nfs_aead.seal_with_nonce(&MAX_NONCE, &pfs_public, &[], &mut hello[..pfs_kex_len]);
    // ticket sealed by write AEAD (nonce 1).
    write_aead.seal(
        &ticket,
        &[],
        &mut hello[pfs_kex_len..pfs_kex_len + ticket_len],
    );
    // padding: 18-byte sealed length (nonce 2) then sealed body (nonce 3). The
    // body is zero-filled; its content is discarded by the peer.
    {
        let pad = &mut hello[pfs_kex_len + ticket_len..];
        let plen = encode_length(pad_total - 18);
        let (lhs, rhs) = pad.split_at_mut(18);
        write_aead.seal(&plen, &[], lhs);
        if pad_total > 18 {
            let body_pt = vec![0u8; pad_total - 18 - 16];
            write_aead.seal(&body_pt, &[], rhs);
        }
    }
    ws.send_with_u8_array(&hello).map_err(|_| fb())?;

    // The two data-phase AES-256-GCM keys (key_w identical to write_aead's) plus
    // their carried nonce counters (write used 1,2,3 for ticket/padding → next 4;
    // read unused → next 1).
    let key_w = derive_key(&pfs_public, &united_key);
    let key_r = derive_key(&client_pfs_public, &united_key);
    Ok(Some(Handshake {
        leftover: reader.leftover(),
        key_w,
        nonce_w: write_aead.nonce,
        key_r,
        nonce_r: [0u8; 12], // read AEAD is unused during the handshake
    }))
}

/// ML-KEM-768 encapsulate against `ek_bytes` (1184-byte encapsulation key).
/// Returns `(ciphertext[1088], sharedSecret[32])`.
fn mlkem_encapsulate(ek_bytes: &[u8], rng: &mut WebRng) -> Result<(Vec<u8>, [u8; 32])> {
    type Ek = <MlKem768 as KemCore>::EncapsulationKey;
    let enc = Encoded::<Ek>::try_from(ek_bytes).map_err(|_| fb())?;
    let ek = Ek::from_bytes(&enc);
    let (ct, ss) = ek.encapsulate(rng).map_err(|_| fb())?;
    let mut ssb = [0u8; 32];
    ssb.copy_from_slice(ss.as_slice());
    Ok((ct.as_slice().to_vec(), ssb))
}
