# Protocol

The wire format of the **signed UUID** and the **encrypted record layer**
— what bytes fly between xray-core client and veilweave relay.

This is the *byte-for-byte* spec that the Rust code in `relay/src/`
implements. It is a subset of xray-core's `proxy/vless/encryption`,
limited to the `mlkem768x25519plus.native.1rtt` profile.

## 0. Layering

```
┌────────────────────────────────────────────┐
│  WebSocket binary frames  (each = 1 record) │  ← Cloudflare TLS
├────────────────────────────────────────────┤
│  [5B header] [AES-256-GCM ciphertext + tag] │  ← VLESS Encryption
├────────────────────────────────────────────┤
│  [VLESS header (variable)] + payload        │  ← VLESS
├────────────────────────────────────────────┤
│  inner-stream  (TCP / UDP / DNS)            │  ← proxy payload
└────────────────────────────────────────────┘
```

## 1. Signed UUID (16 bytes)

The VLESS UUID is the *only* user identity. There is no password or
per-request HMAC — the UUID itself authenticates the user (because it
is unforgeable without `SECRET_KEY`) AND carries the egress.

### Layout

```
 offset  size  field
 0       4     nonce           random per-UUID, public
 4       7     ciphertext      encrypted payload
 11      5     mac             HMAC-SHA256 truncated to 5 bytes
```

### Plaintext layout (inside ciphertext)

```
 offset  size  field
 0       1     type_byte       0x00 direct | 0x01 proxyip | 0x02 socks5 | 0x03 http
 1       4     ipv4            big-endian (egress address; ignored for type=0x00)
 5       2     port            big-endian (egress port;   ignored for type=0x00)
```

### Derivation

```
master      = SECRET_KEY (any 32 bytes; not the relay blob as a whole,
                          but the **uuid_secret(32)** segment of the blob)
prk         = HKDF-Extract(salt = "signed-uuid-hkdf-salt-v1-20250629",
                          ikm   = master)
k_enc       = HKDF-Expand(prk, info = "uuid-enc-v1")
k_mac       = HKDF-Expand(prk, info = "uuid-mac-v1")
keystream   = HMAC-SHA256(k_enc, nonce ‖ 0x00)[:7]      // counter = 0
plaintext   = ciphertext ⊕ keystream
mac         = HMAC-SHA256(k_mac, nonce ‖ ciphertext)[:5]
```

**MAC compare is constant-time.** A failure is rejected at the DO level
(no error log on the hot path; just `pump error → closing 1011`).

### Blob layout (`SECRET_KEY`)

```
 base64url(no pad) of:
   b"VW1"     (3B magic)
   kind       (1B; 0x00 = relay (x25519 private), 0x01 = sub (x25519 public))
   uuid_key   (32B)
   x25519     (32B; private for kind=0, public for kind=1)
```

A non-blob string is treated as a legacy raw secret: it seeds the
codec directly (bytes-as-master) and disables VLESS Encryption (the
relay needs a `kind=0` blob to have the X25519 private key).

## 2. VLESS Encryption handshake (server)

The first WS frame from a client is the **clientHello**. The relay reads
it all in memory, derives the keys, and emits a single **serverHello**
in one shot.

### clientHello (client → server)

```
[iv (16B)]
[client_nfs_pub_x25519 (32B)]                // NFS X25519 public, MUST have byte 31 < 0x80
[sealed_length_pfs (18B)]                    // AES-GCM(nfs_k, nfs_nonce=2, [], length‖16)
[sealed_pfs_pub (lengthB)]                   // AES-GCM(nfs_k, nfs_nonce=3, [], mlkem_ek ‖ x25519_pub ‖ 16)
[sealed_padding_length (18B)]                // AES-GCM(nfs_k, nfs_nonce=4, [], pad_len‖16)
[sealed_padding (pad_lenB)]                  // AES-GCM(nfs_k, nfs_nonce=5, [], pad‖16) — discarded
```

NFS key:

```
nfs_key = X25519(server.nfs_secret, client_nfs_pub)
```

The nfs AEAD context:

```
nfs_aead = Aead(ctx = iv(16B), key = nfs_key(32B))
```

The `sealed_length_pfs` is the length of `sealed_pfs_pub` (sealed form
is 18 bytes — 2 length + 16 tag — xray's choice). Accepted range:
`MLKEM_EK + X25519_LEN = 1216` to `16 + MLKEM_EK + X25519_LEN = 1232`
(0-RTT ticket of 32 bytes is rejected).

`sealed_pfs_pub` plaintext is `mlkem_ek(1184) ‖ x25519_pub(32)` = 1216 bytes.

### serverHello (server → client)

Sent in **one** `ws.send` — no fragmentation, no gaps:

```
[sealed_pfs_pub (1136B)]                     // AES-GCM(nfs_k, nonce=MAX, pfs_pub)
[sealed_ticket (32B)]                        // AES-GCM(write_k, nonce=1, ticket)
[sealed_padding_length (18B)]                // AES-GCM(write_k, nonce=2, pad_len)
[sealed_padding (pad_lenB)]                  // AES-GCM(write_k, nonce=3, zeros)
```

Where:

```
mlkem_ct, mlkem_ss  = ML-KEM-768.Encapsulate(client.mlkem_ek)
server_eph          = X25519.new_random()
server_eph_pub      = server_eph.public_bytes()
pfs_key             = mlkem_ss ‖ X25519(server_eph, client.x25519_pub)
pfs_public          = mlkem_ct ‖ server_eph_pub
united_key          = pfs_key ‖ nfs_key

write_k             = BLAKE3.derive_key(pfs_public, united_key)
read_k              = BLAKE3.derive_key(client.pfs_public, united_key)

ticket              = 16 random bytes; ticket[0..2] = 0x0000   // seconds=0 ⇒ no 0-RTT
```

The server:

- Seals `pfs_public` with the **nfs** AEAD at `nonce = MAX_NONCE` (i.e.
  the nfs counter does NOT advance — it stays at 1).
- Seals the ticket with the **write** AEAD at counter 1.
- Seals the padding with the **write** AEAD at counter 2 (length) and
  counter 3 (body).
- The next write-AEAD nonce for the data path is **4**.
- The first read-AEAD nonce for the data path is **1** (read is unused
  during the handshake).

### Padding

```
pad_total = 100 + rand(901)  // 100..=1000 bytes
```

The 5-byte TLS-record header inside the sealed block requires the body
to be ≥ 18 bytes (2 length + 16 tag), so the relay ensures `pad_total ≥ 18`
and reduces body plaintext to `pad_total - 18` if `pad_total > 18`.

## 3. Record layer (data path)

### Record on the wire (one WS frame)

```
[5B header]
[N bytes ciphertext]
[16B GCM tag]
```

`N` = plaintext length. Header encodes `N + 16` (the tag is part of the
"length" from the protocol's point of view, matching xray-core).

### Header (5 bytes)

```
byte 0 : 0x17
byte 1 : 0x03
byte 2 : 0x03
byte 3 : (N + 16) >> 8
byte 4 : (N + 16) & 0xff
```

Allowed total: 17..=16640 bytes (so plaintext 1..=16624 bytes; the
relay caps at 16384 in downloads).

### AEAD

- **cipher**: AES-256-GCM
- **key**: 32 bytes (`key_w` for download, `key_r` for upload)
- **iv**: 12 bytes, big-endian counter
  - starts at 1 (after handshake)
  - increment once per record (most-significant byte first)
  - no rollover protection — xray-core has none; 2^96 records per
    direction is fine in practice
- **aad**: the 5-byte record header (so the header is bound to the
  ciphertext — flipping any byte of the header invalidates the tag)
- **tag length**: 128 bits (16 bytes)

## 4. VLESS header (decrypted record stream)

After the handshake, the **first** record body is the VLESS request:

```
 offset   size  field
 0        1     version          = 0x00
 1        16    uuid             = the signed UUID (verified)
 17       1     addon_len        = 0 (no Flow addon; flow is "" for native)
 18       1     command          = 0x01 TCP | 0x02 UDP
 19       2     port             = big-endian
 21       1     addr_type        = 0x01 IPv4 | 0x02 domain | 0x03 IPv6
 22       ?     address          = by addr_type
```

### VLESS response

The relay's response (sent before the first data record):

```
[0x00, 0x00]   // version=0, addon_len=0
```

…sealed as one record on `key_w` with `nonce_w` (the next one after
the handshake).

## 5. UDP (DNS) framing

When command is `0x02` (Udp), record bodies are **not** raw VLESS
headers; they are `u16 len ‖ payload` packets:

```
[2B length BE] [N bytes payload]
[2B length BE] [M bytes payload]
... (one record can carry many packets)
```

Each packet is sent as a short-lived TCP request to `(host, port)`,
and the response is sealed back as a `vless://` payload.

## 6. Egress encoding recap

| `type_byte` | Meaning | Egress address |
|-------------|---------|----------------|
| 0x00        | direct  | encoded address (ignored) |
| 0x01        | proxyip | direct-first, fallback to encoded address |
| 0x02        | socks5  | tunnel through encoded address (SOCKS5) |
| 0x03        | http    | tunnel through encoded address (HTTP CONNECT) |

For types 0x01..0x03 the encoded IPv4 + port is the proxy. For 0x00 the
worker connects straight to the VLESS request's `address:port`.

## 7. Apache camouflage

Non-WS requests get a static Apache 2.4.62 (Debian) page from
`relay/static/apache_default.html`. The 404 page is
`relay/static/apache_404.html` with `{{SERVER_NAME}}` and
`{{SERVER_PORT}}` substituted from the `Host` header.

This is **not** a security boundary — it just avoids leaking
"this is a Cloudflare Worker" in the body. The real camouflage is the
VLESS Encryption layer above.
