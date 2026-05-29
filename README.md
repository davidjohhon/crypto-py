<p align="center">
  <a href="https://github.com/davidjohhon/crypto-py/blob/main/README.zh.md">🇨🇳 中文</a>
</p>

# CryptoPy

> Special thanks to [CryptoJS](https://github.com/brix/crypto-js) — this project is a Python port of their JavaScript cryptography library. All algorithm designs, API patterns, and test vectors are derived from their work.

Python cryptography library with zero external dependencies. Covers message digests (MD5, SHA-1/256/512, SM3), symmetric ciphers (AES, DES, SM4), and asymmetric cryptography (RSA, SM2, SM9). CryptoJS-compatible API.

```python
import CryptoPy

CryptoPy.MD5("message")                          # hashing
CryptoPy.SHA256("message")
enc = CryptoPy.AES.encrypt("data", "password")   # encryption
dec = CryptoPy.AES.decrypt(enc, "password")
CryptoPy.HmacSHA256("msg", "key")                # HMAC
```

## Install

```bash
pip install crypto4py
```

## Quick Start

```python
import CryptoPy
# or: from CryptoPy import AES, MD5, SHA256, SM2, RSA, enc, mode, pad

# ── Hashing ──
digest = CryptoPy.MD5("Message")
print(digest)                                   # hex: c6c2c9...
print(digest.toString(CryptoPy.enc.Base64))     # Base64
print(digest.toString(CryptoPy.enc.Hex))        # explicit hex
print(bytes(digest).hex())                      # via raw bytes

CryptoPy.SHA1("Message")
CryptoPy.SHA256("Message")
CryptoPy.SHA3("Message", {"outputLength": 256})
CryptoPy.SM3("SM3 message")                     # Chinese SM standard

# ── HMAC ──
tag = CryptoPy.HmacSHA256("Message", "Secret Key")  # → WordArray
print(tag.toString(CryptoPy.enc.Base64))               # Base64

# ── AES encryption (password-based) ──
enc = CryptoPy.AES.encrypt("My secret data", "password")
dec = CryptoPy.AES.decrypt(enc, "password")
print(CryptoPy.enc.Utf8.stringify(dec))  # "My secret data"

# ── AES encryption (custom key/IV) ──
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = CryptoPy.AES.encrypt("Message", key, {"iv": iv})
dec = CryptoPy.AES.decrypt(enc, key, {"iv": iv})

# ── SM4 (same pattern as AES) ──
enc = CryptoPy.SM4.encrypt("plaintext", "password")
dec = CryptoPy.SM4.decrypt(enc, "password")

# ── Encoders ──
words = CryptoPy.enc.Hex.parse("48656c6c6f")       # hex → WordArray
print(CryptoPy.enc.Base64.stringify(words))         # → "SGVsbG8="
print(words.toString(CryptoPy.enc.Utf8))            # → "Hello"
CryptoPy.enc.Utf8.parse("Hello")                    # str → WordArray

# ── Progressive hashing ──
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("Part 1").update("Part 2")
sha256.finalize("Part 3")

# ── Progressive HMAC ──
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "key")
hmac.update("Part 1").update("Part 2")
hmac.finalize()

# ── Progressive encryption ──
enc = CryptoPy.algo.AES.createEncryptor(key, {"iv": iv})
c1 = enc.process("Part 1")
c2 = enc.process("Part 2")
c3 = enc.finalize("Part 3")
dec = CryptoPy.algo.AES.createDecryptor(key, {"iv": iv})
p1 = dec.process(c1)
p2 = dec.process(c2)
p3 = dec.process(c3)
p4 = dec.finalize()
```

## Data Types

All data in CryptoPy is represented as **WordArray** (32-bit words + byte count), matching crypto-js exactly.

### Conversion Table

| From → To | Code | Example |
|-----------|------|---------|
| `str` → WordArray | `enc.Utf8.parse(s)` | `enc.Utf8.parse("Hello")` |
| `hex` → WordArray | `enc.Hex.parse(h)` | `enc.Hex.parse("48656c6c6f")` |
| `bytes` → WordArray | `bytes_to_wa(b)` (see example) | packs 4 bytes per 32-bit word |
| WordArray → `str` | `wa.toString(enc.Utf8)` | `wa.toString(enc.Utf8)` → `"Hello"` |
| WordArray → `hex` | `wa.toString()` or `str(wa)` | `wa.toString()` → `"48656c6c6f"` |
| WordArray → `Base64` | `wa.toString(enc.Base64)` | `wa.toString(enc.Base64)` → `"SGVsbG8="` |
| WordArray → `bytes` | `bytes(wa)` | `bytes(wa)` → `b'\\x48\\x65...'` |
| WordArray length | `len(wa)` | `len(wa)` → byte count |
| Comparison | `wa == "hex"` | hex string comparison |
| Comparison | `wa == b'\\x00'` | bytes comparison |

### Complete WordArray Example

```python
# ── Create WordArray from different sources ──
from_hex = CryptoPy.enc.Hex.parse("48656c6c6f")      # hex → WA
from_utf8 = CryptoPy.enc.Utf8.parse("Hello")          # str → WA
from_b64 = CryptoPy.enc.Base64.parse("SGVsbG8=")      # Base64 → WA
random_wa = CryptoPy.lib.WordArray.random(16)          # random bytes

# All equal: from_hex == from_utf8 == from_b64

# ── Bytes → WordArray (pack 4 bytes per 32-bit word) ──
def bytes_to_wa(b):
    words = [int.from_bytes(b[i:i+4], 'big') for i in range(0, len(b), 4)]
    return CryptoPy.lib.WordArray.create(words, len(b))

wa = bytes_to_wa(b"Hello")                          # same as enc.Utf8.parse("Hello")

# ── Output conversions ──
from_hex.toString()                                # hex: "48656c6c6f"
from_hex.toString(CryptoPy.enc.Base64)              # Base64: "SGVsbG8="
from_hex.toString(CryptoPy.enc.Utf8)               # text: "Hello"
bytes(from_hex)                                     # raw bytes

# ── Properties ──
len(from_hex)      # 5 (sigBytes)
from_hex.words     # [0x48656c6c, 0x6f000000] (padded)
from_hex.sigBytes  # 5

# ── Operations ──
cloned = from_hex.clone()
combined = cloned.concat(CryptoPy.enc.Utf8.parse(" World"))
combined.toString(CryptoPy.enc.Utf8)               # "Hello World"
```

### Common Output Patterns

| Code | Result |
|------|--------|
| `str(digest)` | `"900150983cd24fb0d6963f7d28e17f72"` (hex) |
| `digest.toString()` | same as `str()` |
| `digest.toString(CryptoPy.enc.Base64)` | `"kAFQmDzST7DWlj99KOF/cg=="` |
| `bytes(digest)` | `b'\\x90\\x01\\x50...'` (16 bytes) |
| `len(digest)` | `16` (byte count) |
| `digest == "900150983cd24fb0d6963f7d28e17f72"` | `True` (compare with hex string) |
| `digest == b'\\x90\\x01\\x50...'` | `True` (compare with bytes) |

## API Reference

### Hash Algorithms

All hashes accept `str`, `bytes`, or `WordArray` and return a **WordArray**.

| Function | Output | Default | Example |
|----------|--------|---------|---------|
| `CryptoPy.MD5(s)` | **WordArray** | hex | `CryptoPy.MD5("abc")` → `"90015098..."` |
| `CryptoPy.SHA1(s)` | **WordArray** | hex | `CryptoPy.SHA1("abc")` |
| `CryptoPy.SHA256(s)` | **WordArray** | hex | `CryptoPy.SHA256("abc")` |
| `CryptoPy.SHA224(s)` | **WordArray** | hex | `CryptoPy.SHA224("abc")` |
| `CryptoPy.SHA384(s)` | **WordArray** | hex | `CryptoPy.SHA384("abc")` |
| `CryptoPy.SHA512(s)` | **WordArray** | hex | `CryptoPy.SHA512("abc")` |
| `CryptoPy.SHA3(s, cfg)` | **WordArray** | hex | `CryptoPy.SHA3("", {"outputLength":256})` |
| `CryptoPy.RIPEMD160(s)` | **WordArray** | hex | `CryptoPy.RIPEMD160("abc")` |
| `CryptoPy.SM3(s)` | **WordArray** | hex | `CryptoPy.SM3("abc")` |

```python
# Input: str, bytes, or WordArray
digest = CryptoPy.SHA256("message")              # str → auto WordArray
digest = CryptoPy.SHA256(b"message")             # bytes → auto WordArray
digest = CryptoPy.SHA256(CryptoPy.enc.Utf8.parse("message"))  # explicit WA

# Output conversions
digest.toString()                               # hex (default)
digest.toString(CryptoPy.enc.Base64)             # Base64
bytes(digest)                                   # raw 32 bytes
len(digest)                                     # 32 (byte count)

# Input as WordArray (from raw bytes)
with open("file.bin", "rb") as f:
    digest = CryptoPy.SHA256(f.read())           # bytes auto-converted
print("SHA256:", digest)                         # hex

# Progressive API
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("chunk 1").update("chunk 2")
digest = sha256.finalize("chunk 3")
```

> **SHA3**: Two variants — `'keccak'` (default, CryptoJS compatible) and `'sha3'` (FIPS 202).
> ```python
> CryptoPy.SHA3("msg", {"outputLength": 256})                    # Keccak
> CryptoPy.SHA3("msg", {"outputLength": 256, "variant": "sha3"}) # FIPS SHA-3
> ```

| Output Method | Code | Result |
|---------------|------|--------|
| Hex string | `str(digest)` or `digest.toString()` | `"ba7816bf..."` |
| Base64 | `digest.toString(CryptoPy.enc.Base64)` | `"ungWv48Bz+pBQUDeXa4iI7ADYaO..."` |
| Raw bytes | `bytes(digest)` | `b'\\xba\\x78\\x16\\xbf...'` (32 bytes) |
| Length | `len(digest)` | `32` |

### HMAC

HMAC functions accept `str`, `bytes`, or `WordArray` for both message and key.

| Function | Return | Default | Example |
|----------|--------|---------|---------|
| `HmacMD5("m","k")` | **WordArray** | hex | `HmacMD5("msg","key")` |
| `HmacSHA1("m","k")` | **WordArray** | hex | `HmacSHA1("msg","key")` |
| `HmacSHA256("m","k")` | **WordArray** | hex | `HmacSHA256("msg","key")` |
| `HmacSHA224("m","k")` | **WordArray** | hex | |
| `HmacSHA384("m","k")` | **WordArray** | hex | |
| `HmacSHA512("m","k")` | **WordArray** | hex | |
| `HmacSHA3("m","k")` | **WordArray** | hex | |
| `HmacRIPEMD160("m","k")` | **WordArray** | hex | |
| `HmacSM3("m","k")` | **WordArray** | hex | |

```python
# Basic — message and key as strings
tag = CryptoPy.HmacSHA256("message", "secret key")

# Output conversions
tag.toString()                                # hex
tag.toString(CryptoPy.enc.Base64)             # Base64
bytes(tag)                                    # raw bytes (32 bytes)
len(tag)                                      # 32

# Bytes input
tag = CryptoPy.HmacSHA256(b"message", b"key")  # bytes auto-converted

# WordArray key
key_wa = CryptoPy.enc.Hex.parse("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
tag = CryptoPy.HmacSHA256("message", key_wa)

# Progressive
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "key")
hmac.update("part1").update("part2")
tag = hmac.finalize("part3")
```

### Ciphers

All ciphers follow `encrypt(message, key)` / `decrypt(ciphertext, key)` returning **CipherParams** / **WordArray**.

| Cipher | Type | Key size | Block size |
|--------|------|----------|------------|
| `CryptoPy.AES` | Block | 128/192/256 bits | 16 bytes |
| `CryptoPy.DES` | Block | 64 bits | 8 bytes |
| `CryptoPy.TripleDES` | Block | 128/192 bits | 8 bytes |
| `CryptoPy.SM4` | Block (SM) | 128 bits | 16 bytes |
| `CryptoPy.Rabbit` | Stream | 128 bits | — |
| `CryptoPy.RabbitLegacy` | Stream | 128 bits | — |
| `CryptoPy.RC4` | Stream | 40-2048 bits | — |
| `CryptoPy.RC4Drop` | Stream | 40-2048 bits | — |
| `CryptoPy.ZUC` | Stream (SM) | 128 bits | — |

#### Encrypt / Decrypt patterns

```python
# ── Password-based (auto key derivation via EvpKDF) ──
enc = CryptoPy.AES.encrypt("plaintext", "password")
dec = CryptoPy.AES.decrypt(enc, "password")

# Output: enc is CipherParams, dec is WordArray
str(enc)                                      # OpenSSL: "U2FsdGVkX1..."
enc.ciphertext.toString()                     # ciphertext hex
dec.toString(CryptoPy.enc.Utf8)               # "plaintext"
bytes(dec)                                    # raw bytes

# ── With custom key (WordArray) and IV ──
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = CryptoPy.AES.encrypt("message", key, {"iv": iv, "mode": CryptoPy.mode.CBC})
dec = CryptoPy.AES.decrypt(enc, key, {"iv": iv, "mode": CryptoPy.mode.CBC})

# ── SM4 (same pattern as AES) ──
enc = CryptoPy.SM4.encrypt("message", "password")
dec = CryptoPy.SM4.decrypt(enc, "password")

# ── DES / TripleDES ──
key = CryptoPy.enc.Hex.parse("0123456789abcdef")
enc = CryptoPy.DES.encrypt("plaintext", key, {"mode": CryptoPy.mode.ECB})
dec = CryptoPy.DES.decrypt(enc, key, {"mode": CryptoPy.mode.ECB})

key3 = CryptoPy.enc.Hex.parse("0123456789abcdef0123456789abcdef")  # 128-bit
enc = CryptoPy.TripleDES.encrypt("plaintext", key3, {"mode": CryptoPy.mode.ECB})
dec = CryptoPy.TripleDES.decrypt(enc, key3, {"mode": CryptoPy.mode.ECB})

# ── Stream ciphers (Rabbit, RC4, ZUC) ──
enc = CryptoPy.Rabbit.encrypt("message", "password")
dec = CryptoPy.Rabbit.decrypt(enc, "password")
# RC4 and ZUC use the same encrypt/decrypt pattern
```

#### Return Types

| Operation | Return | `str()` | `.toString(enc.Hex)` | `.toString(enc.Base64)` | `bytes()` | `.ciphertext` |
|-----------|--------|---------|---------------------|------------------------|-----------|---------------|
| `AES.encrypt("m","p")` | **CipherParams** | OpenSSL | ct hex | ct Base64 | ❌ | WordArray |
| `AES.decrypt(enc,"p")` | **WordArray** | data hex | data hex | data Base64 | raw bytes | ❌ |
| `SM4.encrypt("m","p")` | **CipherParams** | OpenSSL | ct hex | ct Base64 | ❌ | WordArray |
| `DES.encrypt("m",k)` | **CipherParams** | OpenSSL | ct hex | ct Base64 | ❌ | WordArray |
| `TripleDES.encrypt("m",k)` | **CipherParams** | OpenSSL | ct hex | ct Base64 | ❌ | WordArray |
| `Rabbit.encrypt("m","p")` | **CipherParams** | OpenSSL | ct hex | ct Base64 | ❌ | WordArray |

**CipherParams** members: `.ciphertext` (WordArray), `.iv` (WordArray), `.salt` (WordArray), `.key` (WordArray), `.toString()`

### Block Modes

| Mode | Description | Default |
|------|-------------|---------|
| `CryptoPy.mode.CBC` | Cipher Block Chaining | ✓ |
| `CryptoPy.mode.CFB` | Cipher Feedback | |
| `CryptoPy.mode.CTR` | Counter | |
| `CryptoPy.mode.ECB` | Electronic Codebook | |
| `CryptoPy.mode.OFB` | Output Feedback | |

```python
CryptoPy.AES.encrypt("msg", "pass", {"mode": CryptoPy.mode.ECB})
```

### Padding Schemes

| Scheme | Description | Default |
|--------|-------------|---------|
| `CryptoPy.pad.Pkcs7` | PKCS #5/#7 | ✓ |
| `CryptoPy.pad.AnsiX923` | ANSI X.923 | |
| `CryptoPy.pad.Iso10126` | ISO 10126 (random) | |
| `CryptoPy.pad.Iso97971` | ISO/IEC 9797-1 | |
| `CryptoPy.pad.ZeroPadding` | Zero padding | |
| `CryptoPy.pad.NoPadding` | No padding | |

### Encoders

```python
CryptoPy.enc.Hex.parse("48656c6c6f")
CryptoPy.enc.Hex.stringify(wordArray)

CryptoPy.enc.Utf8.parse("Hello")
CryptoPy.enc.Utf8.stringify(wordArray)

CryptoPy.enc.Latin1.parse("Hello")
CryptoPy.enc.Base64.parse("SGVsbG8=")
CryptoPy.enc.Base64.stringify(wordArray)
CryptoPy.enc.Base64url.parse("SGVsbG8", urlSafe=True)
CryptoPy.enc.Utf16.parse("Hello")
CryptoPy.enc.Utf16LE.parse("Hello")
```

### Hash Enum (for RSA and HMAC)

```python
# Used as the third argument in CryptoPy.RSA.sign()
CryptoPy.hash.MD5     # "MD5"
CryptoPy.hash.SHA1    # "SHA-1"
CryptoPy.hash.SHA256  # "SHA-256"
CryptoPy.hash.SHA384  # "SHA-384"
CryptoPy.hash.SHA512  # "SHA-512"
```

### Chinese National Standard (SM) Algorithms

#### SM3 — Hash (GM/T 0004-2012)

```python
CryptoPy.SM3("message")                    # 256-bit hash
CryptoPy.SM3("message") == CryptoPy.algo.SM3.create().finalize("message")
```

256-bit cryptographic hash function, equivalent to SHA-256 in security level. Standardized by the Chinese Cryptographic Standards Committee.

#### SM4 — Block Cipher (GM/T 0002-2012)

```python
CryptoPy.SM4.encrypt("message", "password")
CryptoPy.SM4.decrypt(encrypted, "password")

# With custom key
key = CryptoPy.enc.Hex.parse("0123456789ABCDEFFEDCBA9876543210")
cfg = {"mode": CryptoPy.mode.ECB, "padding": CryptoPy.pad.NoPadding}
CryptoPy.SM4.encrypt("message", key, cfg)
```

128-bit block cipher, 128-bit key, 32 rounds. Replaces AES in Chinese commercial cryptography.

#### ZUC — Stream Cipher (GM/T 0001-2012)

```python
CryptoPy.ZUC.encrypt("message", "password")
CryptoPy.ZUC.decrypt(encrypted, "password")
```

128-bit stream cipher used as the core algorithm in 4G/5G mobile communication standards.

#### SM2 — Public Key Cryptography (GM/T 0003-2012)

```python
# ── Key generation ──
sk, pk = CryptoPy.SM2.generate_keypair()     # → (WordArray, WordArray)
sk.toString()                                 # 32 bytes → 64 hex chars
pk.toString()                                 # 64 bytes → 128 hex chars

# ── Digital signature / verification ──
signature = CryptoPy.SM2.sign("message", sk)  # → WordArray (64 bytes)
assert CryptoPy.SM2.verify("message", signature, pk)

# ── Encryption / decryption ──
ciphertext = CryptoPy.SM2.encrypt("secret data", pk)  # → WordArray
plaintext = CryptoPy.SM2.decrypt(ciphertext, sk)       # → bytes

# Output conversions
signature.toString()                           # hex: 128 chars
signature.toString(CryptoPy.enc.Base64)         # Base64
bytes(signature)                                # raw 64 bytes

# ── Key persistence (hex save/load) ──
# Save keys as hex strings
sk_hex = sk.toString()   # "abc123..."
pk_hex = pk.toString()

# Load keys from hex
sk_loaded = CryptoPy.enc.Hex.parse(sk_hex)
pk_loaded = CryptoPy.enc.Hex.parse(pk_hex)
sig = CryptoPy.SM2.sign("new msg", sk_loaded)
assert CryptoPy.SM2.verify("new msg", sig, pk_loaded)
```

254-bit elliptic curve public key cryptography.

| Operation | Return Type | `.toString()` | `.toString(enc.Base64)` | `bytes()` |
|-----------|-------------|--------------|--------------------|-----------|
| `generate_keypair()` | **(WordArray, WordArray)** | `sk`: 64 hex, `pk`: 128 hex | `sk`: Base64, `pk`: Base64 | 32 + 64 bytes |
| `sign("m", sk)` | **WordArray** | 64 hex chars (r‖s) | Base64 | 64 bytes |
| `verify("m", sig, pk)` | **bool** | `True` or `False` | — | — |
| `encrypt("m", pk)` | **WordArray** | 194 hex chars (C1‖C2‖C3) | Base64 | 97 bytes |
| `decrypt(ct, sk)` | **bytes** | — | — | decrypted message |

#### SM9 — Identity-Based Cryptography (GM/T 0044-2016)

```python
# ── Setup master key ──
mpk, msk = CryptoPy.SM9.setup()              # → (WordArray, WordArray)
mpk.toString()                                # 128 bytes → 256 hex chars
msk.toString()                                # 32 bytes → 64 hex chars

# ── Generate user private key from identity ──
usk = CryptoPy.SM9.generate_user_key(msk, b"alice@example.com")  # WordArray
usk.toString()                                # 192 bytes → 384 hex chars

# ── Sign / verify ──
sig = CryptoPy.SM9.sign(b"message", usk)      # → WordArray (96 bytes)
ok  = CryptoPy.SM9.verify(b"message", sig, mpk, b"alice@example.com")

# Output conversions
sig.toString()                                # hex: 192 chars
sig.toString(CryptoPy.enc.Base64)             # Base64
bytes(sig)                                    # raw 96 bytes

# ── Key persistence (hex save/load) ──
mpk_hex = mpk.toString()
msk_hex = msk.toString()
usk_hex = usk.toString()
# Load from hex
mpk2 = CryptoPy.enc.Hex.parse(mpk_hex)
msk2 = CryptoPy.enc.Hex.parse(msk_hex)
usk2 = CryptoPy.enc.Hex.parse(usk_hex)
sig2 = CryptoPy.SM9.sign(b"msg2", usk2)
assert CryptoPy.SM9.verify(b"msg2", sig2, mpk2, b"alice@example.com")
```

Identity-based signature system. Keys derived from identity strings.

| Operation | Return Type | `.toString()` | `.bytes()` |
|-----------|-------------|--------------|-----------|
| `setup()` | **(WordArray, WordArray)** | mpk: 256 hex, msk: 64 hex | 128 + 32 bytes |
| `generate_user_key(msk, id)` | **WordArray** | 384 hex chars | 192 bytes |
| `sign("m", usk)` | **WordArray** | 192 hex chars (h‖S.x‖S.y) | 96 bytes |
| `verify("m", sig, mpk, id)` | **bool** | `True` or `False` | — |

#### RSA — Asymmetric Encryption (PKCS#1 v1.5)

```python
# ── Key generation ──
priv, pub = CryptoPy.RSA.generate_keypair(2048)  # → (WordArray, WordArray)
priv.toString()                                   # hex
pub.toString()                                    # hex

# ── Encryption / decryption ──
ct = CryptoPy.RSA.encrypt("message", pub)   # → WordArray (ciphertext)
pt = CryptoPy.RSA.decrypt(ct, priv)         # → bytes (plaintext)

ct.toString()                                 # ciphertext hex
ct.toString(CryptoPy.enc.Base64)               # ciphertext Base64
bytes(ct)                                     # raw ciphertext bytes

# ── Digital signature / verification ──
sig = CryptoPy.RSA.sign("message", priv, CryptoPy.hash.SHA256)  # WordArray
ok  = CryptoPy.RSA.verify("message", sig, pub)  # True or raises ValueError

sig.toString()                                # signature hex
sig.toString(CryptoPy.enc.Base64)             # signature Base64
bytes(sig)                                    # raw signature bytes

# ── Key persistence (hex save/load) ──
priv_hex = priv.toString()
pub_hex = pub.toString()
priv2 = CryptoPy.enc.Hex.parse(priv_hex)
pub2 = CryptoPy.enc.Hex.parse(pub_hex)
ct2 = CryptoPy.RSA.encrypt("restored", pub2)
pt2 = CryptoPy.RSA.decrypt(ct2, priv2)
print(CryptoPy.enc.Utf8.stringify(pt2))      # "restored"
```

RSA public key cryptography with PKCS#1 v1.5 padding.

| Operation | Return Type | `.toString()` | `.toString(enc.Base64)` | `bytes()` |
|-----------|-------------|--------------|--------------------|-----------|
| `generate_keypair(n)` | **(WordArray, WordArray)** | priv/pub hex | priv/pub Base64 | key bytes |
| `encrypt("m", pub)` | **WordArray** | ct hex | ct Base64 | ct bytes |
| `decrypt(ct, priv)` | **bytes** | — | — | plaintext |
| `sign("m", priv, hash)` | **WordArray** | sig hex | sig Base64 | sig bytes |
| `verify("m", sig, pub)` | **bool** | `True` / raises `ValueError` | — | — |

### Key Derivation

```python
# ── PBKDF2 (default: SHA256, 1 iteration, 128-bit key) ──
key = CryptoPy.PBKDF2("password", "salt")          # → WordArray (128-bit)
key.toString()                                      # hex
key.toString(CryptoPy.enc.Base64)                   # Base64
bytes(key)                                          # raw key bytes

# With options: 256-bit key, 10000 iterations, SHA256
key = CryptoPy.PBKDF2("password", "salt", {
    "keySize": 256 // 32,       # 256-bit
    "iterations": 10000,
    "hasher": CryptoPy.algo.SHA256,
})

# ── EvpKDF (OpenSSL EVP_BytesToKey, default: MD5) ──
key = CryptoPy.EvpKDF("password", "salt")           # → WordArray
key.toString()                                      # hex
key.toString(CryptoPy.enc.Base64)                   # Base64
```

| Operation | Return Type | `.toString()` | `.toString(enc.Base64)` | `bytes()` |
|-----------|-------------|--------------|--------------------|-----------|
| `PBKDF2("p","s")` | **WordArray** | hex | Base64 | key bytes |
| `EvpKDF("p","s")` | **WordArray** | hex | Base64 | key bytes |

### WordArray

```python
wa = CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef], 5)
wa.toString()                             # hex
wa.toString(CryptoPy.enc.Base64)          # Base64
wa.clone()
wa.concat(other)
CryptoPy.lib.WordArray.random(16)         # cryptographically random
```

### Formats & Serialization

```python
# Default OpenSSL format (Base64 with "Salted__" prefix)
enc = CryptoPy.AES.encrypt("Message", "password")
str(enc)  # "U2FsdGVkX1/..."

# Custom format
class JsonFormatter:
    @staticmethod
    def stringify(cp):
        import json
        obj = {"ct": cp.ciphertext.toString(CryptoPy.enc.Base64)}
        if hasattr(cp, 'iv') and cp.iv:
            obj["iv"] = cp.iv.toString()
        if hasattr(cp, 'salt') and cp.salt:
            obj["s"] = cp.salt.toString()
        return json.dumps(obj)

    @staticmethod
    def parse(s):
        import json
        obj = json.loads(s)
        cp = CryptoPy.lib.CipherParams.create({
            "ciphertext": CryptoPy.enc.Base64.parse(obj["ct"]),
        })
        if "iv" in obj:
            cp.iv = CryptoPy.enc.Hex.parse(obj["iv"])
        if "s" in obj:
            cp.salt = CryptoPy.enc.Hex.parse(obj["s"])
        return cp

enc = CryptoPy.AES.encrypt("Message", "password", {"format": JsonFormatter})
dec = CryptoPy.AES.decrypt(enc, "password", {"format": JsonFormatter})
```

## Real-World Usage

### File Integrity Check (MD5 / SHA256 / SM3)

```python
import CryptoPy

with open("file.bin", "rb") as f:
    data = f.read()

# Hash raw bytes directly (auto-converted to WordArray)
digest = CryptoPy.SHA256(data)                   # → WordArray
print("SHA256:", digest)                         # hex
print("SHA256:", digest.toString(CryptoPy.enc.Base64))  # Base64

# SM3 (Chinese standard)
digest = CryptoPy.SM3(data)
print("SM3:", digest)

# Explicit WordArray from bytes (pack 4 bytes per word)
def bytes_to_wa(b):
    words = [int.from_bytes(b[i:i+4], 'big') for i in range(0, len(b), 4)]
    return CryptoPy.lib.WordArray.create(words, len(b))

wa = bytes_to_wa(data)
digest = CryptoPy.MD5(wa)
print("MD5:", digest)
```

### HMAC for API Authentication

```python
import CryptoPy, time

# Server-side: generate HMAC token
secret = "api-secret-key"
message = f"user=alice&time={int(time.time())}"
token = CryptoPy.HmacSHA256(message, secret)
print("Auth header:", token.toString(CryptoPy.enc.Base64))

# Client-side: verify
expected = CryptoPy.HmacSHA256(message, secret)
if token == expected:
    print("✓ Valid token")
```

### Password Hashing (PBKDF2)

```python
import CryptoPy

salt = CryptoPy.lib.WordArray.random(16)
key = CryptoPy.PBKDF2("user_password", salt, {
    "keySize": 256 // 32,       # 256-bit key
    "iterations": 10000,
    "hasher": CryptoPy.algo.SHA256,
})
print("Derived key:", key.toString(CryptoPy.enc.Base64))
```

### PBKDF2 + AES Combined

```python
import CryptoPy

# Derive AES key from password
salt = CryptoPy.lib.WordArray.random(16)
aes_key = CryptoPy.PBKDF2("my password", salt, {
    "keySize": 256 // 32, "iterations": 10000,
})

# Encrypt using derived key
iv = CryptoPy.lib.WordArray.random(16)
ct = CryptoPy.AES.encrypt("Sensitive data", aes_key, {"iv": iv})

# Store as JSON
import json
stored = json.dumps({
    "salt": salt.toString(),
    "iv": iv.toString(),
    "ct": str(ct),
})

# Decrypt
loaded = json.loads(stored)
aes_key2 = CryptoPy.PBKDF2("my password",
    CryptoPy.enc.Hex.parse(loaded["salt"]),
    {"keySize": 256 // 32, "iterations": 10000})
iv2 = CryptoPy.enc.Hex.parse(loaded["iv"])
dec = CryptoPy.AES.decrypt(loaded["ct"], aes_key2, {"iv": iv2})
print(CryptoPy.enc.Utf8.stringify(dec))  # "Sensitive data"
```

### SM2 Key Persistence (hex save/load)

```python
import CryptoPy

# Generate and save
sk, pk = CryptoPy.SM2.generate_keypair()
with open("sm2_private.key", "w") as f:
    f.write(sk.toString())
with open("sm2_public.key", "w") as f:
    f.write(pk.toString())

# Load and use
sk_hex = open("sm2_private.key").read()
pk_hex = open("sm2_public.key").read()
sk2 = CryptoPy.enc.Hex.parse(sk_hex)
pk2 = CryptoPy.enc.Hex.parse(pk_hex)

sig = CryptoPy.SM2.sign("loaded key test", sk2)
assert CryptoPy.SM2.verify("loaded key test", sig, pk2)
print("SM2 keys loaded and verified")
```

### SM9 Identity-Based Signature

```python
import CryptoPy

# Authority sets up master key
mpk, msk = CryptoPy.SM9.setup()

# Authority generates user key for Alice
alice_usk = CryptoPy.SM9.generate_user_key(msk, b"alice@company.com")

# Alice signs a document
doc = b"Contract #1234 - Payment approved"
sig = CryptoPy.SM9.sign(doc, alice_usk)

# Anyone with mpk can verify Alice's signature
ok = CryptoPy.SM9.verify(doc, sig, mpk, b"alice@company.com")
print(f"Alice's signature: {'✓ valid' if ok else '✗ invalid'}")
```

### RSA Encrypted File Storage

```python
import CryptoPy

# Generate key pair
priv, pub = CryptoPy.RSA.generate_keypair(2048)

# Encrypt with public key
ct = CryptoPy.RSA.encrypt(b"Secret message", pub)
with open("rsa_encrypted.bin", "wb") as f:
    f.write(bytes(ct))

# Decrypt with private key
ct_data = open("rsa_encrypted.bin", "rb").read()
pt = CryptoPy.RSA.decrypt(ct_data, priv)
print("Decrypted:", pt)
```

### Cross-Language: Encrypt with CryptoJS, Decrypt with CryptoPy

```javascript
// JavaScript (CryptoJS)
var enc = CryptoJS.AES.encrypt("Hello", "password");
console.log(enc.toString());
// Output: U2FsdGVkX1/...
```

```python
# Python (CryptoPy)
import CryptoPy
enc = "U2FsdGVkX1/..."  # paste the output above
dec = CryptoPy.AES.decrypt(enc, "password")
print(CryptoPy.enc.Utf8.stringify(dec))
# Output: Hello
```

## CryptoJS API Mapping

| CryptoJS | CryptoPy |
|----------|----------|
| `CryptoJS.MD5("msg")` | `CryptoPy.MD5("msg")` |
| `CryptoJS.SHA256("msg")` | `CryptoPy.SHA256("msg")` |
| `CryptoJS.HmacSHA256("msg","key")` | `CryptoPy.HmacSHA256("msg","key")` |
| `CryptoJS.AES.encrypt("m","p")` | `CryptoPy.AES.encrypt("m","p")` |
| `CryptoJS.AES.decrypt(e,"p")` | `CryptoPy.AES.decrypt(e,"p")` |
| `CryptoJS.enc.Utf8.parse("s")` | `CryptoPy.enc.Utf8.parse("s")` |
| `CryptoJS.enc.Base64.stringify(w)` | `CryptoPy.enc.Base64.stringify(w)` |
| `CryptoJS.lib.WordArray.create([...])` | `CryptoPy.lib.WordArray.create([...])` |
| `CryptoJS.algo.SHA256.create()` | `CryptoPy.algo.SHA256.create()` |
| `CryptoJS.algo.HMAC.create(...)` | `CryptoPy.algo.HMAC.create(...)` |
| `CryptoJS.mode.CBC` | `CryptoPy.mode.CBC` |
| `CryptoJS.pad.Pkcs7` | `CryptoPy.pad.Pkcs7` |
| `CryptoJS.format.OpenSSL` | `CryptoPy.format.OpenSSL` |
| `CryptoJS.kdf.OpenSSL.execute(...)` | `CryptoPy.kdf.OpenSSL.execute(...)` |
| `CryptoJS.PBKDF2("p","s")` | `CryptoPy.PBKDF2("p","s")` |
| `CryptoJS.lib.WordArray.random(16)` | `CryptoPy.lib.WordArray.random(16)` |

## Development

```bash
# Run tests
PYTHONPATH=src python3 tests/test_all.py

# Build
python3 -m build --sdist

# Publish
python3 -m twine upload dist/*
```

## Standards Compliance

Comprehensive cross-validation against multiple third-party libraries:
- **Python stdlib**: hashlib, hmac, base64
- **Python packages**: pycryptodome, gmssl-python, gmalg
- **JavaScript (npm)**: crypto-js, node-forge, @li0ard/zuc, GmSSL-JS
- **C library**: GmSSL (compiled reference implementation)
- **Node.js built-in**: crypto module

Full report: `demo/cross_validate_report.md`.

| Algorithm Group | Test Vectors | hashlib/hmac | pycryptodome | gmssl-python | Status |
|---|---|---|---|---|---|
| MD5, SHA-1, SHA-256/384/512 | ✓ | ✓ | ✓ | N/A | ✅ Verified |
| SHA224, RIPEMD160 | ✓ | ✓ | ✓ | N/A | ✅ Verified |
| SHA3 (Keccak / FIPS) | ✓ | ✓ | ✓ (sha3) | N/A | ✅ Both supported |
| HMAC (all variants) | ✓ | ✓ | ✓ | N/A | ✅ Verified |
| AES (ECB/CBC/CFB/OFB/CTR) | ✓ | N/A | ✓ | N/A | ✅ Verified |
| DES, TripleDES | ✓ | N/A | ✓ | N/A | ✅ Verified |
| PBKDF2, EvpKDF | ✓ | ✓ | N/A | N/A | ✅ Verified |
| SM3 | ✓ | N/A | N/A | ✓ | ✅ Verified |
| SM4 | ✓ | N/A | N/A | ✓ | ✅ Verified |
| SM2 | ✓ | N/A | N/A | ✓ | ✅ Cross-verified |
| SM9 | ✓ | [GmSSL-JS](https://github.com/guanzhi/GmSSL-JS), [gmalg](https://github.com/ww-rm/gmalg) | N/A | N/A | ✅ Cross-verified (full sign/verify interop with GmSSL-JS) |
| ZUC | ✓ | [@li0ard/zuc](https://github.com/li0ard/zuc), [gmalg](https://github.com/ww-rm/gmalg) | N/A | N/A | ✅ Cross-verified (GmSSL C, @li0ard/zuc, gmalg all match) |
| RSA (PKCS#1 v1.5) | ✓ | N/A | ✓ | N/A | ✅ Cross-verified |
| Progressive API | ✓ | N/A | N/A | N/A | ✅ Verified |
| Encoders (Base64, Hex, Utf8) | ✓ | ✓ | N/A | N/A | ✅ Verified |

## References

| Algorithm Group | Source |
|-----------------|--------|
| Base library (MD5, SHA, AES, etc.) | [brix/crypto-js](https://github.com/brix/crypto-js) |
| RSA (PKCS#1 v1.5) | [sybrenstuvel/python-rsa](https://github.com/sybrenstuvel/python-rsa) |
| SM2 / SM3 / SM4 / SM9 | [guanzhi/GmSSL](https://github.com/guanzhi/GmSSL) (C), [GmSSL-JS](https://github.com/guanzhi/GmSSL-JS) (JS) |
| SM9 | [gmalg](https://github.com/ww-rm/gmalg) (Python) |
| ZUC | [@li0ard/zuc](https://github.com/li0ard/zuc) (TS), [gmalg](https://github.com/ww-rm/gmalg) (Python) |
| RSA | [node-forge](https://github.com/digitalbazaar/forge) (JS), [pycryptodome](https://www.pycryptodome.org) (Python) |
| AES, DES, TripleDES | Node.js built-in `crypto`, [crypto-js](https://github.com/brix/crypto-js) (JS) |
| Rabbit, RC4 | [crypto-js](https://github.com/brix/crypto-js) (JS) |
| SHA1, MD5, HMAC | Node.js built-in `crypto` |
| SM9 (R-ate pairing) | [guanzhi/GmSSL](https://github.com/guanzhi/GmSSL) |

## License

MIT

---

*Found a bug? Open an issue → [github.com/davidjohhon/crypto-py/issues](https://github.com/davidjohhon/crypto-py/issues)*
