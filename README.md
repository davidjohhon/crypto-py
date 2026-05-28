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

# --- Hashing ---
digest = CryptoPy.MD5("Message")
print(digest)                                   # hex string: c6c2c9...
print(digest.toString(CryptoPy.enc.Base64))     # Base64
print(digest.toString(CryptoPy.enc.Hex))        # explicit Hex

CryptoPy.SHA1("Message")
CryptoPy.SHA256("Message")
CryptoPy.SHA3("Message", {"outputLength": 256})

# --- HMAC ---
CryptoPy.HmacSHA256("Message", "Secret Key")

# --- AES encryption ---
enc = CryptoPy.AES.encrypt("My secret data", "password")
dec = CryptoPy.AES.decrypt(enc, "password")
print(CryptoPy.enc.Utf8.stringify(dec))  # "My secret data"

# With custom key and IV
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = CryptoPy.AES.encrypt("Message", key, {"iv": iv})
dec = CryptoPy.AES.decrypt(enc, key, {"iv": iv})

# --- Encoders ---
words = CryptoPy.enc.Hex.parse("48656c6c6f")
CryptoPy.enc.Base64.stringify(words)
CryptoPy.enc.Utf8.parse("Hello")

# --- Progressive hashing ---
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("Part 1").update("Part 2")
sha256.finalize("Part 3")

# --- Progressive HMAC ---
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "key")
hmac.update("Part 1").update("Part 2")
hmac.finalize()

# --- Progressive encryption ---
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

## API Reference

### Hash Algorithms

| Function | Output | Example |
|----------|--------|---------|
| `CryptoPy.MD5(s)` | 128 bits | `CryptoPy.MD5("abc")` |
| `CryptoPy.SHA1(s)` | 160 bits | `CryptoPy.SHA1("abc")` |
| `CryptoPy.SHA256(s)` | 256 bits | `CryptoPy.SHA256("abc")` |
| `CryptoPy.SHA224(s)` | 224 bits | `CryptoPy.SHA224("abc")` |
| `CryptoPy.SHA384(s)` | 384 bits | `CryptoPy.SHA384("abc")` |
| `CryptoPy.SHA512(s)` | 512 bits | `CryptoPy.SHA512("abc")` |
| `CryptoPy.SHA3(s, cfg)` | configurable | `CryptoPy.SHA3("", {"outputLength":256})` |

> **SHA3**: Two variants available — default `'keccak'` (CryptoJS compatible) and `'sha3'` (FIPS 202, hashlib compatible). Only the domain separation byte differs (0x01 vs 0x06).
> ```python
> CryptoPy.SHA3("msg", {"outputLength": 256})                    # Keccak (default)
> CryptoPy.SHA3("msg", {"outputLength": 256, "variant": "sha3"}) # FIPS SHA-3
> ```

### HMAC

```python
CryptoPy.HmacMD5("message", "key")
CryptoPy.HmacSHA1("message", "key")
CryptoPy.HmacSHA256("message", "key")
CryptoPy.HmacSHA224("message", "key")
CryptoPy.HmacSHA384("message", "key")
CryptoPy.HmacSHA512("message", "key")
CryptoPy.HmacSHA3("message", "key")
CryptoPy.HmacRIPEMD160("message", "key")
CryptoPy.HmacSM3("message", "key")
```

### Ciphers

| Cipher | Type | Key size |
|--------|------|----------|
| `CryptoPy.AES` | Block | 128/192/256 bits |
| `CryptoPy.DES` | Block | 64 bits |
| `CryptoPy.TripleDES` | Block | 128/192 bits |
| `CryptoPy.Rabbit` | Stream | 128 bits |
| `CryptoPy.RabbitLegacy` | Stream | 128 bits |
| `CryptoPy.RC4` | Stream | 40-2048 bits |
| `CryptoPy.RC4Drop` | Stream | 40-2048 bits |
| `CryptoPy.SM4` | Block (SM) | 128 bits |
| `CryptoPy.ZUC` | Stream (SM) | 128 bits |

All symmetric ciphers share the same API:

```python
enc = CryptoPy.AES.encrypt("plaintext", "password")
dec = CryptoPy.AES.decrypt(enc, "password")

# SM4 and ZUC support the same pattern
enc = CryptoPy.SM4.encrypt("plaintext", "password")
dec = CryptoPy.SM4.decrypt(enc, "password")
```

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
# Generate key pair
sk, pk = CryptoPy.SM2.generate_keypair()

# Digital signature / verification
signature = CryptoPy.SM2.sign(sk, "message")
assert CryptoPy.SM2.verify(pk, "message", signature)

# Encryption / decryption
ciphertext = CryptoPy.SM2.encrypt(pk, "secret data")
plaintext = CryptoPy.SM2.decrypt(sk, ciphertext)
```

254-bit elliptic curve public key cryptography. Supports digital signature, key exchange, and data encryption. Replaces RSA in Chinese standards.

| Output | Size | Format |
|--------|------|--------|
| `sk` | 32 bytes | scalar d |
| `pk` | 64 bytes | `Q.x \|\| Q.y` (G affine) |
| `sig` | 64 bytes | `r \|\| s` |
| `ct` | 97 bytes | `C1 \|\| C2 \|\| C3` |

```python
sk.hex()   # 32 bytes → 64 chars
pk.hex()   # 64 bytes → 128 chars
```

#### SM9 — Identity-Based Cryptography (GM/T 0044-2016)

```python
# Setup master key
master_pk, master_sk = CryptoPy.SM9.setup()

# Generate user private key from identity
user_sk = CryptoPy.SM9.generate_user_key(master_sk, "alice@example.com")

# Sign / verify
sig = CryptoPy.SM9.sign(user_sk, "message")
CryptoPy.SM9.verify(master_pk, "alice@example.com", "message", sig)
```

Identity-based signature system. Eliminates the need for public key certificates by deriving keys from user identity strings (email, phone, etc.). Full R-ate pairing over BN curves with zero third-party dependencies. Ported from GmSSL.

| Output | Size | Format |
|--------|------|--------|
| `mpk` | 128 bytes | `X.a0 \|\| X.a1 \|\| Y.a0 \|\| Y.a1` (G₂ affine) |
| `msk` | 32 bytes | scalar mod N |
| `usk` | 192 bytes | `usk.X \|\| usk.Y (G₁ affine) \|\| mpk` |
| `sig` | 96 bytes | `h \|\| S.X \|\| S.Y` |

```python
mpk.hex()   # -> "hex string"  (128 bytes → 256 chars)
msk.hex()   # -> "hex string"  (32 bytes → 64 chars)
usk.hex()   # -> "hex string"  (192 bytes → 384 chars)
```

#### RSA — Asymmetric Encryption (PKCS#1 v1.5)

```python
# Generate key pair
priv, pub = CryptoPy.RSA.generate_keypair(2048)

# Encryption / decryption
ct = CryptoPy.RSA.encrypt("message", pub)
pt = CryptoPy.RSA.decrypt(ct, priv)

# Digital signature / verification
sig = CryptoPy.RSA.sign("message", priv, CryptoPy.hash.SHA256)
ok  = CryptoPy.RSA.verify("message", sig, pub)  # returns hash name
```

RSA public key cryptography with PKCS#1 v1.5 padding. Supports MD5, SHA-1, SHA-256, SHA-384, SHA-512 for signatures. Uses Chinese Remainder Theorem for fast decryption. Zero external dependencies.

| Output | Size | Format |
|--------|------|--------|
| `pub` | ~key/4 bytes | `nbits(2) \|\| n \|\| e` |
| `priv` | ~3×key/4 bytes | `nbits(2) \|\| n \|\| e \|\| d \|\| p \|\| q \|\| ...` |

```python
pub.hex()   # 512-bit key → ~130 chars, 2048-bit → ~520 chars
priv.hex()  # 512-bit key → ~378 chars, 2048-bit → ~1540 chars
```

### Key Derivation

```python
# PBKDF2 (default: SHA256, 1 iteration)
CryptoPy.PBKDF2("password", "salt")
CryptoPy.PBKDF2("password", "salt", {"keySize": 256//32, "iterations": 1000})

# EvpKDF (OpenSSL EVP_BytesToKey, default: MD5)
CryptoPy.EvpKDF("password", "salt")
CryptoPy.EvpKDF("password", "salt", {"keySize": 256//32})
```

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

### File Integrity Check (MD5/SHA256)

```python
import CryptoPy

with open("file.bin", "rb") as f:
    data = f.read()

# Hash as WordArray from raw bytes
wa = CryptoPy.lib.WordArray.create(list(data), len(data))
digest = CryptoPy.SHA256(wa)
print("SHA256:", digest)
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

### Encrypted File Storage

```python
import CryptoPy

password = "strong-password"
plaintext = "Sensitive data to encrypt"

# Encrypt
encrypted = CryptoPy.AES.encrypt(plaintext, password)
# Store as Base64 string
with open("secret.enc", "w") as f:
    f.write(str(encrypted))

# Decrypt
with open("secret.enc") as f:
    data = f.read()
decrypted = CryptoPy.AES.decrypt(data, password)
print(CryptoPy.enc.Utf8.stringify(decrypted))
```

### Streaming Hash

```python
import CryptoPy

sha256 = CryptoPy.algo.SHA256.create()
with open("largefile.bin", "rb") as f:
    for chunk in iter(lambda: f.read(8192), b""):
        wa = CryptoPy.lib.WordArray.create(list(chunk), len(chunk))
        sha256.update(wa)
print("File SHA256:", sha256.finalize())
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

103 cross-validation tests against Python stdlib (hashlib, hmac), pycryptodome, and gmssl-python. Full report: `demo/cross_validate_report.md`.

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
| SM2, SM9, ZUC | ✓ | N/A | N/A | N/A | ✅ Self-consistent |
| RSA (PKCS#1 v1.5) | ✓ | N/A | ✓ | N/A | ✅ Cross-verified |
| Progressive API | ✓ | N/A | N/A | N/A | ✅ Verified |
| Encoders (Base64, Hex, Utf8) | ✓ | ✓ | N/A | N/A | ✅ Verified |

## References

| Algorithm Group | Source |
|-----------------|--------|
| Base library (MD5, SHA, AES, etc.) | [brix/crypto-js](https://github.com/brix/crypto-js) |
| RSA (PKCS#1 v1.5) | [sybrenstuvel/python-rsa](https://github.com/sybrenstuvel/python-rsa) |
| SM2 / SM3 / SM4 / ZUC | [guanzhi/GmSSL](https://github.com/guanzhi/GmSSL) |
| SM9 (R-ate pairing) | [guanzhi/GmSSL](https://github.com/guanzhi/GmSSL) |

## License

MIT

---

*Found a bug? Open an issue → [github.com/davidjohhon/crypto-py/issues](https://github.com/davidjohhon/crypto-py/issues)*
