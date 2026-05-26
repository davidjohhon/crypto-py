<p align="center">
  <a href="https://github.com/davidjohhon/crypto-py/blob/main/README.zh.md">🇨🇳 中文</a>
</p>

# Crypto

> 🙏 Special thanks to the [CryptoJS](https://github.com/brix/crypto-js) team — this project is a Python port of their excellent JavaScript cryptography library. All algorithm designs, API patterns, and test vectors are derived from their work.

Python port of [CryptoJS](https://github.com/brix/crypto-js) — standard and secure cryptographic algorithms with the same API. Zero external dependencies.

```python
import Crypto

Crypto.MD5("message")                          # hashing
Crypto.SHA256("message")
enc = Crypto.AES.encrypt("data", "password")   # encryption
dec = Crypto.AES.decrypt(enc, "password")
Crypto.HmacSHA256("msg", "key")                # HMAC
```

## Install

```bash
pip install crypto4py
```

## Quick Start

```python
import Crypto

# --- Hashing ---
digest = Crypto.MD5("Message")
print(digest)                                   # hex string: c6c2c9...
print(digest.toString(Crypto.enc.Base64))     # Base64
print(digest.toString(Crypto.enc.Hex))        # explicit Hex

Crypto.SHA1("Message")
Crypto.SHA256("Message")
Crypto.SHA3("Message", {"outputLength": 256})

# --- HMAC ---
Crypto.HmacSHA256("Message", "Secret Key")

# --- AES encryption ---
enc = Crypto.AES.encrypt("My secret data", "password")
dec = Crypto.AES.decrypt(enc, "password")
print(Crypto.enc.Utf8.stringify(dec))  # "My secret data"

# With custom key and IV
key = Crypto.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = Crypto.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = Crypto.AES.encrypt("Message", key, {"iv": iv})
dec = Crypto.AES.decrypt(enc, key, {"iv": iv})

# --- Encoders ---
words = Crypto.enc.Hex.parse("48656c6c6f")
Crypto.enc.Base64.stringify(words)
Crypto.enc.Utf8.parse("Hello")

# --- Progressive hashing ---
sha256 = Crypto.algo.SHA256.create()
sha256.update("Part 1").update("Part 2")
sha256.finalize("Part 3")

# --- Progressive HMAC ---
hmac = Crypto.algo.HMAC.create(Crypto.algo.SHA256, "key")
hmac.update("Part 1").update("Part 2")
hmac.finalize()

# --- Progressive encryption ---
enc = Crypto.algo.AES.createEncryptor(key, {"iv": iv})
c1 = enc.process("Part 1")
c2 = enc.process("Part 2")
c3 = enc.finalize("Part 3")

dec = Crypto.algo.AES.createDecryptor(key, {"iv": iv})
p1 = dec.process(c1)
p2 = dec.process(c2)
p3 = dec.process(c3)
p4 = dec.finalize()
```

## API Reference

### Hash Algorithms

| Function | Output | Example |
|----------|--------|---------|
| `Crypto.MD5(s)` | 128 bits | `Crypto.MD5("abc")` |
| `Crypto.SHA1(s)` | 160 bits | `Crypto.SHA1("abc")` |
| `Crypto.SHA256(s)` | 256 bits | `Crypto.SHA256("abc")` |
| `Crypto.SHA224(s)` | 224 bits | `Crypto.SHA224("abc")` |
| `Crypto.SHA384(s)` | 384 bits | `Crypto.SHA384("abc")` |
| `Crypto.SHA512(s)` | 512 bits | `Crypto.SHA512("abc")` |
| `Crypto.SHA3(s, cfg)` | configurable | `Crypto.SHA3("", {"outputLength":256})` |
| `Crypto.RIPEMD160(s)` | 160 bits | `Crypto.RIPEMD160("abc")` |
| `Crypto.SM3(s)` | 256 bits | `Crypto.SM3("abc")` |

**Note**: `SHA3` implements raw Keccak[c=2d] (matching CryptoJS), not FIPS 202 SHA-3. Output differs from `hashlib.sha3_512()`.

### HMAC

```python
Crypto.HmacMD5("message", "key")
Crypto.HmacSHA1("message", "key")
Crypto.HmacSHA256("message", "key")
Crypto.HmacSHA224("message", "key")
Crypto.HmacSHA384("message", "key")
Crypto.HmacSHA512("message", "key")
Crypto.HmacSHA3("message", "key")
Crypto.HmacRIPEMD160("message", "key")
```

### Ciphers

| Cipher | Type | Key size |
|--------|------|----------|
| `Crypto.AES` | Block | 128/192/256 bits |
| `Crypto.DES` | Block | 64 bits |
| `Crypto.TripleDES` | Block | 128/192 bits |
| `Crypto.Rabbit` | Stream | 128 bits |
| `Crypto.RabbitLegacy` | Stream | 128 bits |
| `Crypto.RC4` | Stream | 40-2048 bits |
| `Crypto.RC4Drop` | Stream | 40-2048 bits |
| `Crypto.SM4` | Block (SM) | 128 bits |
| `Crypto.ZUC` | Stream (SM) | 128 bits |

All symmetric ciphers share the same API:

```python
enc = Crypto.AES.encrypt("plaintext", "password")
dec = Crypto.AES.decrypt(enc, "password")

# SM4 and ZUC support the same pattern
enc = Crypto.SM4.encrypt("plaintext", "password")
dec = Crypto.SM4.decrypt(enc, "password")
```

### Block Modes

| Mode | Description | Default |
|------|-------------|---------|
| `Crypto.mode.CBC` | Cipher Block Chaining | ✓ |
| `Crypto.mode.CFB` | Cipher Feedback | |
| `Crypto.mode.CTR` | Counter | |
| `Crypto.mode.ECB` | Electronic Codebook | |
| `Crypto.mode.OFB` | Output Feedback | |

```python
Crypto.AES.encrypt("msg", "pass", {"mode": Crypto.mode.ECB})
```

### Padding Schemes

| Scheme | Description | Default |
|--------|-------------|---------|
| `Crypto.pad.Pkcs7` | PKCS #5/#7 | ✓ |
| `Crypto.pad.AnsiX923` | ANSI X.923 | |
| `Crypto.pad.Iso10126` | ISO 10126 (random) | |
| `Crypto.pad.Iso97971` | ISO/IEC 9797-1 | |
| `Crypto.pad.ZeroPadding` | Zero padding | |
| `Crypto.pad.NoPadding` | No padding | |

### Encoders

```python
Crypto.enc.Hex.parse("48656c6c6f")
Crypto.enc.Hex.stringify(wordArray)

Crypto.enc.Utf8.parse("Hello")
Crypto.enc.Utf8.stringify(wordArray)

Crypto.enc.Latin1.parse("Hello")
Crypto.enc.Base64.parse("SGVsbG8=")
Crypto.enc.Base64.stringify(wordArray)
Crypto.enc.Base64url.parse("SGVsbG8", urlSafe=True)
Crypto.enc.Utf16.parse("Hello")
Crypto.enc.Utf16LE.parse("Hello")

### Chinese National Standard (SM) Algorithms

#### SM3 — Hash (GM/T 0004-2012)

```python
Crypto.SM3("message")                    # 256-bit hash
Crypto.SM3("message") == Crypto.algo.SM3.create().finalize("message")
```

256-bit cryptographic hash function, equivalent to SHA-256 in security level. Standardized by the Chinese Cryptographic Standards Committee.

#### SM4 — Block Cipher (GM/T 0002-2012)

```python
Crypto.SM4.encrypt("message", "password")
Crypto.SM4.decrypt(encrypted, "password")

# With custom key
key = Crypto.enc.Hex.parse("0123456789ABCDEFFEDCBA9876543210")
cfg = {"mode": Crypto.mode.ECB, "padding": Crypto.pad.NoPadding}
Crypto.SM4.encrypt("message", key, cfg)
```

128-bit block cipher, 128-bit key, 32 rounds. Replaces AES in Chinese commercial cryptography.

#### ZUC — Stream Cipher (GM/T 0001-2012)

```python
Crypto.ZUC.encrypt("message", "password")
Crypto.ZUC.decrypt(encrypted, "password")
```

128-bit stream cipher used as the core algorithm in 4G/5G mobile communication standards.

#### SM2 — Public Key Cryptography (GM/T 0003-2012)

```python
# Generate key pair
sk, pk = Crypto.SM2.generate_keypair()

# Digital signature / verification
signature = Crypto.SM2.sign(sk, "message")
assert Crypto.SM2.verify(pk, "message", signature)

# Encryption / decryption
ciphertext = Crypto.SM2.encrypt(pk, "secret data")
plaintext = Crypto.SM2.decrypt(sk, ciphertext)
```

254-bit elliptic curve public key cryptography. Supports digital signature, key exchange, and data encryption. Replaces RSA in Chinese standards.

#### SM9 — Identity-Based Cryptography (GM/T 0044-2016)

```python
# Setup master key
master_pk, master_sk = Crypto.SM9.setup()

# Generate user private key from identity
user_sk = Crypto.SM9.generate_user_key(master_sk, "alice@example.com")

# Sign / verify
sig = Crypto.SM9.sign(user_sk, "message")
Crypto.SM9.verify(master_pk, "alice@example.com", "message", sig)
```

Identity-based signature system. Eliminates the need for public key certificates by deriving keys from user identity strings (email, phone, etc.).

> **Note**: SM9 verification requires bilinear pairings (Tate pairing over BN curves), which is partially implemented. Signature generation works correctly.

### Key Derivation

```python
# PBKDF2 (default: SHA256, 1 iteration)
Crypto.PBKDF2("password", "salt")
Crypto.PBKDF2("password", "salt", {"keySize": 256//32, "iterations": 1000})

# EvpKDF (OpenSSL EVP_BytesToKey, default: MD5)
Crypto.EvpKDF("password", "salt")
Crypto.EvpKDF("password", "salt", {"keySize": 256//32})
```

### WordArray

```python
wa = Crypto.lib.WordArray.create([0x12345678, 0x90abcdef], 5)
wa.toString()                             # hex
wa.toString(Crypto.enc.Base64)          # Base64
wa.clone()
wa.concat(other)
Crypto.lib.WordArray.random(16)         # cryptographically random
```

### Formats & Serialization

```python
# Default OpenSSL format (Base64 with "Salted__" prefix)
enc = Crypto.AES.encrypt("Message", "password")
str(enc)  # "U2FsdGVkX1/..."

# Custom format
class JsonFormatter:
    @staticmethod
    def stringify(cp):
        import json
        obj = {"ct": cp.ciphertext.toString(Crypto.enc.Base64)}
        if hasattr(cp, 'iv') and cp.iv:
            obj["iv"] = cp.iv.toString()
        if hasattr(cp, 'salt') and cp.salt:
            obj["s"] = cp.salt.toString()
        return json.dumps(obj)

    @staticmethod
    def parse(s):
        import json
        obj = json.loads(s)
        cp = Crypto.lib.CipherParams.create({
            "ciphertext": Crypto.enc.Base64.parse(obj["ct"]),
        })
        if "iv" in obj:
            cp.iv = Crypto.enc.Hex.parse(obj["iv"])
        if "s" in obj:
            cp.salt = Crypto.enc.Hex.parse(obj["s"])
        return cp

enc = Crypto.AES.encrypt("Message", "password", {"format": JsonFormatter})
dec = Crypto.AES.decrypt(enc, "password", {"format": JsonFormatter})
```

## Real-World Usage

### File Integrity Check (MD5/SHA256)

```python
import Crypto

with open("file.bin", "rb") as f:
    data = f.read()

# Hash as WordArray from raw bytes
wa = Crypto.lib.WordArray.create(list(data), len(data))
digest = Crypto.SHA256(wa)
print("SHA256:", digest)
```

### Password Hashing (PBKDF2)

```python
import Crypto

salt = Crypto.lib.WordArray.random(16)
key = Crypto.PBKDF2("user_password", salt, {
    "keySize": 256 // 32,       # 256-bit key
    "iterations": 10000,
    "hasher": Crypto.algo.SHA256,
})
print("Derived key:", key.toString(Crypto.enc.Base64))
```

### Encrypted File Storage

```python
import Crypto

password = "strong-password"
plaintext = "Sensitive data to encrypt"

# Encrypt
encrypted = Crypto.AES.encrypt(plaintext, password)
# Store as Base64 string
with open("secret.enc", "w") as f:
    f.write(str(encrypted))

# Decrypt
with open("secret.enc") as f:
    data = f.read()
decrypted = Crypto.AES.decrypt(data, password)
print(Crypto.enc.Utf8.stringify(decrypted))
```

### Streaming Hash

```python
import Crypto

sha256 = Crypto.algo.SHA256.create()
with open("largefile.bin", "rb") as f:
    for chunk in iter(lambda: f.read(8192), b""):
        wa = Crypto.lib.WordArray.create(list(chunk), len(chunk))
        sha256.update(wa)
print("File SHA256:", sha256.finalize())
```

### Cross-Language: Encrypt with CryptoJS, Decrypt with Crypto

```javascript
// JavaScript (CryptoJS)
var enc = CryptoJS.AES.encrypt("Hello", "password");
console.log(enc.toString());
// Output: U2FsdGVkX1/...
```

```python
# Python (Crypto)
import Crypto
enc = "U2FsdGVkX1/..."  # paste the output above
dec = Crypto.AES.decrypt(enc, "password")
print(Crypto.enc.Utf8.stringify(dec))
# Output: Hello
```

## CryptoJS API Mapping

| CryptoJS | Crypto |
|----------|----------|
| `CryptoJS.MD5("msg")` | `Crypto.MD5("msg")` |
| `CryptoJS.SHA256("msg")` | `Crypto.SHA256("msg")` |
| `CryptoJS.HmacSHA256("msg","key")` | `Crypto.HmacSHA256("msg","key")` |
| `CryptoJS.AES.encrypt("m","p")` | `Crypto.AES.encrypt("m","p")` |
| `CryptoJS.AES.decrypt(e,"p")` | `Crypto.AES.decrypt(e,"p")` |
| `CryptoJS.enc.Utf8.parse("s")` | `Crypto.enc.Utf8.parse("s")` |
| `CryptoJS.enc.Base64.stringify(w)` | `Crypto.enc.Base64.stringify(w)` |
| `CryptoJS.lib.WordArray.create([...])` | `Crypto.lib.WordArray.create([...])` |
| `CryptoJS.algo.SHA256.create()` | `Crypto.algo.SHA256.create()` |
| `CryptoJS.algo.HMAC.create(...)` | `Crypto.algo.HMAC.create(...)` |
| `CryptoJS.mode.CBC` | `Crypto.mode.CBC` |
| `CryptoJS.pad.Pkcs7` | `Crypto.pad.Pkcs7` |
| `CryptoJS.format.OpenSSL` | `Crypto.format.OpenSSL` |
| `CryptoJS.kdf.OpenSSL.execute(...)` | `Crypto.kdf.OpenSSL.execute(...)` |
| `CryptoJS.PBKDF2("p","s")` | `Crypto.PBKDF2("p","s")` |
| `CryptoJS.lib.WordArray.random(16)` | `Crypto.lib.WordArray.random(16)` |

## Development

```bash
# Run tests
PYTHONPATH=src python3 tests/test_all.py

# Build
python3 -m build --sdist

# Publish
python3 -m twine upload dist/*
```

## License

MIT

---

*Found a bug? Open an issue → [github.com/davidjohhon/crypto-py/issues](https://github.com/davidjohhon/crypto-py/issues)*
