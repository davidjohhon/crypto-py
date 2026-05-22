<p align="center">
  <a href="README.zh.md">🇨🇳 中文</a>
</p>

# CryptoPy

Python port of [CryptoJS](https://github.com/brix/crypto-js) — standard and secure cryptographic algorithms with the same API. Zero external dependencies.

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
| `CryptoPy.RIPEMD160(s)` | 160 bits | `CryptoPy.RIPEMD160("abc")` |

**Note**: `SHA3` implements raw Keccak[c=2d] (matching CryptoJS), not FIPS 202 SHA-3. Output differs from `hashlib.sha3_512()`.

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

All ciphers share the same API:

```python
enc = CryptoPy.AES.encrypt("plaintext", "password")
dec = CryptoPy.AES.decrypt(enc, "password")
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

## License

MIT
