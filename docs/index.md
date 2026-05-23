<p align="center">
  <a href="https://github.com/davidjohhon/crypto-py/blob/main/docs/index_zh.md">🇨🇳 中文</a>
</p>

# CryptoPy API Reference

## Import

```python
import CryptoPy
```

All APIs are accessed through the `CryptoPy` namespace, following CryptoJS conventions.

---

## Hash Algorithms

### Basic Usage

```python
CryptoPy.MD5("Message")
CryptoPy.SHA1("Message")
CryptoPy.SHA256("Message")
CryptoPy.SHA224("Message")
CryptoPy.SHA384("Message")
CryptoPy.SHA512("Message")
CryptoPy.SHA3("Message", {"outputLength": 256})
CryptoPy.RIPEMD160("Message")
```

**Input**: `str` or `WordArray`.

**Output**: `WordArray`. Use `str()` or `.toString()` for hex string.

```python
h = CryptoPy.SHA256("Message")
print(h)                             # hex
h.toString(CryptoPy.enc.Base64)      # Base64
h.toString(CryptoPy.enc.Hex)         # Hex (default)
```

### SHA3 Note

> SHA3 implements raw **Keccak[c=2d]** (matching CryptoJS), **NOT** the FIPS 202 standardized SHA-3.
> The difference is the domain separation byte: Keccak uses `0x01`, FIPS 202 SHA-3 uses `0x06`.
> `CryptoPy.SHA3("")` ≠ `hashlib.sha3_512(b"")`.

### Progressive Hashing

```python
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("Message Part 1")
sha256.update("Message Part 2")
hash = sha256.finalize("Message Part 3")

# Equivalent to:
CryptoPy.SHA256("Message Part 1Message Part 2Message Part 3")
```

### Clone Hash State

```python
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("a")
clone = sha256.clone()
clone.finalize()                      # SHA256("a")
sha256.update("b").finalize()         # SHA256("ab")
```

---

## HMAC

### Basic Usage

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

### Progressive HMAC

```python
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "Secret Key")
hmac.update("Message Part 1")
hmac.update("Message Part 2")
hmac.finalize("Message Part 3")
```

---

## Ciphers

### AES

```python
# Password-based (auto key/IV derivation)
enc = CryptoPy.AES.encrypt("Message", "Secret Passphrase")
dec = CryptoPy.AES.decrypt(enc, "Secret Passphrase")
CryptoPy.enc.Utf8.stringify(dec)

# Custom Key and IV
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = CryptoPy.AES.encrypt("Message", key, {"iv": iv})
dec = CryptoPy.AES.decrypt(enc, key, {"iv": iv})

# Custom mode and padding
CryptoPy.AES.encrypt("Message", "password", {
    "mode": CryptoPy.mode.ECB,
    "padding": CryptoPy.pad.ZeroPadding,
})
```

### DES / TripleDES / Rabbit / RC4

```python
CryptoPy.DES.encrypt("Message", "Secret Passphrase")
CryptoPy.TripleDES.encrypt("Message", "Secret Passphrase")
CryptoPy.Rabbit.encrypt("Message", "Key")
CryptoPy.RC4.encrypt("Message", "Key")
CryptoPy.RC4Drop.encrypt("Message", "Key", {"drop": 3072 // 4})
```

### Progressive Encryption

```python
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")

# Encrypt
enc = CryptoPy.algo.AES.createEncryptor(key, {"iv": iv})
c1 = enc.process("Message Part 1")
c2 = enc.process("Message Part 2")
c3 = enc.finalize("Message Part 3")

# Decrypt
dec = CryptoPy.algo.AES.createDecryptor(key, {"iv": iv})
p1 = dec.process(c1)
p2 = dec.process(c2)
p3 = dec.process(c3)
p4 = dec.finalize()
CryptoPy.enc.Utf8.stringify(p1.clone().concat(p2).concat(p3).concat(p4))
```

---

## Block Cipher Modes

| Mode | Description | Default |
|------|-------------|---------|
| `CryptoPy.mode.CBC` | Cipher Block Chaining | ✓ |
| `CryptoPy.mode.CFB` | Cipher Feedback | |
| `CryptoPy.mode.CTR` | Counter | |
| `CryptoPy.mode.ECB` | Electronic Codebook | |
| `CryptoPy.mode.OFB` | Output Feedback | |

```python
CryptoPy.AES.encrypt("Message", "password", {"mode": CryptoPy.mode.CTR})
```

---

## Padding Schemes

| Scheme | Description | Default |
|--------|-------------|---------|
| `CryptoPy.pad.Pkcs7` | PKCS #5/#7 | ✓ |
| `CryptoPy.pad.AnsiX923` | ANSI X.923 | |
| `CryptoPy.pad.Iso10126` | ISO 10126 (random) | |
| `CryptoPy.pad.Iso97971` | ISO/IEC 9797-1 | |
| `CryptoPy.pad.ZeroPadding` | Zero padding | |
| `CryptoPy.pad.NoPadding` | No padding | |

```python
CryptoPy.AES.encrypt("Message", "password", {"padding": CryptoPy.pad.Iso97971})
```

---

## Encoders

```python
CryptoPy.enc.Hex.parse("48656c6c6f")
CryptoPy.enc.Hex.stringify(wordArray)
CryptoPy.enc.Utf8.parse("Hello, World!")
CryptoPy.enc.Utf8.stringify(wordArray)
CryptoPy.enc.Latin1.parse("Hello")
CryptoPy.enc.Base64.parse("SGVsbG8sIFdvcmxkIQ==")
CryptoPy.enc.Base64.stringify(wordArray)
CryptoPy.enc.Base64url.parse("SGVsbG8sIFdvcmxkIQ==", urlSafe=True)
CryptoPy.enc.Utf16.parse("Hello")
CryptoPy.enc.Utf16LE.parse("Hello")
```

---

## Key Derivation

### PBKDF2

```python
# Default (SHA256, 250000 iterations, 128-bit key)
key = CryptoPy.PBKDF2("password", "salt")

# Full parameters
key = CryptoPy.PBKDF2("password", "salt", {
    "keySize": 256 // 32,      # key size in words
    "iterations": 1000,         # iteration count
    "hasher": CryptoPy.algo.SHA256,
})
```

> **Performance note**: The default 250000 iterations takes ~2 minutes in Python. Use a lower count for testing.

### EvpKDF (OpenSSL EVP_BytesToKey)

```python
key = CryptoPy.EvpKDF("password", "salt")
key = CryptoPy.EvpKDF("password", "salt", {
    "keySize": 256 // 32,
    "hasher": CryptoPy.algo.MD5,
})
```

---

## WordArray

### Create

```python
# From word list
wa = CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef])

# With specific byte count
wa = CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef], 5)

# Random bytes
rand = CryptoPy.lib.WordArray.random(16)
```

### Operations

```python
wa.toString()                              # hex
wa.toString(CryptoPy.enc.Base64)           # Base64
wa.toString(CryptoPy.enc.Hex)              # explicit Hex
wa.toString(CryptoPy.enc.Latin1)           # Latin1 string
wa.toString(CryptoPy.enc.Utf8)             # UTF-8 string
clone = wa.clone()
wa.concat(other)
wa.clamp()
```

---

## Format & Serialization

### OpenSSL Format (Default)

```python
enc = CryptoPy.AES.encrypt("Message", "password")
str(enc)  # "U2FsdGVkX1/..." (Base64 with "Salted__" prefix)

# Decrypt
CryptoPy.AES.decrypt(enc, "password")
```

### Custom JSON Format

```python
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
print(CryptoPy.enc.Utf8.stringify(dec))  # "Message"
```

---

## Real-World Usage

### File Integrity Check

```python
import CryptoPy

with open("file.bin", "rb") as f:
    data = f.read()

wa = CryptoPy.lib.WordArray.create(list(data), len(data))
digest = CryptoPy.SHA256(wa)
print("SHA256:", digest)
```

### Password Hashing

```python
import CryptoPy

salt = CryptoPy.lib.WordArray.random(16)
key = CryptoPy.PBKDF2("user_password", salt, {
    "keySize": 256 // 32,
    "iterations": 10000,
})
print("Derived key:", key.toString(CryptoPy.enc.Base64))
```

### File Encryption

```python
import CryptoPy

enc = CryptoPy.AES.encrypt("Sensitive data", "password")
with open("secret.enc", "w") as f:
    f.write(str(enc))

with open("secret.enc") as f:
    data = f.read()
dec = CryptoPy.AES.decrypt(data, "password")
print(CryptoPy.enc.Utf8.stringify(dec))
```

### Streaming Hash for Large Files

```python
import CryptoPy

sha256 = CryptoPy.algo.SHA256.create()
with open("largefile.bin", "rb") as f:
    for chunk in iter(lambda: f.read(8192), b""):
        wa = CryptoPy.lib.WordArray.create(list(chunk), len(chunk))
        sha256.update(wa)
print("File SHA256:", sha256.finalize())
```

### Cross-Language Interop (CryptoJS ↔ CryptoPy)

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

---

## CryptoJS API Mapping

| CryptoJS | CryptoPy |
|----------|----------|
| `CryptoJS.MD5("msg")` | `CryptoPy.MD5("msg")` |
| `CryptoJS.SHA256("msg")` | `CryptoPy.SHA256("msg")` |
| `CryptoJS.HmacSHA256("msg", "key")` | `CryptoPy.HmacSHA256("msg", "key")` |
| `CryptoJS.AES.encrypt("msg", "pass")` | `CryptoPy.AES.encrypt("msg", "pass")` |
| `CryptoJS.AES.decrypt(enc, "pass")` | `CryptoPy.AES.decrypt(enc, "pass")` |
| `CryptoJS.enc.Utf8.parse("str")` | `CryptoPy.enc.Utf8.parse("str")` |
| `CryptoJS.enc.Base64.stringify(wa)` | `CryptoPy.enc.Base64.stringify(wa)` |
| `CryptoJS.enc.Hex.parse("a1b2")` | `CryptoPy.enc.Hex.parse("a1b2")` |
| `CryptoJS.lib.WordArray.create([...])` | `CryptoPy.lib.WordArray.create([...])` |
| `CryptoJS.algo.SHA256.create()` | `CryptoPy.algo.SHA256.create()` |
| `CryptoJS.algo.HMAC.create(...)` | `CryptoPy.algo.HMAC.create(...)` |
| `CryptoJS.mode.CBC` | `CryptoPy.mode.CBC` |
| `CryptoJS.pad.Pkcs7` | `CryptoPy.pad.Pkcs7` |
| `CryptoJS.format.OpenSSL` | `CryptoPy.format.OpenSSL` |
| `CryptoJS.kdf.OpenSSL.execute(...)` | `CryptoPy.kdf.OpenSSL.execute(...)` |
| `CryptoJS.PBKDF2("pass", "salt")` | `CryptoPy.PBKDF2("pass", "salt")` |
| `CryptoJS.lib.WordArray.random(16)` | `CryptoPy.lib.WordArray.random(16)` |

## Internal API

```python
CryptoPy.lib.Base
CryptoPy.lib.WordArray
CryptoPy.lib.Hasher
CryptoPy.lib.Cipher
CryptoPy.lib.BlockCipher
CryptoPy.lib.StreamCipher
CryptoPy.lib.CipherParams
CryptoPy.lib.SerializableCipher
CryptoPy.lib.PasswordBasedCipher

CryptoPy.algo.MD5.create()
CryptoPy.algo.SHA256.create()
CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "key")
CryptoPy.algo.AES.createEncryptor(key, cfg)
CryptoPy.algo.AES.createDecryptor(key, cfg)

CryptoPy.kdf.OpenSSL.execute(password, keySize, ivSize, salt, hasher)
```

## Development

```bash
# Run tests
PYTHONPATH=src python3 tests/test_all.py

# Build
python3 -m build --sdist

# Publish
python3 -m twine upload dist/*
```

---

*Found a bug? Open an issue → [github.com/davidjohhon/crypto-py/issues](https://github.com/davidjohhon/crypto-py/issues)*
