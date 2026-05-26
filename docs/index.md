<p align="center">
  <a href="https://github.com/davidjohhon/crypto-py/blob/main/docs/index_zh.md">🇨🇳 中文</a>
</p>

# Crypto API Reference

## Import

```python
import Crypto
```

All APIs are accessed through the `Crypto` namespace, following CryptoJS conventions.

---

## Hash Algorithms

### Basic Usage

```python
Crypto.MD5("Message")
Crypto.SHA1("Message")
Crypto.SHA256("Message")
Crypto.SHA224("Message")
Crypto.SHA384("Message")
Crypto.SHA512("Message")
Crypto.SHA3("Message", {"outputLength": 256})
Crypto.RIPEMD160("Message")
```

**Input**: `str` or `WordArray`.

**Output**: `WordArray`. Use `str()` or `.toString()` for hex string.

```python
h = Crypto.SHA256("Message")
print(h)                             # hex
h.toString(Crypto.enc.Base64)      # Base64
h.toString(Crypto.enc.Hex)         # Hex (default)
```

### SHA3 Note

> SHA3 implements raw **Keccak[c=2d]** (matching CryptoJS), **NOT** the FIPS 202 standardized SHA-3.
> The difference is the domain separation byte: Keccak uses `0x01`, FIPS 202 SHA-3 uses `0x06`.
> `Crypto.SHA3("")` ≠ `hashlib.sha3_512(b"")`.

### Progressive Hashing

```python
sha256 = Crypto.algo.SHA256.create()
sha256.update("Message Part 1")
sha256.update("Message Part 2")
hash = sha256.finalize("Message Part 3")

# Equivalent to:
Crypto.SHA256("Message Part 1Message Part 2Message Part 3")
```

### Clone Hash State

```python
sha256 = Crypto.algo.SHA256.create()
sha256.update("a")
clone = sha256.clone()
clone.finalize()                      # SHA256("a")
sha256.update("b").finalize()         # SHA256("ab")
```

---

## HMAC

### Basic Usage

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

### Progressive HMAC

```python
hmac = Crypto.algo.HMAC.create(Crypto.algo.SHA256, "Secret Key")
hmac.update("Message Part 1")
hmac.update("Message Part 2")
hmac.finalize("Message Part 3")
```

---

## Ciphers

### AES

```python
# Password-based (auto key/IV derivation)
enc = Crypto.AES.encrypt("Message", "Secret Passphrase")
dec = Crypto.AES.decrypt(enc, "Secret Passphrase")
Crypto.enc.Utf8.stringify(dec)

# Custom Key and IV
key = Crypto.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = Crypto.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = Crypto.AES.encrypt("Message", key, {"iv": iv})
dec = Crypto.AES.decrypt(enc, key, {"iv": iv})

# Custom mode and padding
Crypto.AES.encrypt("Message", "password", {
    "mode": Crypto.mode.ECB,
    "padding": Crypto.pad.ZeroPadding,
})
```

### DES / TripleDES / Rabbit / RC4

```python
Crypto.DES.encrypt("Message", "Secret Passphrase")
Crypto.TripleDES.encrypt("Message", "Secret Passphrase")
Crypto.Rabbit.encrypt("Message", "Key")
Crypto.RC4.encrypt("Message", "Key")
Crypto.RC4Drop.encrypt("Message", "Key", {"drop": 3072 // 4})
```

### Progressive Encryption

```python
key = Crypto.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = Crypto.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")

# Encrypt
enc = Crypto.algo.AES.createEncryptor(key, {"iv": iv})
c1 = enc.process("Message Part 1")
c2 = enc.process("Message Part 2")
c3 = enc.finalize("Message Part 3")

# Decrypt
dec = Crypto.algo.AES.createDecryptor(key, {"iv": iv})
p1 = dec.process(c1)
p2 = dec.process(c2)
p3 = dec.process(c3)
p4 = dec.finalize()
Crypto.enc.Utf8.stringify(p1.clone().concat(p2).concat(p3).concat(p4))
```

---

## Block Cipher Modes

| Mode | Description | Default |
|------|-------------|---------|
| `Crypto.mode.CBC` | Cipher Block Chaining | ✓ |
| `Crypto.mode.CFB` | Cipher Feedback | |
| `Crypto.mode.CTR` | Counter | |
| `Crypto.mode.ECB` | Electronic Codebook | |
| `Crypto.mode.OFB` | Output Feedback | |

```python
Crypto.AES.encrypt("Message", "password", {"mode": Crypto.mode.CTR})
```

---

## Padding Schemes

| Scheme | Description | Default |
|--------|-------------|---------|
| `Crypto.pad.Pkcs7` | PKCS #5/#7 | ✓ |
| `Crypto.pad.AnsiX923` | ANSI X.923 | |
| `Crypto.pad.Iso10126` | ISO 10126 (random) | |
| `Crypto.pad.Iso97971` | ISO/IEC 9797-1 | |
| `Crypto.pad.ZeroPadding` | Zero padding | |
| `Crypto.pad.NoPadding` | No padding | |

```python
Crypto.AES.encrypt("Message", "password", {"padding": Crypto.pad.Iso97971})
```

---

## Encoders

```python
Crypto.enc.Hex.parse("48656c6c6f")
Crypto.enc.Hex.stringify(wordArray)
Crypto.enc.Utf8.parse("Hello, World!")
Crypto.enc.Utf8.stringify(wordArray)
Crypto.enc.Latin1.parse("Hello")
Crypto.enc.Base64.parse("SGVsbG8sIFdvcmxkIQ==")
Crypto.enc.Base64.stringify(wordArray)
Crypto.enc.Base64url.parse("SGVsbG8sIFdvcmxkIQ==", urlSafe=True)
Crypto.enc.Utf16.parse("Hello")
Crypto.enc.Utf16LE.parse("Hello")
```

---

## Key Derivation

### PBKDF2

```python
# Default (SHA256, 250000 iterations, 128-bit key)
key = Crypto.PBKDF2("password", "salt")

# Full parameters
key = Crypto.PBKDF2("password", "salt", {
    "keySize": 256 // 32,      # key size in words
    "iterations": 1000,         # iteration count
    "hasher": Crypto.algo.SHA256,
})
```

> **Performance note**: The default 250000 iterations takes ~2 minutes in Python. Use a lower count for testing.

### EvpKDF (OpenSSL EVP_BytesToKey)

```python
key = Crypto.EvpKDF("password", "salt")
key = Crypto.EvpKDF("password", "salt", {
    "keySize": 256 // 32,
    "hasher": Crypto.algo.MD5,
})
```

---

## WordArray

### Create

```python
# From word list
wa = Crypto.lib.WordArray.create([0x12345678, 0x90abcdef])

# With specific byte count
wa = Crypto.lib.WordArray.create([0x12345678, 0x90abcdef], 5)

# Random bytes
rand = Crypto.lib.WordArray.random(16)
```

### Operations

```python
wa.toString()                              # hex
wa.toString(Crypto.enc.Base64)           # Base64
wa.toString(Crypto.enc.Hex)              # explicit Hex
wa.toString(Crypto.enc.Latin1)           # Latin1 string
wa.toString(Crypto.enc.Utf8)             # UTF-8 string
clone = wa.clone()
wa.concat(other)
wa.clamp()
```

---

## Format & Serialization

### OpenSSL Format (Default)

```python
enc = Crypto.AES.encrypt("Message", "password")
str(enc)  # "U2FsdGVkX1/..." (Base64 with "Salted__" prefix)

# Decrypt
Crypto.AES.decrypt(enc, "password")
```

### Custom JSON Format

```python
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
print(Crypto.enc.Utf8.stringify(dec))  # "Message"
```

---

## Real-World Usage

### File Integrity Check

```python
import Crypto

with open("file.bin", "rb") as f:
    data = f.read()

wa = Crypto.lib.WordArray.create(list(data), len(data))
digest = Crypto.SHA256(wa)
print("SHA256:", digest)
```

### Password Hashing

```python
import Crypto

salt = Crypto.lib.WordArray.random(16)
key = Crypto.PBKDF2("user_password", salt, {
    "keySize": 256 // 32,
    "iterations": 10000,
})
print("Derived key:", key.toString(Crypto.enc.Base64))
```

### File Encryption

```python
import Crypto

enc = Crypto.AES.encrypt("Sensitive data", "password")
with open("secret.enc", "w") as f:
    f.write(str(enc))

with open("secret.enc") as f:
    data = f.read()
dec = Crypto.AES.decrypt(data, "password")
print(Crypto.enc.Utf8.stringify(dec))
```

### Streaming Hash for Large Files

```python
import Crypto

sha256 = Crypto.algo.SHA256.create()
with open("largefile.bin", "rb") as f:
    for chunk in iter(lambda: f.read(8192), b""):
        wa = Crypto.lib.WordArray.create(list(chunk), len(chunk))
        sha256.update(wa)
print("File SHA256:", sha256.finalize())
```

### Cross-Language Interop (CryptoJS ↔ Crypto)

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

---

## CryptoJS API Mapping

| CryptoJS | Crypto |
|----------|----------|
| `CryptoJS.MD5("msg")` | `Crypto.MD5("msg")` |
| `CryptoJS.SHA256("msg")` | `Crypto.SHA256("msg")` |
| `CryptoJS.HmacSHA256("msg", "key")` | `Crypto.HmacSHA256("msg", "key")` |
| `CryptoJS.AES.encrypt("msg", "pass")` | `Crypto.AES.encrypt("msg", "pass")` |
| `CryptoJS.AES.decrypt(enc, "pass")` | `Crypto.AES.decrypt(enc, "pass")` |
| `CryptoJS.enc.Utf8.parse("str")` | `Crypto.enc.Utf8.parse("str")` |
| `CryptoJS.enc.Base64.stringify(wa)` | `Crypto.enc.Base64.stringify(wa)` |
| `CryptoJS.enc.Hex.parse("a1b2")` | `Crypto.enc.Hex.parse("a1b2")` |
| `CryptoJS.lib.WordArray.create([...])` | `Crypto.lib.WordArray.create([...])` |
| `CryptoJS.algo.SHA256.create()` | `Crypto.algo.SHA256.create()` |
| `CryptoJS.algo.HMAC.create(...)` | `Crypto.algo.HMAC.create(...)` |
| `CryptoJS.mode.CBC` | `Crypto.mode.CBC` |
| `CryptoJS.pad.Pkcs7` | `Crypto.pad.Pkcs7` |
| `CryptoJS.format.OpenSSL` | `Crypto.format.OpenSSL` |
| `CryptoJS.kdf.OpenSSL.execute(...)` | `Crypto.kdf.OpenSSL.execute(...)` |
| `CryptoJS.PBKDF2("pass", "salt")` | `Crypto.PBKDF2("pass", "salt")` |
| `CryptoJS.lib.WordArray.random(16)` | `Crypto.lib.WordArray.random(16)` |

## Internal API

```python
Crypto.lib.Base
Crypto.lib.WordArray
Crypto.lib.Hasher
Crypto.lib.Cipher
Crypto.lib.BlockCipher
Crypto.lib.StreamCipher
Crypto.lib.CipherParams
Crypto.lib.SerializableCipher
Crypto.lib.PasswordBasedCipher

Crypto.algo.MD5.create()
Crypto.algo.SHA256.create()
Crypto.algo.HMAC.create(Crypto.algo.SHA256, "key")
Crypto.algo.AES.createEncryptor(key, cfg)
Crypto.algo.AES.createDecryptor(key, cfg)

Crypto.kdf.OpenSSL.execute(password, keySize, ivSize, salt, hasher)
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
