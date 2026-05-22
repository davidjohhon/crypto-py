<p align="center">
  <a href="https://github.com/davidjohhon/crypto-py/blob/main/README.zh.md">🇨🇳 中文</a>
</p>

# CryptoPy

Python port of [CryptoJS](https://github.com/brix/crypto-js) — standard and secure cryptographic algorithms with the same API.

## Install

```bash
pip install crypto4py
```

## Quick Start

```python
import CryptoPy

# Hash
CryptoPy.MD5("Message")
CryptoPy.SHA256("Message")

# HMAC
CryptoPy.HmacSHA256("Message", "Secret Key")

# AES encrypt / decrypt
enc = CryptoPy.AES.encrypt("My secret data", "password")
dec = CryptoPy.AES.decrypt(enc, "password")

# Encoders
CryptoPy.enc.Hex.parse("48656c6c6f")
CryptoPy.enc.Base64.stringify(wordArray)
CryptoPy.enc.Utf8.parse("Hello")

# Progressive hashing
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("Part 1").update("Part 2")
sha256.finalize("Part 3")

# Progressive HMAC
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "key")
hmac.update("Part 1").update("Part 2")
hmac.finalize()
```

## API

All APIs follow [CryptoJS](https://github.com/brix/crypto-js) naming conventions.

### Hash Algorithms

`MD5`, `SHA1`, `SHA256`, `SHA224`, `SHA384`, `SHA512`, `SHA3`, `RIPEMD160`

```python
CryptoPy.MD5("message")
CryptoPy.SHA3("message", {"outputLength": 256})
```

### HMAC

`HmacMD5`, `HmacSHA1`, `HmacSHA256`, `HmacSHA224`, `HmacSHA384`, `HmacSHA512`, `HmacSHA3`, `HmacRIPEMD160`

### Ciphers

`AES`, `DES`, `TripleDES`, `Rabbit`, `RabbitLegacy`, `RC4`, `RC4Drop`

```python
CryptoPy.AES.encrypt("message", "password")
CryptoPy.DES.decrypt(encrypted, "password")
```

### Block Modes

`CBC` (default), `CFB`, `CTR`, `ECB`, `OFB`

### Padding Schemes

`Pkcs7` (default), `AnsiX923`, `Iso10126`, `Iso97971`, `ZeroPadding`, `NoPadding`

### Encoders

`Hex`, `Latin1`, `Utf8`, `Utf16`, `Utf16BE`, `Utf16LE`, `Base64`, `Base64url`

### Key Derivation

```python
CryptoPy.PBKDF2("password", "salt", {"keySize": 256 // 32, "iterations": 1000})
CryptoPy.EvpKDF("password", "salt", {"keySize": 256 // 32})
```

## Links

- **GitHub**: https://github.com/davidjohhon/crypto-py
- **PyPI**: https://pypi.org/project/crypto4py/

## License

MIT
