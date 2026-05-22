<p align="center">
  <a href="README.md">🇬🇧 English</a>
</p>

# CryptoPy

Python 实现的加密算法库，从 [CryptoJS](https://github.com/brix/crypto-js) 移植，API 完全兼容。

## 安装

```bash
pip install crypto4py
```

## 快速开始

```python
import CryptoPy

# 哈希
CryptoPy.MD5("Message")
CryptoPy.SHA256("Message")

# HMAC
CryptoPy.HmacSHA256("Message", "Secret Key")

# AES 加密/解密
enc = CryptoPy.AES.encrypt("My secret data", "password")
dec = CryptoPy.AES.decrypt(enc, "password")
print(CryptoPy.enc.Utf8.stringify(dec))

# 编码器
CryptoPy.enc.Hex.parse("48656c6c6f")
CryptoPy.enc.Base64.stringify(wordArray)
CryptoPy.enc.Utf8.parse("Hello")

# 渐进式哈希
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("Part 1").update("Part 2")
sha256.finalize("Part 3")

# 渐进式 HMAC
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "key")
hmac.update("Part 1").update("Part 2")
hmac.finalize()
```

## API

所有 API 遵循 [CryptoJS](https://github.com/brix/crypto-js) 命名规范。

### 哈希算法

`MD5`, `SHA1`, `SHA256`, `SHA224`, `SHA384`, `SHA512`, `SHA3`, `RIPEMD160`

```python
CryptoPy.MD5("message")
CryptoPy.SHA3("message", {"outputLength": 256})
```

### HMAC

`HmacMD5`, `HmacSHA1`, `HmacSHA256`, `HmacSHA224`, `HmacSHA384`, `HmacSHA512`, `HmacSHA3`, `HmacRIPEMD160`

### 加密算法

`AES`, `DES`, `TripleDES`, `Rabbit`, `RabbitLegacy`, `RC4`, `RC4Drop`

```python
CryptoPy.AES.encrypt("message", "password")
CryptoPy.AES.decrypt(encrypted, "password")
```

### 块密码模式

`CBC`（默认）, `CFB`, `CTR`, `ECB`, `OFB`

### 填充方案

`Pkcs7`（默认）, `AnsiX923`, `Iso10126`, `Iso97971`, `ZeroPadding`, `NoPadding`

### 编码器

`Hex`, `Latin1`, `Utf8`, `Utf16`, `Utf16BE`, `Utf16LE`, `Base64`, `Base64url`

### 密钥派生

```python
CryptoPy.PBKDF2("password", "salt", {"keySize": 256 // 32, "iterations": 1000})
CryptoPy.EvpKDF("password", "salt", {"keySize": 256 // 32})
```

## 链接

- **GitHub**：https://github.com/davidjohhon/crypto-py
- **PyPI**：https://pypi.org/project/crypto4py/

## 许可证

MIT
