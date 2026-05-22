# CryptoPy

Python 实现的加密算法库，从 [CryptoJS](https://github.com/brix/crypto-js) 移植，API 完全兼容。

## 安装

```bash
pip install cryptopy
```

## 快速开始

```python
import CryptoPy

# 哈希
digest = CryptoPy.MD5("Message")
print(digest)  # hex string

# HMAC
CryptoPy.HmacSHA256("Message", "Secret Key")

# AES 加密/解密
enc = CryptoPy.AES.encrypt("My secret data", "password")
dec = CryptoPy.AES.decrypt(enc, "password")
print(CryptoPy.enc.Utf8.stringify(dec))  # "My secret data"
```

## API 文档

### 哈希算法

```python
CryptoPy.MD5("message")
CryptoPy.SHA1("message")
CryptoPy.SHA256("message")
CryptoPy.SHA224("message")
CryptoPy.SHA384("message")
CryptoPy.SHA512("message")
CryptoPy.SHA3("message", {"outputLength": 256})  # 224/256/384/512
CryptoPy.RIPEMD160("message")
```

**输入**: 字符串或 `WordArray`。
**输出**: `WordArray`，直接 `print()` 或 `.toString()` 得到 hex 字符串。

```python
# 转其他编码
hash = CryptoPy.SHA256("Message")
hash.toString(CryptoPy.enc.Base64)  # Base64
hash.toString(CryptoPy.enc.Hex)     # Hex（默认）
```

**渐进式哈希**:

```python
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("Message Part 1")
sha256.update("Message Part 2")
sha256.update("Message Part 3")
digest = sha256.finalize()
```

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

**渐进式 HMAC**:

```python
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "Secret Key")
hmac.update("Message Part 1")
hmac.update("Message Part 2")
hmac.update("Message Part 3")
digest = hmac.finalize()
```

### AES 加密

**密码加密**（自动派生密钥和 IV）:

```python
encrypted = CryptoPy.AES.encrypt("Message", "Secret Passphrase")
decrypted = CryptoPy.AES.decrypt(encrypted, "Secret Passphrase")
plaintext = CryptoPy.enc.Utf8.stringify(decrypted)
```

**自定义 Key 和 IV**:

```python
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
encrypted = CryptoPy.AES.encrypt("Message", key, {"iv": iv})
decrypted = CryptoPy.AES.decrypt(encrypted, key, {"iv": iv})
```

**指定模式和填充**:

```python
encrypted = CryptoPy.AES.encrypt("Message", "Secret Passphrase", {
    "mode": CryptoPy.mode.CFB,
    "padding": CryptoPy.pad.AnsiX923,
})
```

**渐进式加密**:

```python
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")

encryptor = CryptoPy.algo.AES.createEncryptor(key, {"iv": iv})
c1 = encryptor.process("Message Part 1")
c2 = encryptor.process("Message Part 2")
c3 = encryptor.finalize("Message Part 3")

decryptor = CryptoPy.algo.AES.createDecryptor(key, {"iv": iv})
p1 = decryptor.process(c1)
p2 = decryptor.process(c2)
p3 = decryptor.process(c3)
p4 = decryptor.finalize()
```

### 其他加密算法

```python
CryptoPy.DES.encrypt("message", "password")
CryptoPy.TripleDES.encrypt("message", "password")
CryptoPy.Rabbit.encrypt("message", "password")
CryptoPy.RabbitLegacy.encrypt("message", "password")
CryptoPy.RC4.encrypt("message", "password")
CryptoPy.RC4Drop.encrypt("message", "password")
# 解密方式相同
CryptoPy.DES.decrypt(encrypted, "password")
```

### 块密码模式

| 模式 | 说明 |
|------|------|
| `CryptoPy.mode.CBC` | Cipher Block Chaining（默认） |
| `CryptoPy.mode.CFB` | Cipher Feedback |
| `CryptoPy.mode.CTR` | Counter |
| `CryptoPy.mode.ECB` | Electronic Codebook |
| `CryptoPy.mode.OFB` | Output Feedback |

```python
CryptoPy.AES.encrypt("Message", "password", {"mode": CryptoPy.mode.ECB})
```

### 填充方案

| 方案 | 说明 |
|------|------|
| `CryptoPy.pad.Pkcs7` | PKCS #5/#7（默认） |
| `CryptoPy.pad.AnsiX923` | ANSI X.923 |
| `CryptoPy.pad.Iso10126` | ISO 10126 |
| `CryptoPy.pad.Iso97971` | ISO/IEC 9797-1 |
| `CryptoPy.pad.ZeroPadding` | 补零 |
| `CryptoPy.pad.NoPadding` | 无填充 |

```python
CryptoPy.AES.encrypt("Message", "password", {"padding": CryptoPy.pad.ZeroPadding})
```

### 编码器

```python
# Hex
words = CryptoPy.enc.Hex.parse("48656c6c6f")
hex_str = CryptoPy.enc.Hex.stringify(words)

# Utf8
words = CryptoPy.enc.Utf8.parse("Hello, World!")
utf8_str = CryptoPy.enc.Utf8.stringify(words)

# Latin1
words = CryptoPy.enc.Latin1.parse("Hello")
latin1_str = CryptoPy.enc.Latin1.stringify(words)

# Base64
words = CryptoPy.enc.Base64.parse("SGVsbG8sIFdvcmxkIQ==")
b64_str = CryptoPy.enc.Base64.stringify(words)

# Base64url
words = CryptoPy.enc.Base64url.parse("SGVsbG8sIFdvcmxkIQ==", urlSafe=True)

# UTF-16
words = CryptoPy.enc.Utf16.parse("Hello")
CryptoPy.enc.Utf16BE.stringify(words)
CryptoPy.enc.Utf16LE.stringify(words)
```

### 密钥派生

```python
# PBKDF2
key = CryptoPy.PBKDF2("password", "salt")
key = CryptoPy.PBKDF2("password", "salt", {
    "keySize": 256 // 32,      # 输出密钥大小（字）
    "iterations": 1000,         # 迭代次数（默认 1）
    "hasher": CryptoPy.algo.SHA256,
})

# EvpKDF（OpenSSL EVP_BytesToKey）
key = CryptoPy.EvpKDF("password", "salt")
key = CryptoPy.EvpKDF("password", "salt", {
    "keySize": 256 // 32,
    "hasher": CryptoPy.algo.MD5,
    "iterations": 1,
})
```

### WordArray

```python
# 创建
wa = CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef])
wa = CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef], 5)  # 指定有效字节数

# 输出
print(wa)                     # Hex 字符串
wa.toString(CryptoPy.enc.Base64)

# 操作
clone = wa.clone()
wa.concat(other)
wa.clamp()

# 随机字节
rand = CryptoPy.lib.WordArray.random(16)
```

### 格式与序列化

```python
# OpenSSL 兼容格式（默认）
enc = CryptoPy.AES.encrypt("Message", "password")
str(enc)  # "U2FsdGVkX1/..."（Base64 编码，含 "Salted__" 前缀）

# 自定义 JSON 格式
class JsonFormatter:
    @staticmethod
    def stringify(cipherParams):
        obj = {"ct": cipherParams.ciphertext.toString(CryptoPy.enc.Base64)}
        if hasattr(cipherParams, 'iv') and cipherParams.iv:
            obj["iv"] = cipherParams.iv.toString()
        if hasattr(cipherParams, 'salt') and cipherParams.salt:
            obj["s"] = cipherParams.salt.toString()
        import json
        return json.dumps(obj)

    @staticmethod
    def parse(jsonStr):
        import json
        obj = json.loads(jsonStr)
        from CryptoPy.cipher_core import CipherParams
        return CipherParams.create({
            "ciphertext": CryptoPy.enc.Base64.parse(obj["ct"]),
        })

enc = CryptoPy.AES.encrypt("Message", "password", {"format": JsonFormatter})
dec = CryptoPy.AES.decrypt(enc, "password", {"format": JsonFormatter})
```

## 与 CryptoJS 对照

| CryptoJS | CryptoPy |
|----------|----------|
| `CryptoJS.MD5("msg")` | `CryptoPy.MD5("msg")` |
| `CryptoJS.AES.encrypt(...)` | `CryptoPy.AES.encrypt(...)` |
| `CryptoJS.enc.Utf8.parse(...)` | `CryptoPy.enc.Utf8.parse(...)` |
| `CryptoJS.lib.WordArray.create(...)` | `CryptoPy.lib.WordArray.create(...)` |
| `CryptoJS.algo.SHA256.create()` | `CryptoPy.algo.SHA256.create()` |
| `CryptoJS.mode.CBC` | `CryptoPy.mode.CBC` |
| `CryptoJS.pad.Pkcs7` | `CryptoPy.pad.Pkcs7` |
| `CryptoJS.format.OpenSSL` | `CryptoPy.format.OpenSSL` |

## 开发

```bash
# 运行测试
PYTHONPATH=src python3 tests/test_all.py

# 直接使用
PYTHONPATH=src python3 -c "import CryptoPy; print(CryptoPy.MD5('test'))"
```

## License

MIT
