<p align="center">
  <a href="README.md">🇬🇧 English</a>
</p>

# CryptoPy

Python 实现的加密算法库，从 [CryptoJS](https://github.com/brix/crypto-js) 移植，API 完全兼容。零外部依赖。

## 安装

```bash
pip install crypto4py
```

## 快速开始

```python
import CryptoPy

# 哈希
digest = CryptoPy.MD5("Message")
print(digest)                                   # hex 字符串
print(digest.toString(CryptoPy.enc.Base64))     # Base64
print(digest.toString(CryptoPy.enc.Hex))        # 显式 Hex

CryptoPy.SHA256("Message")
CryptoPy.SHA3("Message", {"outputLength": 256})

# HMAC
CryptoPy.HmacSHA256("Message", "Secret Key")

# AES 加密/解密
enc = CryptoPy.AES.encrypt("My secret data", "password")
dec = CryptoPy.AES.decrypt(enc, "password")
print(CryptoPy.enc.Utf8.stringify(dec))  # "My secret data"

# 自定义 Key 和 IV
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = CryptoPy.AES.encrypt("Message", key, {"iv": iv})
dec = CryptoPy.AES.decrypt(enc, key, {"iv": iv})

# 渐进式哈希
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("Part 1").update("Part 2")
sha256.finalize("Part 3")

# 渐进式 HMAC
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "key")
hmac.update("Part 1").update("Part 2")
hmac.finalize()
```

## API 参考

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

> **注意**：`SHA3` 实现的是原始 Keccak[c=2d]（与 CryptoJS 一致），而非 FIPS 202 标准的 SHA-3。两者的区别在于填充前的域分隔字节不同。标准 `hashlib.sha3_512()` 的输出与此不同。

### toString 编码输出

```python
digest = CryptoPy.MD5("1")
print(digest)                                          # hex: c4ca4238...
print(digest.toString(CryptoPy.enc.Hex))               # hex: c4ca4238...
print(digest.toString(CryptoPy.enc.Base64))            # Base64: xMpCOKC5...
print(digest.toString(CryptoPy.enc.Latin1))            # Latin1 字符串

enc = CryptoPy.AES.encrypt("msg", "pass")
print(enc.toString(CryptoPy.enc.Hex))                  # 密文的 Hex
print(enc.toString(CryptoPy.enc.Base64))               # 密文的 Base64
print(enc.toString(CryptoPy.format.OpenSSL))           # OpenSSL 格式（默认）
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

# 渐进式
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "key")
hmac.update("Part 1")
hmac.finalize("Part 2")
```

### 加密算法

```python
CryptoPy.AES.encrypt("message", "password")
CryptoPy.AES.decrypt(encrypted, "password")
CryptoPy.DES.encrypt("message", "password")
CryptoPy.TripleDES.encrypt("message", "password")
CryptoPy.Rabbit.encrypt("message", "password")
CryptoPy.RC4.encrypt("message", "password")
```

### 块密码模式

```python
CryptoPy.mode.CBC   # 默认
CryptoPy.mode.ECB
CryptoPy.mode.CFB
CryptoPy.mode.OFB
CryptoPy.mode.CTR
```

### 填充方案

```python
CryptoPy.pad.Pkcs7        # 默认
CryptoPy.pad.ZeroPadding
CryptoPy.pad.AnsiX923
CryptoPy.pad.Iso10126
CryptoPy.pad.Iso97971
CryptoPy.pad.NoPadding
```

### 编码器

```python
CryptoPy.enc.Hex.parse("48656c6c6f")
CryptoPy.enc.Hex.stringify(wordArray)
CryptoPy.enc.Utf8.parse("Hello")
CryptoPy.enc.Utf8.stringify(wordArray)
CryptoPy.enc.Base64.parse("SGVsbG8=")
CryptoPy.enc.Base64.stringify(wordArray)
CryptoPy.enc.Utf16.parse("Hello")
CryptoPy.enc.Utf16LE.parse("Hello")
```

### 密钥派生

```python
CryptoPy.PBKDF2("password", "salt")
CryptoPy.PBKDF2("password", "salt", {"keySize": 256//32, "iterations": 10000})
CryptoPy.EvpKDF("password", "salt")
```

## 实际应用场景

### 文件完整性校验

```python
import CryptoPy

with open("file.bin", "rb") as f:
    data = f.read()

wa = CryptoPy.lib.WordArray.create(list(data), len(data))
print("SHA256:", CryptoPy.SHA256(wa))
```

### 密码哈希存储

```python
import CryptoPy

salt = CryptoPy.lib.WordArray.random(16)
key = CryptoPy.PBKDF2("user_password", salt, {
    "keySize": 256 // 32,
    "iterations": 10000,
})
print("Derived key:", key.toString(CryptoPy.enc.Base64))
```

### 文件加密

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

### 大文件流式哈希

```python
import CryptoPy

sha256 = CryptoPy.algo.SHA256.create()
with open("largefile.bin", "rb") as f:
    for chunk in iter(lambda: f.read(8192), b""):
        wa = CryptoPy.lib.WordArray.create(list(chunk), len(chunk))
        sha256.update(wa)
print("File SHA256:", sha256.finalize())
```

### 跨语言互操作 (CryptoJS ↔ CryptoPy)

```javascript
// JavaScript (CryptoJS)
var enc = CryptoJS.AES.encrypt("Hello", "password");
console.log(enc.toString());
// 输出: U2FsdGVkX1/...
```

```python
# Python (CryptoPy)
import CryptoPy
enc = "U2FsdGVkX1/..."  # 粘贴上面输出的值
dec = CryptoPy.AES.decrypt(enc, "password")
print(CryptoPy.enc.Utf8.stringify(dec))
# 输出: Hello
```

## CryptoJS 对照表

| CryptoJS | CryptoPy |
|----------|----------|
| `CryptoJS.MD5("msg")` | `CryptoPy.MD5("msg")` |
| `CryptoJS.AES.encrypt(...)` | `CryptoPy.AES.encrypt(...)` |
| `CryptoJS.enc.Utf8.parse("s")` | `CryptoPy.enc.Utf8.parse("s")` |
| `CryptoJS.lib.WordArray.create([...])` | `CryptoPy.lib.WordArray.create([...])` |
| `CryptoJS.algo.SHA256.create()` | `CryptoPy.algo.SHA256.create()` |
| `CryptoJS.algo.HMAC.create(...)` | `CryptoPy.algo.HMAC.create(...)` |
| `CryptoJS.mode.CBC` | `CryptoPy.mode.CBC` |
| `CryptoJS.pad.Pkcs7` | `CryptoPy.pad.Pkcs7` |
| `CryptoJS.format.OpenSSL` | `CryptoPy.format.OpenSSL` |

## 开发

```bash
# 运行测试
PYTHONPATH=src python3 tests/test_all.py

# 打包
python3 -m build --sdist

# 发布
python3 -m twine upload dist/*
```

## 许可证

MIT
