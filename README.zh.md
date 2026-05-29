<p align="center">
  <a href="https://github.com/davidjohhon/crypto-py/blob/main/README.md">🇬🇧 English</a>
</p>

# CryptoPy

> 感谢 [CryptoJS](https://github.com/brix/crypto-js) 团队——本项目是他们的 JavaScript 加密库的 Python 移植版。所有算法设计、API 模式及测试向量均源自他们的工作。

Python 密码学算法库，零外部依赖。涵盖摘要算法（MD5, SHA-1/256/512, SM3）、对称加密（AES, DES, SM4）和非对称加密（RSA, SM2, SM9）。兼容 CryptoJS API。

## 安装

```bash
pip install crypto4py
```

## 数据类型

CryptoPy 使用 **WordArray**（32 位字数组 + 字节数）作为通用二进制数据类型，与 crypto-js 完全一致。

### 类型转换表

| 从 → 到 | 代码 | 说明 |
|-----------|------|------|
| `str` → WordArray | `enc.Utf8.parse(s)` | `enc.Utf8.parse("Hello")` |
| `hex` → WordArray | `enc.Hex.parse(h)` | `enc.Hex.parse("48656c6c6f")` |
| `bytes` → WordArray | `CryptoPy.util.bytes_to_wa(b)` | `CryptoPy.util.bytes_to_wa(b"Hello")` |
| WordArray → `str` | `wa.toString(enc.Utf8)` | `"Hello"` |
| WordArray → `hex` | `wa.toString()` 或 `str(wa)` | `"48656c6c6f"` |
| WordArray → `Base64` | `wa.toString(enc.Base64)` | `"SGVsbG8="` |
| WordArray → `bytes` | `bytes(wa)` | 原始字节 |
| WordArray 长度 | `len(wa)` | 字节数 |

### 完整 WordArray 示例

```python
# 从不同来源创建 WordArray
from_hex = CryptoPy.enc.Hex.parse("48656c6c6f")
from_utf8 = CryptoPy.enc.Utf8.parse("Hello")
from_b64 = CryptoPy.enc.Base64.parse("SGVsbG8=")

# bytes → WordArray（使用内置工具函数）
wa = CryptoPy.util.bytes_to_wa(b"Hello")

# 输出转换
from_hex.toString()                                # "48656c6c6f"
from_hex.toString(CryptoPy.enc.Base64)              # "SGVsbG8="
from_hex.toString(CryptoPy.enc.Utf8)               # "Hello"
bytes(from_hex)                                     # 原始字节

# 属性
len(from_hex)      # 5
from_hex.words     # [0x48656c6c, 0x6f000000]
from_hex.sigBytes  # 5
```

## 快速开始

```python
import CryptoPy
# or: from CryptoPy import AES, MD5, SHA256, SM2, RSA, enc, mode, pad

# ── 哈希 ──
digest = CryptoPy.MD5("Message")
print(digest)                                   # hex
print(digest.toString(CryptoPy.enc.Base64))     # Base64
print(bytes(digest).hex())                      # 原始字节

CryptoPy.SHA1("Message")
CryptoPy.SHA256("Message")
CryptoPy.SHA3("Message", {"outputLength": 256})
CryptoPy.SM3("SM3 message")

# ── HMAC ──
tag = CryptoPy.HmacSHA256("Message", "Secret Key")
print(tag.toString(CryptoPy.enc.Base64))

# ── AES 加密（密码模式）──
enc = CryptoPy.AES.encrypt("My secret data", "password")
dec = CryptoPy.AES.decrypt(enc, "password")
print(CryptoPy.enc.Utf8.stringify(dec))

# ── AES 加密（自定义 Key/IV）──
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = CryptoPy.AES.encrypt("Message", key, {"iv": iv})
dec = CryptoPy.AES.decrypt(enc, key, {"iv": iv})

# ── SM4（与 AES 相同模式）──
enc = CryptoPy.SM4.encrypt("plaintext", "password")
dec = CryptoPy.SM4.decrypt(enc, "password")

# ── 编码器 ──
words = CryptoPy.enc.Hex.parse("48656c6c6f")
print(CryptoPy.enc.Base64.stringify(words))      # "SGVsbG8="
print(words.toString(CryptoPy.enc.Utf8))         # "Hello"

# ── 渐进式哈希 ──
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("Part 1").update("Part 2")
sha256.finalize("Part 3")

# ── 渐进式 HMAC ──
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "key")
hmac.update("Part 1").update("Part 2")
hmac.finalize()
```

## API 参考

### 哈希算法

所有哈希函数接受 `str`, `bytes`, 或 `WordArray`，返回 **WordArray**。

| 函数 | 返回 | 默认输出 | 示例 |
|----------|--------|---------|---------|
| `CryptoPy.MD5(s)` | **WordArray** | hex | `CryptoPy.MD5("abc")` |
| `CryptoPy.SHA1(s)` | **WordArray** | hex | |
| `CryptoPy.SHA256(s)` | **WordArray** | hex | |
| `CryptoPy.SHA224(s)` | **WordArray** | hex | |
| `CryptoPy.SHA384(s)` | **WordArray** | hex | |
| `CryptoPy.SHA512(s)` | **WordArray** | hex | |
| `CryptoPy.SHA3(s, cfg)` | **WordArray** | hex | `{"outputLength":256}` |
| `CryptoPy.RIPEMD160(s)` | **WordArray** | hex | |
| `CryptoPy.SM3(s)` | **WordArray** | hex | |

```python
digest = CryptoPy.SHA256("message")
digest = CryptoPy.SHA256(b"message")             # bytes 自动转换

# 输出转换
digest.toString()                               # hex
digest.toString(CryptoPy.enc.Base64)            # Base64
bytes(digest)                                   # 32 字节
len(digest)                                     # 32

# 渐进式
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("chunk 1").update("chunk 2")
digest = sha256.finalize("chunk 3")
```

### HMAC

| 函数 | 返回 | 默认 |
|----------|--------|---------|
| `HmacMD5("m","k")` | **WordArray** | hex |
| `HmacSHA1("m","k")` | **WordArray** | hex |
| `HmacSHA256("m","k")` | **WordArray** | hex |
| `HmacSHA384("m","k")` | **WordArray** | hex |
| `HmacSHA512("m","k")` | **WordArray** | hex |
| `HmacSM3("m","k")` | **WordArray** | hex |

```python
tag = CryptoPy.HmacSHA256("message", "secret key")
tag.toString()                                # hex
tag.toString(CryptoPy.enc.Base64)             # Base64
bytes(tag)                                    # 32 字节
len(tag)                                      # 32

# bytes 输入
tag = CryptoPy.HmacSHA256(b"message", b"key")

# WordArray 密钥
key_wa = CryptoPy.enc.Hex.parse("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
tag = CryptoPy.HmacSHA256("message", key_wa)

# 渐进式
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "key")
hmac.update("part1").update("part2")
tag = hmac.finalize("part3")
```

### 对称加密

| 算法 | 类型 | 密钥长度 | 分组大小 |
|--------|------|----------|------------|
| `AES` | Block | 128/192/256 bits | 16 bytes |
| `DES` | Block | 64 bits | 8 bytes |
| `TripleDES` | Block | 128/192 bits | 8 bytes |
| `SM4` | Block | 128 bits | 16 bytes |
| `Rabbit` | Stream | 128 bits | — |
| `RC4` | Stream | 40-2048 bits | — |
| `ZUC` | Stream | 128 bits | — |

```python
# 密码模式
enc = CryptoPy.AES.encrypt("plaintext", "password")
dec = CryptoPy.AES.decrypt(enc, "password")
str(enc)                                      # OpenSSL 格式
dec.toString(CryptoPy.enc.Utf8)               # 原文

# 自定义 Key/IV
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = CryptoPy.AES.encrypt("message", key, {"iv": iv, "mode": CryptoPy.mode.CBC})
dec = CryptoPy.AES.decrypt(enc, key, {"iv": iv, "mode": CryptoPy.mode.CBC})

# SM4
enc = CryptoPy.SM4.encrypt("message", "password")
dec = CryptoPy.SM4.decrypt(enc, "password")

# DES / TripleDES
key = CryptoPy.enc.Hex.parse("0123456789abcdef")
enc = CryptoPy.DES.encrypt("plaintext", key, {"mode": CryptoPy.mode.ECB})
dec = CryptoPy.DES.decrypt(enc, key, {"mode": CryptoPy.mode.ECB})

key3 = CryptoPy.enc.Hex.parse("0123456789abcdef0123456789abcdef")
enc = CryptoPy.TripleDES.encrypt("plaintext", key3, {"mode": CryptoPy.mode.ECB})
dec = CryptoPy.TripleDES.decrypt(enc, key3, {"mode": CryptoPy.mode.ECB})

# 流密码 (Rabbit, RC4, ZUC)
enc = CryptoPy.Rabbit.encrypt("message", "password")
dec = CryptoPy.Rabbit.decrypt(enc, "password")
```

| 操作 | 返回 | `str()` | `bytes()` |
|-----------|--------|---------|-----------|
| `AES.encrypt("m","p")` | **CipherParams** | OpenSSL | ❌ |
| `AES.decrypt(enc,"p")` | **WordArray** | hex | 原文 bytes |

### SM2 — 公钥密码 (GM/T 0003-2012)

```python
# 密钥生成
sk, pk = CryptoPy.SM2.generate_keypair()     # → (WordArray, WordArray)
sk.toString()                                 # 64 hex chars
pk.toString()                                 # 128 hex chars

# 签名/验签
sig = CryptoPy.SM2.sign("message", sk)        # → WordArray
assert CryptoPy.SM2.verify("message", sig, pk)

# 加密/解密
ct = CryptoPy.SM2.encrypt("secret data", pk)  # → WordArray
pt = CryptoPy.SM2.decrypt(ct, sk)            # → bytes

# 密钥持久化（hex 存储）
sk_hex = sk.toString()
pk_hex = pk.toString()
sk2 = CryptoPy.enc.Hex.parse(sk_hex)
pk2 = CryptoPy.enc.Hex.parse(pk_hex)
sig2 = CryptoPy.SM2.sign("new msg", sk2)
assert CryptoPy.SM2.verify("new msg", sig2, pk2)
```

### SM9 — 标识密码 (GM/T 0044-2016)

```python
# 主密钥
mpk, msk = CryptoPy.SM9.setup()              # → (WordArray, WordArray)

# 用户密钥派生
usk = CryptoPy.SM9.generate_user_key(msk, b"alice@example.com")

# 签名/验签
sig = CryptoPy.SM9.sign(b"message", usk)      # → WordArray
ok  = CryptoPy.SM9.verify(b"message", sig, mpk, b"alice@example.com")
```

### RSA — 非对称加密 (PKCS#1 v1.5)

```python
# 密钥生成
priv, pub = CryptoPy.RSA.generate_keypair(2048)

# 加密/解密
ct = CryptoPy.RSA.encrypt("message", pub)     # → WordArray
pt = CryptoPy.RSA.decrypt(ct, priv)          # → bytes

ct.toString()                                 # 密文 hex
bytes(ct)                                     # 密文 bytes

# 签名/验签
sig = CryptoPy.RSA.sign("message", priv, CryptoPy.hash.SHA256)  # → WordArray
ok  = CryptoPy.RSA.verify("message", sig, pub)  # True / raises Error

# 密钥持久化
priv_hex = priv.toString()
pub_hex = pub.toString()
priv2 = CryptoPy.enc.Hex.parse(priv_hex)
pub2 = CryptoPy.enc.Hex.parse(pub_hex)
```

### 密钥派生

```python
# PBKDF2
key = CryptoPy.PBKDF2("password", "salt", {
    "keySize": 256 // 32,
    "iterations": 10000,
})
key.toString()                                # hex
key.toString(CryptoPy.enc.Base64)             # Base64
bytes(key)                                    # 密钥原始字节

# EvpKDF
key = CryptoPy.EvpKDF("password", "salt")
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

### 哈希枚举（用于 RSA.sign）

```python
CryptoPy.hash.MD5     # "MD5"
CryptoPy.hash.SHA1    # "SHA-1"
CryptoPy.hash.SHA256  # "SHA-256"
CryptoPy.hash.SHA384  # "SHA-384"
CryptoPy.hash.SHA512  # "SHA-512"
```

## 实际应用场景

### 文件完整性校验

```python
import CryptoPy

with open("file.bin", "rb") as f:
    data = f.read()

digest = CryptoPy.SHA256(data)                # bytes 自动转换
print("SHA256:", digest)
print("SHA256 Base64:", digest.toString(CryptoPy.enc.Base64))
```

### HMAC API 认证

```python
import CryptoPy

secret = "api-secret-key"
message = "user=alice&time=12345"
token = CryptoPy.HmacSHA256(message, secret)
print("Token:", token.toString(CryptoPy.enc.Base64))
```

### PBKDF2 + AES 组合加密

```python
import CryptoPy, json

salt = CryptoPy.lib.WordArray.random(16)
aes_key = CryptoPy.PBKDF2("my password", salt, {
    "keySize": 256 // 32, "iterations": 10000,
})
iv = CryptoPy.lib.WordArray.random(16)
ct = CryptoPy.AES.encrypt("Sensitive data", aes_key, {"iv": iv})

stored = json.dumps({
    "salt": salt.toString(),
    "iv": iv.toString(),
    "ct": str(ct),
})
```

### SM2 密钥持久化

```python
import CryptoPy

sk, pk = CryptoPy.SM2.generate_keypair()
with open("sm2_private.key", "w") as f:
    f.write(sk.toString())
with open("sm2_public.key", "w") as f:
    f.write(pk.toString())

sk2 = CryptoPy.enc.Hex.parse(open("sm2_private.key").read())
pk2 = CryptoPy.enc.Hex.parse(open("sm2_public.key").read())
sig = CryptoPy.SM2.sign("test", sk2)
assert CryptoPy.SM2.verify("test", sig, pk2)
```

### SM9 身份签名

```python
import CryptoPy

mpk, msk = CryptoPy.SM9.setup()
usk = CryptoPy.SM9.generate_user_key(msk, b"alice@company.com")

doc = b"Contract #1234 - Payment approved"
sig = CryptoPy.SM9.sign(doc, usk)
ok = CryptoPy.SM9.verify(doc, sig, mpk, b"alice@company.com")
print(f"Signature valid: {ok}")
```

### RSA 文件加密

```python
import CryptoPy

priv, pub = CryptoPy.RSA.generate_keypair(2048)
ct = CryptoPy.RSA.encrypt(b"Secret message", pub)
with open("rsa_encrypted.bin", "wb") as f:
    f.write(bytes(ct))

ct_data = open("rsa_encrypted.bin", "rb").read()
pt = CryptoPy.RSA.decrypt(ct_data, priv)
print("Decrypted:", pt)
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
| `CryptoJS.mode.CBC` | `CryptoPy.mode.CBC` |
| `CryptoJS.pad.Pkcs7` | `CryptoPy.pad.Pkcs7` |
| `CryptoJS.kdf.OpenSSL.execute(...)` | `CryptoPy.kdf.OpenSSL.execute(...)` |
| `CryptoJS.PBKDF2("p","s")` | `CryptoPy.PBKDF2("p","s")` |
| `CryptoJS.lib.WordArray.random(16)` | `CryptoPy.lib.WordArray.random(16)` |

## 开发

```bash
PYTHONPATH=src python3 tests/test_all.py
python3 -m build --sdist
python3 -m twine upload dist/*
```

## 标准合规

已完成 179 项交叉验证测试，对比以下独立第三方库：
- **Python**: hashlib, hmac, base64, pycryptodome, gmssl-python, gmalg
- **JavaScript (npm)**: crypto-js, node-forge, @li0ard/zuc, GmSSL-JS
- **C**: GmSSL (编译参考实现)
- **Node.js**: crypto 内置模块

完整报告：`demo/cross_validate_report.md`。

## 参考来源

| 算法分类 | 来源 |
|----------|------|
| 基础库 (MD5, SHA, AES 等) | [brix/crypto-js](https://github.com/brix/crypto-js) |
| RSA (PKCS#1 v1.5) | [sybrenstuvel/python-rsa](https://github.com/sybrenstuvel/python-rsa) |
| SM2 / SM3 / SM4 / SM9 | [guanzhi/GmSSL](https://github.com/guanzhi/GmSSL) (C), [GmSSL-JS](https://github.com/guanzhi/GmSSL-JS) (JS) |
| SM9 | [gmalg](https://github.com/ww-rm/gmalg) (Python) |
| ZUC | [@li0ard/zuc](https://github.com/li0ard/zuc) (TS), [gmalg](https://github.com/ww-rm/gmalg) (Python) |
| RSA | [node-forge](https://github.com/digitalbazaar/forge) (JS), [pycryptodome](https://www.pycryptodome.org) (Python) |
| AES, DES, TripleDES | Node.js built-in `crypto`, [crypto-js](https://github.com/brix/crypto-js) (JS) |
| Rabbit, RC4 | [crypto-js](https://github.com/brix/crypto-js) (JS) |
| SHA1, MD5, HMAC | Node.js built-in `crypto` |

## 许可证

MIT

---

*发现 Bug？请在 GitHub 提交 Issue → [github.com/davidjohhon/crypto-py/issues](https://github.com/davidjohhon/crypto-py/issues)*
