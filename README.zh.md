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

### 中国国家密码算法（商密）

#### SM3 — 哈希 (GM/T 0004-2012)

```python
CryptoPy.SM3("message")  # 256 位哈希
```

中国国家密码标准哈希算法，安全等级等同 SHA-256。

#### SM4 — 分组密码 (GM/T 0002-2012)

```python
CryptoPy.SM4.encrypt("message", "password")
CryptoPy.SM4.decrypt(encrypted, "password")
```

128 位分组密码，32 轮迭代。在中国商用密码中替换 AES。

#### ZUC — 序列密码 (GM/T 0001-2012)

```python
CryptoPy.ZUC.encrypt("message", "password")
CryptoPy.ZUC.decrypt(encrypted, "password")
```

128 位流密码，4G/5G 移动通信标准核心算法。

#### SM2 — 公钥密码 (GM/T 0003-2012)

```python
sk, pk = CryptoPy.SM2.generate_keypair()
sig = CryptoPy.SM2.sign(sk, "message")
assert CryptoPy.SM2.verify(pk, "message", sig)
ct = CryptoPy.SM2.encrypt(pk, "secret")
pt = CryptoPy.SM2.decrypt(sk, ct)
```

256 位椭圆曲线公钥密码，支持数字签名、密钥交换、数据加密。在中国标准中替换 RSA。

#### SM9 — 标识密码 (GM/T 0044-2016)

```python
mpk, msk = CryptoPy.SM9.setup()
usk = CryptoPy.SM9.generate_user_key(msk, "alice@example.com")
sig = CryptoPy.SM9.sign(usk, "message")
CryptoPy.SM9.verify(mpk, "alice@example.com", "message", sig)
```

基于身份标识的签名系统，无需公钥证书，直接从用户标识（邮箱、手机号等）派生密钥。基于 BN 曲线上的 R-ate 配对实现，零外部依赖。从 GmSSL 移植。

| 输出 | 长度 | 格式 |
|------|------|------|
| `mpk` | 128 字节 | `X.a0 \|\| X.a1 \|\| Y.a0 \|\| Y.a1` (G₂ 仿射) |
| `msk` | 32 字节 | 标量 mod N |
| `usk` | 192 字节 | `usk.X \|\| usk.Y (G₁ 仿射) \|\| mpk` |
| `sig` | 96 字节 | `h \|\| S.X \|\| S.Y` |

```python
mpk.hex()   # -> "hex字符串"  (128 bytes → 256 chars)
msk.hex()   # -> "hex字符串"  (32 bytes → 64 chars)
usk.hex()   # -> "hex字符串"  (192 bytes → 384 chars)
```

#### RSA — 非对称加密 (PKCS#1 v1.5)

```python
priv, pub = CryptoPy.RSA.generate_keypair(2048)
ct = CryptoPy.RSA.encrypt("message", pub)
pt = CryptoPy.RSA.decrypt(ct, priv)
sig = CryptoPy.RSA.sign("message", priv, CryptoPy.hash.SHA256)
ok  = CryptoPy.RSA.verify("message", sig, pub)
```

RSA 公钥密码体制，支持 PKCS#1 v1.5 填充方案。签名支持 MD5、SHA-1、SHA-256、SHA-384、SHA-512。使用中国剩余定理加速解密。零外部依赖。

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

## 标准合规与交叉验证

103 项交叉验证测试已通过（对比 Python stdlib、pycryptodome、gmssl-python）。完整报告：`demo/cross_validate_report.md`。

| 算法分类 | 测试向量 | hashlib/hmac | pycryptodome | gmssl-python | 状态 |
|---|---|---|---|---|---|
| MD5, SHA-1, SHA-256/384/512 | ✓ | ✓ | ✓ | N/A | ✅ 已验证 |
| SHA224, RIPEMD160 | ✓ | ✓ | ✓ | N/A | ✅ 已验证 |
| SHA3 (Keccak / FIPS) | ✓ | ✓ (sha3) | ✓ (sha3) | N/A | ✅ 两种均支持 |
| HMAC (全部) | ✓ | ✓ | ✓ | N/A | ✅ 已验证 |
| AES (ECB/CBC/CFB/OFB/CTR) | ✓ | N/A | ✓ | N/A | ✅ 已验证 |
| DES, TripleDES | ✓ | N/A | ✓ | N/A | ✅ 已验证 |
| PBKDF2, EvpKDF | ✓ | ✓ | N/A | N/A | ✅ 已验证 |
| SM3 | ✓ | N/A | N/A | ✓ | ✅ 已验证 |
| SM4 | ✓ | N/A | N/A | ✓ | ✅ 已验证 |
| SM2 | ✓ | N/A | N/A | ✓ | ✅ 交叉验证 |
| SM9, ZUC | ✓ | N/A | N/A | N/A | ✅ 自洽一致 |
| RSA (PKCS#1 v1.5) | ✓ | N/A | ✓ | N/A | ✅ 交叉验证 |
| 渐进式 API | ✓ | N/A | N/A | N/A | ✅ 已验证 |
| 编码器 (Base64, Hex, Utf8) | ✓ | ✓ | N/A | N/A | ✅ 已验证 |

## 参考来源

| 算法分类 | 来源 |
|----------|------|
| 基础库 (MD5, SHA, AES 等) | [brix/crypto-js](https://github.com/brix/crypto-js) |
| RSA (PKCS#1 v1.5) | [sybrenstuvel/python-rsa](https://github.com/sybrenstuvel/python-rsa) |
| SM2 / SM3 / SM4 / ZUC | [guanzhi/GmSSL](https://github.com/guanzhi/GmSSL) |
| SM9 (R-ate 配对) | [guanzhi/GmSSL](https://github.com/guanzhi/GmSSL) |

## 许可证

MIT

---

*发现 Bug？请在 GitHub 提交 Issue → [github.com/davidjohhon/crypto-py/issues](https://github.com/davidjohhon/crypto-py/issues)*
