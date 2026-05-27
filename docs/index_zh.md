<p align="center">
  <a href="https://github.com/davidjohhon/crypto-py/blob/main/docs/index.md">🇬🇧 English</a>
</p>

# Crypto 完整 API 文档

## 导入

```python
import Crypto
```

所有 API 通过 `Crypto` 命名空间直接访问，风格与 CryptoJS 完全一致。

---

## 哈希算法

### 基础用法

```python
CryptoPy.MD5("Message")
CryptoPy.SHA1("Message")
CryptoPy.SHA256("Message")
CryptoPy.SHA224("Message")
CryptoPy.SHA384("Message")
CryptoPy.SHA512("Message")
CryptoPy.SHA3("Message", {"outputLength": 256})
CryptoPy.RIPEMD160("Message")
CryptoPy.SM3("Message")
```

**输入**: `str` 或 `WordArray`。

**输出**: `WordArray`。`str()` 或 `.toString()` 得到 hex 字符串。

```python
h = CryptoPy.SHA256("Message")
print(h)                             # hex
h.toString(CryptoPy.enc.Base64)      # Base64
h.toString(CryptoPy.enc.Hex)         # Hex（默认）
```

### SHA3 说明

> SHA3 实现的是原始 **Keccak[c=2d]**（与 CryptoJS 一致），**非** FIPS 202 标准的 SHA-3。
> 两者区别在于填充前的域分隔字节：Keccak 使用 `0x01`，FIPS 202 SHA-3 使用 `0x06`。
> 即 `CryptoPy.SHA3("")` ≠ `hashlib.sha3_512(b"")`。

### 渐进式哈希

```python
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("Message Part 1")
sha256.update("Message Part 2")
hash = sha256.finalize("Message Part 3")

# 等价于：
CryptoPy.SHA256("Message Part 1Message Part 2Message Part 3")
```

### 克隆哈希状态

```python
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("a")
clone = sha256.clone()      # 复制当前状态
clone.finalize()             # SHA256("a")
sha256.update("b").finalize()  # SHA256("ab")
```

---

## HMAC

### 基础用法

```python
CryptoPy.HmacMD5("message", "key")
CryptoPy.HmacSHA1("message", "key")
CryptoPy.HmacSHA256("message", "key")
CryptoPy.HmacSHA224("message", "key")
CryptoPy.HmacSHA384("message", "key")
CryptoPy.HmacSHA512("message", "key")
CryptoPy.HmacSHA3("message", "key")
CryptoPy.HmacRIPEMD160("message", "key")
CryptoPy.HmacSM3("message", "key")
```

### 渐进式 HMAC

```python
hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "Secret Key")
hmac.update("Message Part 1")
hmac.update("Message Part 2")
hmac.finalize("Message Part 3")
```

---

## 加密算法

### AES

```python
# 密码加密（自动派生 Key 和 IV）
enc = CryptoPy.AES.encrypt("Message", "Secret Passphrase")
dec = CryptoPy.AES.decrypt(enc, "Secret Passphrase")
CryptoPy.enc.Utf8.stringify(dec)

# 自定义 Key 和 IV
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = CryptoPy.AES.encrypt("Message", key, {"iv": iv})
dec = CryptoPy.AES.decrypt(enc, key, {"iv": iv})

# 指定模式和填充
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
CryptoPy.SM4.encrypt("Message", "password")
CryptoPy.ZUC.encrypt("Message", "password")
```

### 渐进式加密

```python
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")

# 加密
enc = CryptoPy.algo.AES.createEncryptor(key, {"iv": iv})
c1 = enc.process("Message Part 1")
c2 = enc.process("Message Part 2")
c3 = enc.finalize("Message Part 3")

# 解密
dec = CryptoPy.algo.AES.createDecryptor(key, {"iv": iv})
p1 = dec.process(c1)
p2 = dec.process(c2)
p3 = dec.process(c3)
p4 = dec.finalize()
CryptoPy.enc.Utf8.stringify(p1.clone().concat(p2).concat(p3).concat(p4))
```

---

## 块密码模式

| 模式 | 描述 | 默认 |
|------|------|------|
| `CryptoPy.mode.CBC` | Cipher Block Chaining | ✓ |
| `CryptoPy.mode.CFB` | Cipher Feedback | |
| `CryptoPy.mode.CTR` | Counter | |
| `CryptoPy.mode.ECB` | Electronic Codebook | |
| `CryptoPy.mode.OFB` | Output Feedback | |

```python
CryptoPy.AES.encrypt("Message", "password", {"mode": CryptoPy.mode.CTR})
```

---

## 填充方案

| 方案 | 描述 | 默认 |
|------|------|------|
| `CryptoPy.pad.Pkcs7` | PKCS #5/#7 | ✓ |
| `CryptoPy.pad.AnsiX923` | ANSI X.923 | |
| `CryptoPy.pad.Iso10126` | ISO 10126（随机填充） | |
| `CryptoPy.pad.Iso97971` | ISO/IEC 9797-1 | |
| `CryptoPy.pad.ZeroPadding` | 补零 | |
| `CryptoPy.pad.NoPadding` | 无填充 | |

```python
CryptoPy.AES.encrypt("Message", "password", {"padding": CryptoPy.pad.Iso97971})
```

---

## 编码器

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

## 中国国家密码算法（商密）

### SM2 — 公钥密码

```python
sk, pk = CryptoPy.SM2.generate_keypair()
sig = CryptoPy.SM2.sign(sk, "message")
CryptoPy.SM2.verify(pk, "message", sig)
ct = CryptoPy.SM2.encrypt(pk, "secret")
pt = CryptoPy.SM2.decrypt(sk, ct)
```

### SM3 — 哈希

```python
CryptoPy.SM3("message")
```

### SM4 — 分组密码

```python
CryptoPy.SM4.encrypt("message", "password")
CryptoPy.SM4.decrypt(enc, "password")
```

### SM9 — 标识签名 (GM/T 0044-2016)

```python
# 生成主密钥
mpk, msk = CryptoPy.SM9.setup()

# 从用户标识生成私钥
user_key = CryptoPy.SM9.generate_user_key(msk, "alice@example.com")

# 签名
sig = CryptoPy.SM9.sign(user_key, "message")

# 验签
assert CryptoPy.SM9.verify(mpk, "alice@example.com", "message", sig)
assert not CryptoPy.SM9.verify(mpk, "bob@example.com", "message", sig)
```

基于身份标识的签名系统，基于 BN 曲线上的 R-ate 双线性配对实现。无需证书，密钥直接从用户标识（邮箱、手机号等）派生。零外部依赖。

| 输出 | 长度 |
|------|------|
| `master_pk` | 128 字节（G₂ 仿射坐标） |
| `master_sk` | 32 字节（标量） |
| `user_key` | 192 字节（usk G₁ + mpk G₂） |
| `signature` | 96 字节（h \|\| S.x \|\| S.y） |

### RSA — 非对称加密 (PKCS#1 v1.5)

```python
# 生成密钥对
priv, pub = CryptoPy.RSA.generate_keypair(2048)

# 加密 / 解密
ct = CryptoPy.RSA.encrypt("secret data", pub)
pt = CryptoPy.RSA.decrypt(ct, priv)

# 数字签名 / 验签
sig = CryptoPy.RSA.sign("message", priv, CryptoPy.hash.SHA256)
ok  = CryptoPy.RSA.verify("message", sig, pub)  # 返回哈希算法名
```

RSA 公钥密码体制，PKCS#1 v1.5 填充方案。支持 MD5、SHA-1、SHA-256、SHA-384、SHA-512 签名。使用中国剩余定理加速解密。零外部依赖。

### ZUC — 序列密码

```python
CryptoPy.ZUC.encrypt("message", "password")
CryptoPy.ZUC.decrypt(enc, "password")
```

## 密钥派生

### PBKDF2

```python
# 默认（SHA256, 250000 次迭代, 128 位密钥）
key = CryptoPy.PBKDF2("password", "salt")

# 完整参数（指定迭代数以加快测试）
key = CryptoPy.PBKDF2("password", "salt", {
    "keySize": 256 // 32,      # 输出密钥长度（字）
    "iterations": 1000,         # 迭代次数
    "hasher": CryptoPy.algo.SHA256,
})
```

> **性能提示**: 默认 250000 次迭代在 Python 中约需 2 分钟。测试时建议使用 `iterations=1000`。

### EvpKDF（OpenSSL EVP_BytesToKey）

```python
key = CryptoPy.EvpKDF("password", "salt")
key = CryptoPy.EvpKDF("password", "salt", {
    "keySize": 256 // 32,
    "hasher": CryptoPy.algo.MD5,
})
```

---

## WordArray

### 创建

```python
# 从字列表创建
wa = CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef])

# 指定有效字节数
wa = CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef], 5)

# 随机字节
rand = CryptoPy.lib.WordArray.random(16)
```

### 操作

```python
wa.toString()                              # hex
wa.toString(CryptoPy.enc.Base64)           # Base64
wa.toString(CryptoPy.enc.Hex)              # 显式 Hex
wa.toString(CryptoPy.enc.Latin1)           # Latin1 字符串
wa.toString(CryptoPy.enc.Utf8)             # UTF-8 字符串（需有效 UTF-8 数据）
clone = wa.clone()
wa.concat(other)
wa.clamp()
```

---

## 格式与序列化

### OpenSSL 格式（默认）

```python
enc = CryptoPy.AES.encrypt("Message", "password")
str(enc)  # "U2FsdGVkX1/..."（Base64，含"Salted__"前缀）

# 解密
CryptoPy.AES.decrypt(enc, "password")
```

### 自定义 JSON 格式

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

## 实际应用场景

### 文件完整性校验

```python
import Crypto

with open("file.bin", "rb") as f:
    data = f.read()

wa = CryptoPy.lib.WordArray.create(list(data), len(data))
digest = CryptoPy.SHA256(wa)
print("SHA256:", digest)
```

### 密码哈希存储

```python
import Crypto

salt = CryptoPy.lib.WordArray.random(16)
key = CryptoPy.PBKDF2("user_password", salt, {
    "keySize": 256 // 32,
    "iterations": 10000,
})
print("Derived key:", key.toString(CryptoPy.enc.Base64))
```

### 文件加密

```python
import Crypto

# 加密
enc = CryptoPy.AES.encrypt("Sensitive data", "password")
with open("secret.enc", "w") as f:
    f.write(str(enc))

# 解密
with open("secret.enc") as f:
    data = f.read()
dec = CryptoPy.AES.decrypt(data, "password")
print(CryptoPy.enc.Utf8.stringify(dec))
```

### 大文件流式哈希

```python
import Crypto

sha256 = CryptoPy.algo.SHA256.create()
with open("largefile.bin", "rb") as f:
    for chunk in iter(lambda: f.read(8192), b""):
        wa = CryptoPy.lib.WordArray.create(list(chunk), len(chunk))
        sha256.update(wa)
print("File SHA256:", sha256.finalize())
```

### 跨语言互操作（CryptoJS ↔ Crypto）

```javascript
// JavaScript (CryptoJS)
var enc = CryptoJS.AES.encrypt("Hello", "password");
console.log(enc.toString());
// 输出: U2FsdGVkX1/...
```

```python
# Python (Crypto)
import Crypto
enc = "U2FsdGVkX1/..."  # 粘贴上面输出的值
dec = CryptoPy.AES.decrypt(enc, "password")
print(CryptoPy.enc.Utf8.stringify(dec))
# 输出: Hello
```

---

## 与 CryptoJS 对照

| CryptoJS | Crypto |
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

## 内部 API

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

## 开发

```bash
# 运行测试
PYTHONPATH=src python3 tests/test_all.py

# 打包
python3 -m build --sdist

# 发布
python3 -m twine upload dist/*
```

---

*发现 Bug？请在 GitHub 提交 Issue → [github.com/davidjohhon/crypto-py/issues](https://github.com/davidjohhon/crypto-py/issues)*
