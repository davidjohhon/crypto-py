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
Crypto.MD5("Message")
Crypto.SHA1("Message")
Crypto.SHA256("Message")
Crypto.SHA224("Message")
Crypto.SHA384("Message")
Crypto.SHA512("Message")
Crypto.SHA3("Message", {"outputLength": 256})
Crypto.RIPEMD160("Message")
Crypto.SM3("Message")
```

**输入**: `str` 或 `WordArray`。

**输出**: `WordArray`。`str()` 或 `.toString()` 得到 hex 字符串。

```python
h = Crypto.SHA256("Message")
print(h)                             # hex
h.toString(Crypto.enc.Base64)      # Base64
h.toString(Crypto.enc.Hex)         # Hex（默认）
```

### SHA3 说明

> SHA3 实现的是原始 **Keccak[c=2d]**（与 CryptoJS 一致），**非** FIPS 202 标准的 SHA-3。
> 两者区别在于填充前的域分隔字节：Keccak 使用 `0x01`，FIPS 202 SHA-3 使用 `0x06`。
> 即 `Crypto.SHA3("")` ≠ `hashlib.sha3_512(b"")`。

### 渐进式哈希

```python
sha256 = Crypto.algo.SHA256.create()
sha256.update("Message Part 1")
sha256.update("Message Part 2")
hash = sha256.finalize("Message Part 3")

# 等价于：
Crypto.SHA256("Message Part 1Message Part 2Message Part 3")
```

### 克隆哈希状态

```python
sha256 = Crypto.algo.SHA256.create()
sha256.update("a")
clone = sha256.clone()      # 复制当前状态
clone.finalize()             # SHA256("a")
sha256.update("b").finalize()  # SHA256("ab")
```

---

## HMAC

### 基础用法

```python
Crypto.HmacMD5("message", "key")
Crypto.HmacSHA1("message", "key")
Crypto.HmacSHA256("message", "key")
Crypto.HmacSHA224("message", "key")
Crypto.HmacSHA384("message", "key")
Crypto.HmacSHA512("message", "key")
Crypto.HmacSHA3("message", "key")
Crypto.HmacRIPEMD160("message", "key")
Crypto.HmacSM3("message", "key")
```

### 渐进式 HMAC

```python
hmac = Crypto.algo.HMAC.create(Crypto.algo.SHA256, "Secret Key")
hmac.update("Message Part 1")
hmac.update("Message Part 2")
hmac.finalize("Message Part 3")
```

---

## 加密算法

### AES

```python
# 密码加密（自动派生 Key 和 IV）
enc = Crypto.AES.encrypt("Message", "Secret Passphrase")
dec = Crypto.AES.decrypt(enc, "Secret Passphrase")
Crypto.enc.Utf8.stringify(dec)

# 自定义 Key 和 IV
key = Crypto.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = Crypto.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = Crypto.AES.encrypt("Message", key, {"iv": iv})
dec = Crypto.AES.decrypt(enc, key, {"iv": iv})

# 指定模式和填充
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
Crypto.SM4.encrypt("Message", "password")
Crypto.ZUC.encrypt("Message", "password")
```

### 渐进式加密

```python
key = Crypto.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = Crypto.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")

# 加密
enc = Crypto.algo.AES.createEncryptor(key, {"iv": iv})
c1 = enc.process("Message Part 1")
c2 = enc.process("Message Part 2")
c3 = enc.finalize("Message Part 3")

# 解密
dec = Crypto.algo.AES.createDecryptor(key, {"iv": iv})
p1 = dec.process(c1)
p2 = dec.process(c2)
p3 = dec.process(c3)
p4 = dec.finalize()
Crypto.enc.Utf8.stringify(p1.clone().concat(p2).concat(p3).concat(p4))
```

---

## 块密码模式

| 模式 | 描述 | 默认 |
|------|------|------|
| `Crypto.mode.CBC` | Cipher Block Chaining | ✓ |
| `Crypto.mode.CFB` | Cipher Feedback | |
| `Crypto.mode.CTR` | Counter | |
| `Crypto.mode.ECB` | Electronic Codebook | |
| `Crypto.mode.OFB` | Output Feedback | |

```python
Crypto.AES.encrypt("Message", "password", {"mode": Crypto.mode.CTR})
```

---

## 填充方案

| 方案 | 描述 | 默认 |
|------|------|------|
| `Crypto.pad.Pkcs7` | PKCS #5/#7 | ✓ |
| `Crypto.pad.AnsiX923` | ANSI X.923 | |
| `Crypto.pad.Iso10126` | ISO 10126（随机填充） | |
| `Crypto.pad.Iso97971` | ISO/IEC 9797-1 | |
| `Crypto.pad.ZeroPadding` | 补零 | |
| `Crypto.pad.NoPadding` | 无填充 | |

```python
Crypto.AES.encrypt("Message", "password", {"padding": Crypto.pad.Iso97971})
```

---

## 编码器

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

## 中国国家密码算法（商密）

### SM2 — 公钥密码

```python
sk, pk = Crypto.SM2.generate_keypair()
sig = Crypto.SM2.sign(sk, "message")
Crypto.SM2.verify(pk, "message", sig)
ct = Crypto.SM2.encrypt(pk, "secret")
pt = Crypto.SM2.decrypt(sk, ct)
```

### SM3 — 哈希

```python
Crypto.SM3("message")
```

### SM4 — 分组密码

```python
Crypto.SM4.encrypt("message", "password")
Crypto.SM4.decrypt(enc, "password")
```

### SM9 — 标识签名 (GM/T 0044-2016)

```python
# 生成主密钥
mpk, msk = Crypto.SM9.setup()

# 从用户标识生成私钥
user_key = Crypto.SM9.generate_user_key(msk, "alice@example.com")

# 签名
sig = Crypto.SM9.sign(user_key, "message")

# 验签
assert Crypto.SM9.verify(mpk, "alice@example.com", "message", sig)
assert not Crypto.SM9.verify(mpk, "bob@example.com", "message", sig)
```

基于身份标识的签名系统，基于 BN 曲线上的 R-ate 双线性配对实现。无需证书，密钥直接从用户标识（邮箱、手机号等）派生。零外部依赖。

| 输出 | 长度 |
|------|------|
| `master_pk` | 128 字节（G₂ 仿射坐标） |
| `master_sk` | 32 字节（标量） |
| `user_key` | 192 字节（usk G₁ + mpk G₂） |
| `signature` | 96 字节（h \|\| S.x \|\| S.y） |

### ZUC — 序列密码

```python
Crypto.ZUC.encrypt("message", "password")
Crypto.ZUC.decrypt(enc, "password")
```

## 密钥派生

### PBKDF2

```python
# 默认（SHA256, 250000 次迭代, 128 位密钥）
key = Crypto.PBKDF2("password", "salt")

# 完整参数（指定迭代数以加快测试）
key = Crypto.PBKDF2("password", "salt", {
    "keySize": 256 // 32,      # 输出密钥长度（字）
    "iterations": 1000,         # 迭代次数
    "hasher": Crypto.algo.SHA256,
})
```

> **性能提示**: 默认 250000 次迭代在 Python 中约需 2 分钟。测试时建议使用 `iterations=1000`。

### EvpKDF（OpenSSL EVP_BytesToKey）

```python
key = Crypto.EvpKDF("password", "salt")
key = Crypto.EvpKDF("password", "salt", {
    "keySize": 256 // 32,
    "hasher": Crypto.algo.MD5,
})
```

---

## WordArray

### 创建

```python
# 从字列表创建
wa = Crypto.lib.WordArray.create([0x12345678, 0x90abcdef])

# 指定有效字节数
wa = Crypto.lib.WordArray.create([0x12345678, 0x90abcdef], 5)

# 随机字节
rand = Crypto.lib.WordArray.random(16)
```

### 操作

```python
wa.toString()                              # hex
wa.toString(Crypto.enc.Base64)           # Base64
wa.toString(Crypto.enc.Hex)              # 显式 Hex
wa.toString(Crypto.enc.Latin1)           # Latin1 字符串
wa.toString(Crypto.enc.Utf8)             # UTF-8 字符串（需有效 UTF-8 数据）
clone = wa.clone()
wa.concat(other)
wa.clamp()
```

---

## 格式与序列化

### OpenSSL 格式（默认）

```python
enc = Crypto.AES.encrypt("Message", "password")
str(enc)  # "U2FsdGVkX1/..."（Base64，含"Salted__"前缀）

# 解密
Crypto.AES.decrypt(enc, "password")
```

### 自定义 JSON 格式

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

## 实际应用场景

### 文件完整性校验

```python
import Crypto

with open("file.bin", "rb") as f:
    data = f.read()

wa = Crypto.lib.WordArray.create(list(data), len(data))
digest = Crypto.SHA256(wa)
print("SHA256:", digest)
```

### 密码哈希存储

```python
import Crypto

salt = Crypto.lib.WordArray.random(16)
key = Crypto.PBKDF2("user_password", salt, {
    "keySize": 256 // 32,
    "iterations": 10000,
})
print("Derived key:", key.toString(Crypto.enc.Base64))
```

### 文件加密

```python
import Crypto

# 加密
enc = Crypto.AES.encrypt("Sensitive data", "password")
with open("secret.enc", "w") as f:
    f.write(str(enc))

# 解密
with open("secret.enc") as f:
    data = f.read()
dec = Crypto.AES.decrypt(data, "password")
print(Crypto.enc.Utf8.stringify(dec))
```

### 大文件流式哈希

```python
import Crypto

sha256 = Crypto.algo.SHA256.create()
with open("largefile.bin", "rb") as f:
    for chunk in iter(lambda: f.read(8192), b""):
        wa = Crypto.lib.WordArray.create(list(chunk), len(chunk))
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
dec = Crypto.AES.decrypt(enc, "password")
print(Crypto.enc.Utf8.stringify(dec))
# 输出: Hello
```

---

## 与 CryptoJS 对照

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

## 内部 API

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
