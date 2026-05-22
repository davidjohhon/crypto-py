# CryptoPy 完整 API 文档

## 导入

```python
import CryptoPy
```

所有 API 通过 `CryptoPy` 命名空间直接访问，风格与 CryptoJS 完全一致。

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
```

**输入**: `str` 或 `WordArray`。

**输出**: `WordArray`。`str()` 或 `.toString()` 得到 hex 字符串。

```python
h = CryptoPy.SHA256("Message")
print(h)                             # hex
h.toString(CryptoPy.enc.Base64)      # Base64
h.toString(CryptoPy.enc.Hex)         # Hex（默认）
```

### SHA3 输出长度

```python
CryptoPy.SHA3("Message", {"outputLength": 512})  # 默认
CryptoPy.SHA3("Message", {"outputLength": 384})
CryptoPy.SHA3("Message", {"outputLength": 256})
CryptoPy.SHA3("Message", {"outputLength": 224})
```

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

### DES

```python
CryptoPy.DES.encrypt("Message", "Secret Passphrase")
CryptoPy.DES.decrypt(encrypted, "Secret Passphrase")
```

### TripleDES

```python
CryptoPy.TripleDES.encrypt("Message", "Secret Passphrase")
CryptoPy.TripleDES.decrypt(encrypted, "Secret Passphrase")
```

### Rabbit

```python
CryptoPy.Rabbit.encrypt("Message", "Key")
CryptoPy.Rabbit.decrypt(encrypted, "Key")

CryptoPy.RabbitLegacy.encrypt("Message", "Key")  # 旧版兼容
```

### RC4 / RC4Drop

```python
CryptoPy.RC4.encrypt("Message", "Key")
CryptoPy.RC4Drop.encrypt("Message", "Key")

# 自定义丢弃字数
CryptoPy.RC4Drop.encrypt("Message", "Key", {"drop": 3072 // 4})
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

### Hex

```python
words = CryptoPy.enc.Hex.parse("48656c6c6f")     # "Hello"
hex_str = CryptoPy.enc.Hex.stringify(words)       # "48656c6c6f"
```

### Utf8

```python
words = CryptoPy.enc.Utf8.parse("Hello, World!")
utf8_str = CryptoPy.enc.Utf8.stringify(words)
```

### Latin1

```python
words = CryptoPy.enc.Latin1.parse("Hello")
latin1_str = CryptoPy.enc.Latin1.stringify(words)
```

### Base64

```python
words = CryptoPy.enc.Base64.parse("SGVsbG8sIFdvcmxkIQ==")
b64_str = CryptoPy.enc.Base64.stringify(words)
```

### Base64url

```python
words = CryptoPy.enc.Base64url.parse("SGVsbG8sIFdvcmxkIQ==", urlSafe=True)
b64url_str = CryptoPy.enc.Base64url.stringify(words, urlSafe=True)
```

### UTF-16

```python
words = CryptoPy.enc.Utf16.parse("Hello")       # 大端
s = CryptoPy.enc.Utf16.stringify(words)

words = CryptoPy.enc.Utf16LE.parse("Hello")     # 小端
s = CryptoPy.enc.Utf16LE.stringify(words)
```

---

## 密钥派生

### PBKDF2

```python
# 默认（SHA256, 1 次迭代, 128 位密钥）
key = CryptoPy.PBKDF2("password", "salt")

# 完整参数
key = CryptoPy.PBKDF2("password", "salt", {
    "keySize": 256 // 32,      # 输出密钥长度（字）
    "iterations": 1000,         # 迭代次数
    "hasher": CryptoPy.algo.SHA256,
})
```

### EvpKDF（OpenSSL EVP_BytesToKey）

```python
# 默认（MD5, 1 次迭代, 128 位密钥）
key = CryptoPy.EvpKDF("password", "salt")

key = CryptoPy.EvpKDF("password", "salt", {
    "keySize": 256 // 32,
    "hasher": CryptoPy.algo.MD5,
})
```

---

## WordArray

`WordArray` 是 CryptoPy 的核心数据结构，表示 32 位字数组。

### 创建

```python
from CryptoPy.core import WordArray

# 从字列表创建
wa = WordArray.create([0x12345678, 0x90abcdef])

# 指定有效字节数
wa = WordArray.create([0x12345678, 0x90abcdef], 5)

# 随机字节
rand = WordArray.random(16)

# 从编码器解析
wa = CryptoPy.enc.Hex.parse("48656c6c6f")
```

### 操作

```python
wa.toString()                              # hex
wa.toString(CryptoPy.enc.Base64)           # Base64
clone = wa.clone()
wa.concat(other)                           # 拼接
wa.clamp()                                 # 裁剪多余位
```

### 属性

```python
wa.words        # 32 位字列表
wa.sigBytes     # 有效字节数
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

### Hex 格式

```python
enc = CryptoPy.AES.encrypt("Message", "password", {"format": CryptoPy.format.Hex})
CryptoPy.AES.decrypt(enc, "password", {"format": CryptoPy.format.Hex})
```

### 自定义 JSON 格式

```python
class JsonFormatter:
    @staticmethod
    def stringify(cp):
        obj = {"ct": cp.ciphertext.toString(CryptoPy.enc.Base64)}
        if hasattr(cp, 'iv') and cp.iv:
            obj["iv"] = cp.iv.toString()
        if hasattr(cp, 'salt') and cp.salt:
            obj["s"] = cp.salt.toString()
        import json
        return json.dumps(obj)

    @staticmethod
    def parse(s):
        import json
        obj = json.loads(s)
        from CryptoPy.cipher_core import CipherParams
        cp = CipherParams.create({
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

## 内部 API

### lib

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
```

### algo

```python
CryptoPy.algo.MD5.create()
CryptoPy.algo.SHA256.create()
CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, "key")
CryptoPy.algo.AES.createEncryptor(key, cfg)
CryptoPy.algo.AES.createDecryptor(key, cfg)
```

### kdf

```python
CryptoPy.kdf.OpenSSL.execute(password, keySize, ivSize, salt, hasher)
```

---

## 与 CryptoJS 对照

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
