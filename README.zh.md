<p align="center">
  <a href="https://github.com/davidjohhon/crypto-py/blob/main/README.md">🇬🇧 English</a>
</p>

# Crypto

> 🙏 感谢 [CryptoJS](https://github.com/brix/crypto-js) 团队——本项目是他们的 JavaScript 加密库的 Python 移植版。所有算法设计、API 模式及测试向量均源自他们的工作。

Python 实现的加密算法库，从 [CryptoJS](https://github.com/brix/crypto-js) 移植，API 完全兼容。零外部依赖。

## 安装

```bash
pip install crypto4py
```

## 快速开始

```python
import Crypto

# 哈希
digest = Crypto.MD5("Message")
print(digest)                                   # hex 字符串
print(digest.toString(Crypto.enc.Base64))     # Base64
print(digest.toString(Crypto.enc.Hex))        # 显式 Hex

Crypto.SHA256("Message")
Crypto.SHA3("Message", {"outputLength": 256})

# HMAC
Crypto.HmacSHA256("Message", "Secret Key")

# AES 加密/解密
enc = Crypto.AES.encrypt("My secret data", "password")
dec = Crypto.AES.decrypt(enc, "password")
print(Crypto.enc.Utf8.stringify(dec))  # "My secret data"

# 自定义 Key 和 IV
key = Crypto.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = Crypto.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = Crypto.AES.encrypt("Message", key, {"iv": iv})
dec = Crypto.AES.decrypt(enc, key, {"iv": iv})

# 渐进式哈希
sha256 = Crypto.algo.SHA256.create()
sha256.update("Part 1").update("Part 2")
sha256.finalize("Part 3")

# 渐进式 HMAC
hmac = Crypto.algo.HMAC.create(Crypto.algo.SHA256, "key")
hmac.update("Part 1").update("Part 2")
hmac.finalize()
```

## API 参考

### 哈希算法

```python
Crypto.MD5("message")
Crypto.SHA1("message")
Crypto.SHA256("message")
Crypto.SHA224("message")
Crypto.SHA384("message")
Crypto.SHA512("message")
Crypto.SHA3("message", {"outputLength": 256})  # 224/256/384/512
Crypto.RIPEMD160("message")
```

> **注意**：`SHA3` 实现的是原始 Keccak[c=2d]（与 CryptoJS 一致），而非 FIPS 202 标准的 SHA-3。两者的区别在于填充前的域分隔字节不同。标准 `hashlib.sha3_512()` 的输出与此不同。

### toString 编码输出

```python
digest = Crypto.MD5("1")
print(digest)                                          # hex: c4ca4238...
print(digest.toString(Crypto.enc.Hex))               # hex: c4ca4238...
print(digest.toString(Crypto.enc.Base64))            # Base64: xMpCOKC5...
print(digest.toString(Crypto.enc.Latin1))            # Latin1 字符串

enc = Crypto.AES.encrypt("msg", "pass")
print(enc.toString(Crypto.enc.Hex))                  # 密文的 Hex
print(enc.toString(Crypto.enc.Base64))               # 密文的 Base64
print(enc.toString(Crypto.format.OpenSSL))           # OpenSSL 格式（默认）
```

### HMAC

```python
Crypto.HmacMD5("message", "key")
Crypto.HmacSHA1("message", "key")
Crypto.HmacSHA256("message", "key")
Crypto.HmacSHA224("message", "key")
Crypto.HmacSHA384("message", "key")
Crypto.HmacSHA512("message", "key")
Crypto.HmacSHA3("message", "key")
Crypto.HmacRIPEMD160("message", "key")

# 渐进式
hmac = Crypto.algo.HMAC.create(Crypto.algo.SHA256, "key")
hmac.update("Part 1")
hmac.finalize("Part 2")
```

### 加密算法

```python
Crypto.AES.encrypt("message", "password")
Crypto.AES.decrypt(encrypted, "password")
Crypto.DES.encrypt("message", "password")
Crypto.TripleDES.encrypt("message", "password")
Crypto.Rabbit.encrypt("message", "password")
Crypto.RC4.encrypt("message", "password")
```

### 块密码模式

```python
Crypto.mode.CBC   # 默认
Crypto.mode.ECB
Crypto.mode.CFB
Crypto.mode.OFB
Crypto.mode.CTR
```

### 填充方案

```python
Crypto.pad.Pkcs7        # 默认
Crypto.pad.ZeroPadding
Crypto.pad.AnsiX923
Crypto.pad.Iso10126
Crypto.pad.Iso97971
Crypto.pad.NoPadding
```

### 编码器

```python
Crypto.enc.Hex.parse("48656c6c6f")
Crypto.enc.Hex.stringify(wordArray)
Crypto.enc.Utf8.parse("Hello")
Crypto.enc.Utf8.stringify(wordArray)
Crypto.enc.Base64.parse("SGVsbG8=")
Crypto.enc.Base64.stringify(wordArray)
Crypto.enc.Utf16.parse("Hello")
Crypto.enc.Utf16LE.parse("Hello")
```

### 中国国家密码算法（商密）

#### SM3 — 哈希 (GM/T 0004-2012)

```python
Crypto.SM3("message")  # 256 位哈希
```

中国国家密码标准哈希算法，安全等级等同 SHA-256。

#### SM4 — 分组密码 (GM/T 0002-2012)

```python
Crypto.SM4.encrypt("message", "password")
Crypto.SM4.decrypt(encrypted, "password")
```

128 位分组密码，32 轮迭代。在中国商用密码中替换 AES。

#### ZUC — 序列密码 (GM/T 0001-2012)

```python
Crypto.ZUC.encrypt("message", "password")
Crypto.ZUC.decrypt(encrypted, "password")
```

128 位流密码，4G/5G 移动通信标准核心算法。

#### SM2 — 公钥密码 (GM/T 0003-2012)

```python
sk, pk = Crypto.SM2.generate_keypair()
sig = Crypto.SM2.sign(sk, "message")
assert Crypto.SM2.verify(pk, "message", sig)
ct = Crypto.SM2.encrypt(pk, "secret")
pt = Crypto.SM2.decrypt(sk, ct)
```

256 位椭圆曲线公钥密码，支持数字签名、密钥交换、数据加密。在中国标准中替换 RSA。

#### SM9 — 标识密码 (GM/T 0044-2016)

```python
mpk, msk = Crypto.SM9.setup()
usk = Crypto.SM9.generate_user_key(msk, "alice@example.com")
sig = Crypto.SM9.sign(usk, "message")
Crypto.SM9.verify(mpk, "alice@example.com", "message", sig)
```

基于身份标识的签名系统，无需公钥证书，直接从用户标识（邮箱、手机号等）派生密钥。基于 BN 曲线上的 R-ate 配对实现，零外部依赖。从 GmSSL 移植。

### 密钥派生

```python
Crypto.PBKDF2("password", "salt")
Crypto.PBKDF2("password", "salt", {"keySize": 256//32, "iterations": 10000})
Crypto.EvpKDF("password", "salt")
```

## 实际应用场景

### 文件完整性校验

```python
import Crypto

with open("file.bin", "rb") as f:
    data = f.read()

wa = Crypto.lib.WordArray.create(list(data), len(data))
print("SHA256:", Crypto.SHA256(wa))
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

enc = Crypto.AES.encrypt("Sensitive data", "password")
with open("secret.enc", "w") as f:
    f.write(str(enc))

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

### 跨语言互操作 (CryptoJS ↔ Crypto)

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

## CryptoJS 对照表

| CryptoJS | Crypto |
|----------|----------|
| `CryptoJS.MD5("msg")` | `Crypto.MD5("msg")` |
| `CryptoJS.AES.encrypt(...)` | `Crypto.AES.encrypt(...)` |
| `CryptoJS.enc.Utf8.parse("s")` | `Crypto.enc.Utf8.parse("s")` |
| `CryptoJS.lib.WordArray.create([...])` | `Crypto.lib.WordArray.create([...])` |
| `CryptoJS.algo.SHA256.create()` | `Crypto.algo.SHA256.create()` |
| `CryptoJS.algo.HMAC.create(...)` | `Crypto.algo.HMAC.create(...)` |
| `CryptoJS.mode.CBC` | `Crypto.mode.CBC` |
| `CryptoJS.pad.Pkcs7` | `Crypto.pad.Pkcs7` |
| `CryptoJS.format.OpenSSL` | `Crypto.format.OpenSSL` |

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

---

*发现 Bug？请在 GitHub 提交 Issue → [github.com/davidjohhon/crypto-py/issues](https://github.com/davidjohhon/crypto-py/issues)*
