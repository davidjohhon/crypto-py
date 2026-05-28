import CryptoPy
import hashlib
import hmac
import base64
import json

print("=" * 60)
print("CryptoPy vs Python Standard Library 对比测试")
print("=" * 60)

test_message = "abc"
test_password = "password"
test_salt = b"salt"
test_key = "Secret Key"

results = []

def test(name, cryptopy_result, stdlib_result):
    status = "✓ PASS" if str(cryptopy_result) == str(stdlib_result) else "✗ FAIL"
    if status == "✗ FAIL":
        results.append((name, status, str(cryptopy_result), str(stdlib_result)))
    print(f"\n{name}: {status}")
    if status == "✗ FAIL":
        print(f"  CryptoPy: {cryptopy_result}")
        print(f"  Stdlib:   {stdlib_result}")

print("\n" + "=" * 60)
print("1. 哈希算法测试 (Hash Algorithms)")
print("=" * 60)

print("\n--- MD5 ---")
cp_md5 = CryptoPy.MD5(test_message)
py_md5 = hashlib.md5(test_message.encode()).hexdigest()
test("MD5", cp_md5, py_md5)

print("\n--- SHA1 ---")
cp_sha1 = CryptoPy.SHA1(test_message)
py_sha1 = hashlib.sha1(test_message.encode()).hexdigest()
test("SHA1", cp_sha1, py_sha1)

print("\n--- SHA256 ---")
cp_sha256 = CryptoPy.SHA256(test_message)
py_sha256 = hashlib.sha256(test_message.encode()).hexdigest()
test("SHA256", cp_sha256, py_sha256)

print("\n--- SHA224 ---")
cp_sha224 = CryptoPy.SHA224(test_message)
py_sha224 = hashlib.sha224(test_message.encode()).hexdigest()
test("SHA224", cp_sha224, py_sha224)

print("\n--- SHA384 ---")
cp_sha384 = CryptoPy.SHA384(test_message)
py_sha384 = hashlib.sha384(test_message.encode()).hexdigest()
test("SHA384", cp_sha384, py_sha384)

print("\n--- SHA512 ---")
cp_sha512 = CryptoPy.SHA512(test_message)
py_sha512 = hashlib.sha512(test_message.encode()).hexdigest()
test("SHA512", cp_sha512, py_sha512)

print("\n--- SHA3-256 ---")
cp_sha3_256 = CryptoPy.SHA3(test_message, {"outputLength": 256})
py_sha3_256 = hashlib.sha3_256(test_message.encode()).hexdigest()
test("SHA3-256 (CryptoPy uses Keccak, stdlib uses FIPS)", cp_sha3_256, py_sha3_256)

print("\n--- SHA3-512 ---")
cp_sha3_512 = CryptoPy.SHA3(test_message, {"outputLength": 512})
py_sha3_512 = hashlib.sha3_512(test_message.encode()).hexdigest()
test("SHA3-512 (CryptoPy uses Keccak, stdlib uses FIPS)", cp_sha3_512, py_sha3_512)

print("\n" + "=" * 60)
print("2. HMAC 测试")
print("=" * 60)

print("\n--- HMAC-MD5 ---")
cp_hmac_md5 = CryptoPy.HmacMD5(test_message, test_key)
py_hmac_md5 = hmac.new(test_key.encode(), test_message.encode(), hashlib.md5).hexdigest()
test("HmacMD5", cp_hmac_md5, py_hmac_md5)

print("\n--- HMAC-SHA256 ---")
cp_hmac_sha256 = CryptoPy.HmacSHA256(test_message, test_key)
py_hmac_sha256 = hmac.new(test_key.encode(), test_message.encode(), hashlib.sha256).hexdigest()
test("HmacSHA256", cp_hmac_sha256, py_hmac_sha256)

print("\n--- HMAC-SHA512 ---")
cp_hmac_sha512 = CryptoPy.HmacSHA512(test_message, test_key)
py_hmac_sha512 = hmac.new(test_key.encode(), test_message.encode(), hashlib.sha512).hexdigest()
test("HmacSHA512", cp_hmac_sha512, py_hmac_sha512)

print("\n" + "=" * 60)
print("3. 编码器测试 (Encoders)")
print("=" * 60)

print("\n--- Hex Encoder ---")
hex_str = "48656c6c6f"
words = CryptoPy.enc.Hex.parse(hex_str)
cp_hex = CryptoPy.enc.Hex.stringify(words)
py_hex = hex_str
test("Hex.stringify", cp_hex, py_hex)

print("\n--- Base64 Encoder ---")
b64_str = "SGVsbG8="
words = CryptoPy.enc.Base64.parse(b64_str)
cp_b64 = CryptoPy.enc.Base64.stringify(words)
py_b64 = base64.b64encode(base64.b64decode(b64_str)).decode()
test("Base64.stringify", cp_b64, b64_str)

print("\n--- Utf8 Encoder ---")
utf8_str = "Hello"
words = CryptoPy.enc.Utf8.parse(utf8_str)
cp_utf8 = CryptoPy.enc.Utf8.stringify(words)
py_utf8 = utf8_str
test("Utf8.parse/stringify", cp_utf8, py_utf8)

print("\n" + "=" * 60)
print("4. AES 加密解密测试")
print("=" * 60)

print("\n--- AES encrypt/decrypt roundtrip ---")
enc = CryptoPy.AES.encrypt("My secret data", test_password)
dec = CryptoPy.AES.decrypt(enc, test_password)
decrypted = CryptoPy.enc.Utf8.stringify(dec)
status = "✓ PASS" if decrypted == "My secret data" else "✗ FAIL"
print(f"AES encrypt/decrypt: {status}")
if status == "✗ FAIL":
    results.append(("AES encrypt/decrypt", status, decrypted, "My secret data"))

print("\n--- AES with custom key and IV ---")
key = CryptoPy.enc.Hex.parse("000102030405060708090a0b0c0d0e0f")
iv  = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")
enc = CryptoPy.AES.encrypt("Message", key, {"iv": iv})
dec = CryptoPy.AES.decrypt(enc, key, {"iv": iv})
decrypted = CryptoPy.enc.Utf8.stringify(dec)
status = "✓ PASS" if decrypted == "Message" else "✗ FAIL"
print(f"AES custom key/iv: {status}")
if status == "✗ FAIL":
    results.append(("AES custom key/iv", status, decrypted, "Message"))

print("\n" + "=" * 60)
print("5. PBKDF2 测试")
print("=" * 60)

print("\n--- PBKDF2 default ---")
salt = CryptoPy.lib.WordArray.create(list(b"salt"), 4)
cp_pbkdf2 = CryptoPy.PBKDF2("password", salt)
py_pbkdf2 = hashlib.pbkdf2_hmac('sha256', b"password", b"salt", 1)
py_pbkdf2_hex = py_pbkdf2.hex()
test("PBKDF2 (default SHA256, 1 iteration)", cp_pbkdf2, py_pbkdf2_hex)

print("\n--- PBKDF2 custom ---")
cp_pbkdf2_custom = CryptoPy.PBKDF2("password", salt, {"keySize": 256//32, "iterations": 1000})
py_pbkdf2_custom = hashlib.pbkdf2_hmac('sha256', b"password", b"salt", 1000)
py_pbkdf2_custom_hex = py_pbkdf2_custom.hex()
test("PBKDF2 (SHA256, 1000 iterations)", cp_pbkdf2_custom, py_pbkdf2_custom_hex)

print("\n" + "=" * 60)
print("6. Progressive Hashing 测试")
print("=" * 60)

print("\n--- Progressive SHA256 ---")
sha256 = CryptoPy.algo.SHA256.create()
sha256.update("Part 1").update("Part 2")
cp_progressive = sha256.finalize("Part 3")
py_progressive = hashlib.sha256(("Part 1" + "Part 2" + "Part 3").encode()).hexdigest()
test("Progressive SHA256", cp_progressive, py_progressive)

print("\n" + "=" * 60)
print("7. Progressive HMAC 测试")
print("=" * 60)

print("\n--- Progressive HMAC-SHA256 ---")
hmac_prog = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, test_key)
hmac_prog.update("Part 1").update("Part 2")
cp_hmac_prog = hmac_prog.finalize()
py_hmac_prog = hmac.new(test_key.encode(), ("Part 1" + "Part 2").encode(), hashlib.sha256).hexdigest()
test("Progressive HMAC-SHA256", cp_hmac_prog, py_hmac_prog)

print("\n" + "=" * 60)
print("8. WordArray 测试")
print("=" * 60)

print("\n--- WordArray create and toString ---")
wa = CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef], 5)
cp_wa_hex = wa.toString()
py_wa = "1234567890abcdef0000"
test("WordArray.create (5 bytes)", cp_wa_hex, py_wa)

print("\n--- WordArray random ---")
wa1 = CryptoPy.lib.WordArray.random(16)
wa2 = CryptoPy.lib.WordArray.random(16)
status = "✓ PASS" if str(wa1) != str(wa2) else "✗ FAIL (random values identical)"
print(f"WordArray.random: {status}")

print("\n" + "=" * 60)
print("9. 块模式测试 (Block Modes)")
print("=" * 60)

key_hex = "000102030405060708090a0b0c0d0e0f"
key = CryptoPy.enc.Hex.parse(key_hex)
iv = CryptoPy.enc.Hex.parse("101112131415161718191a1b1c1d1e1f")

for mode_name, mode in [
    ("CBC", CryptoPy.mode.CBC),
    ("CFB", CryptoPy.mode.CFB),
    ("CTR", CryptoPy.mode.CTR),
    ("ECB", CryptoPy.mode.ECB),
    ("OFB", CryptoPy.mode.OFB),
]:
    print(f"\n--- {mode_name} mode ---")
    try:
        enc = CryptoPy.AES.encrypt("Message", key, {"iv": iv, "mode": mode})
        dec = CryptoPy.AES.decrypt(enc, key, {"iv": iv, "mode": mode})
        decrypted = CryptoPy.enc.Utf8.stringify(dec)
        status = "✓ PASS" if decrypted == "Message" else "✗ FAIL"
        print(f"  AES.{mode_name}: {status}")
        if status == "✗ FAIL":
            results.append((f"AES.{mode_name}", status, decrypted, "Message"))
    except Exception as e:
        print(f"  AES.{mode_name}: ✗ FAIL (Exception: {e})")
        results.append((f"AES.{mode_name}", "✗ FAIL", str(e), "No exception"))

print("\n" + "=" * 60)
print("10. Padding 模式测试")
print("=" * 60)

for pad_name, pad in [
    ("Pkcs7", CryptoPy.pad.Pkcs7),
    ("AnsiX923", CryptoPy.pad.AnsiX923),
    ("Iso10126", CryptoPy.pad.Iso10126),
    ("Iso97971", CryptoPy.pad.Iso97971),
    ("ZeroPadding", CryptoPy.pad.ZeroPadding),
    ("NoPadding", CryptoPy.pad.NoPadding),
]:
    print(f"\n--- {pad_name} ---")
    try:
        enc = CryptoPy.AES.encrypt("Message", test_password, {"padding": pad})
        dec = CryptoPy.AES.decrypt(enc, test_password, {"padding": pad})
        decrypted = CryptoPy.enc.Utf8.stringify(dec)
        status = "✓ PASS" if decrypted == "Message" else "✗ FAIL"
        print(f"  AES.{pad_name}: {status}")
        if status == "✗ FAIL":
            results.append((f"AES.{pad_name}", status, decrypted, "Message"))
    except Exception as e:
        print(f"  AES.{pad_name}: ✗ FAIL (Exception: {e})")
        results.append((f"AES.{pad_name}", "✗ FAIL", str(e), "No exception"))

print("\n" + "=" * 60)
print("11. SM3 哈希测试")
print("=" * 60)

print("\n--- SM3 basic ---")
cp_sm3 = CryptoPy.SM3(test_message)
print(f"  SM3('abc'): {cp_sm3}")

print("\n" + "=" * 60)
print("12. SM4 加密测试")
print("=" * 60)

print("\n--- SM4 encrypt/decrypt ---")
try:
    enc = CryptoPy.SM4.encrypt("My secret data", test_password)
    dec = CryptoPy.SM4.decrypt(enc, test_password)
    decrypted = CryptoPy.enc.Utf8.stringify(dec)
    status = "✓ PASS" if decrypted == "My secret data" else "✗ FAIL"
    print(f"  SM4 encrypt/decrypt: {status}")
    if status == "✗ FAIL":
        results.append(("SM4 encrypt/decrypt", status, decrypted, "My secret data"))
except Exception as e:
    print(f"  SM4 encrypt/decrypt: ✗ FAIL (Exception: {e})")
    results.append(("SM4 encrypt/decrypt", "✗ FAIL", str(e), "Success"))

print("\n" + "=" * 60)
print("总结 (SUMMARY)")
print("=" * 60)

if results:
    print(f"\n✗ {len(results)} 个测试失败:\n")
    for name, status, got, expected in results:
        print(f"  - {name}")
        print(f"    Expected: {expected}")
        print(f"    Got:      {got}")
else:
    print("\n✓ 所有测试通过!")

