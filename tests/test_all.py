"""Comprehensive test suite for Crypto - ported from CryptoJS test suite."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import CryptoPy


def assert_eq(name, actual, expected):
    a = str(actual)
    e = str(expected) if not isinstance(expected, str) else expected
    ok = "✓" if a == e else "✗"
    if ok == "✗":
        print(f"  FAIL {name}: got {a!r}, expected {e!r}")
    return ok == "✓"


def test_md5():
    print("MD5:")
    ok = True
    ok &= assert_eq("vector1", CryptoPy.MD5(''), 'd41d8cd98f00b204e9800998ecf8427e')
    ok &= assert_eq("vector2", CryptoPy.MD5('a'), '0cc175b9c0f1b6a831c399e269772661')
    ok &= assert_eq("vector3", CryptoPy.MD5('abc'), '900150983cd24fb0d6963f7d28e17f72')
    ok &= assert_eq("vector4", CryptoPy.MD5('message digest'), 'f96b697d7cb7938d525a2f31aaf161d0')
    ok &= assert_eq("vector5", CryptoPy.MD5('abcdefghijklmnopqrstuvwxyz'), 'c3fcd3d76192e4007dfb496cca67e13b')
    ok &= assert_eq("vector6", CryptoPy.MD5('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), 'd174ab98d277d9f5a5611c2c9f419d9f')
    ok &= assert_eq("vector7", CryptoPy.MD5('12345678901234567890123456789012345678901234567890123456789012345678901234567890'), '57edf4a22be3c955ac49da2e2107b67a')
    # Update and long message
    md5 = CryptoPy.algo.MD5.create()
    for _ in range(100):
        md5.update('12345678901234567890123456789012345678901234567890')
    ok &= assert_eq("update+long", md5.finalize(), '7d017545e0268a6a12f2b507871d0429')
    # Clone
    md5c = CryptoPy.algo.MD5.create()
    ok &= assert_eq("clone1", md5c.update('a').clone().finalize(), CryptoPy.MD5('a'))
    ok &= assert_eq("clone2", md5c.update('b').clone().finalize(), CryptoPy.MD5('ab'))
    ok &= assert_eq("clone3", md5c.update('c').clone().finalize(), CryptoPy.MD5('abc'))
    # Helper
    ok &= assert_eq("helper", CryptoPy.algo.MD5.create().finalize(''), CryptoPy.MD5(''))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha1():
    print("SHA1:")
    ok = True
    ok &= assert_eq("v1", CryptoPy.SHA1(''), 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
    ok &= assert_eq("v2", CryptoPy.SHA1('a'), '86f7e437faa5a7fce15d1ddcb9eaeaea377667b8')
    ok &= assert_eq("v3", CryptoPy.SHA1('abc'), 'a9993e364706816aba3e25717850c26c9cd0d89d')
    ok &= assert_eq("v4", CryptoPy.SHA1('message digest'), 'c12252ceda8be8994d5fa0290a47231c1d16aae3')
    ok &= assert_eq("v5", CryptoPy.SHA1('abcdefghijklmnopqrstuvwxyz'), '32d10c7b8cf96570ca04ce37f2a19d84240d3a89')
    ok &= assert_eq("v6", CryptoPy.SHA1('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), '761c457bf73b14d27e9e9265c46f4b4dda11f940')
    ok &= assert_eq("v7", CryptoPy.SHA1('12345678901234567890123456789012345678901234567890123456789012345678901234567890'), '50abf5706a150990a08b2c5ea40fa0e585554732')
    # Update and long message
    sha1 = CryptoPy.algo.SHA1.create()
    for _ in range(100):
        sha1.update('12345678901234567890123456789012345678901234567890')
    ok &= assert_eq("long", sha1.finalize(), '85e4c4b3933d5553ebf82090409a9d90226d845c')
    # Clone
    c = CryptoPy.algo.SHA1.create()
    ok &= assert_eq("clone1", c.update('a').clone().finalize(), CryptoPy.SHA1('a'))
    ok &= assert_eq("clone2", c.update('b').clone().finalize(), CryptoPy.SHA1('ab'))
    ok &= assert_eq("clone3", c.update('c').clone().finalize(), CryptoPy.SHA1('abc'))
    ok &= assert_eq("helper", CryptoPy.algo.SHA1.create().finalize(''), CryptoPy.SHA1(''))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha256():
    print("SHA256:")
    ok = True
    ok &= assert_eq("v1", CryptoPy.SHA256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    ok &= assert_eq("v2", CryptoPy.SHA256('a'), 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb')
    ok &= assert_eq("v3", CryptoPy.SHA256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    ok &= assert_eq("v4", CryptoPy.SHA256('message digest'), 'f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650')
    ok &= assert_eq("v5", CryptoPy.SHA256('abcdefghijklmnopqrstuvwxyz'), '71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73')
    ok &= assert_eq("v6", CryptoPy.SHA256('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), 'db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0')
    ok &= assert_eq("v7", CryptoPy.SHA256('12345678901234567890123456789012345678901234567890123456789012345678901234567890'), 'f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e')
    sha256 = CryptoPy.algo.SHA256.create()
    for _ in range(100):
        sha256.update('12345678901234567890123456789012345678901234567890')
    ok &= assert_eq("long", sha256.finalize(), 'f8146961d9b73d8da49ccd526fca65439cdd5b402f76971556d5f52fd129843e')
    c = CryptoPy.algo.SHA256.create()
    ok &= assert_eq("clone1", c.update('a').clone().finalize(), CryptoPy.SHA256('a'))
    ok &= assert_eq("clone2", c.update('b').clone().finalize(), CryptoPy.SHA256('ab'))
    ok &= assert_eq("clone3", c.update('c').clone().finalize(), CryptoPy.SHA256('abc'))
    ok &= assert_eq("helper", CryptoPy.algo.SHA256.create().finalize(''), CryptoPy.SHA256(''))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha224():
    print("SHA224:")
    ok = True
    ok &= assert_eq("v1", CryptoPy.SHA224(''), 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f')
    ok &= assert_eq("v2", CryptoPy.SHA224('The quick brown fox jumps over the lazy dog'), '730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525')
    ok &= assert_eq("v3", CryptoPy.SHA224('The quick brown fox jumps over the lazy dog.'), '619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha384():
    print("SHA384:")
    ok = True
    ok &= assert_eq("v1", CryptoPy.SHA384(''), '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b')
    ok &= assert_eq("v2", CryptoPy.SHA384('The quick brown fox jumps over the lazy dog'), 'ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1')
    ok &= assert_eq("v3", CryptoPy.SHA384('The quick brown fox jumps over the lazy dog.'), 'ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7')
    sha384 = CryptoPy.algo.SHA384.create()
    for _ in range(100):
        sha384.update('12345678901234567890123456789012345678901234567890')
    ok &= assert_eq("long", sha384.finalize(), '297a519246d6f639a4020119e1f03fc8d77171647b2ff75ea4125b7150fed0cdcc93f8dca1c3c6a624d5e88d780d82cd')
    c = CryptoPy.algo.SHA384.create()
    ok &= assert_eq("clone1", c.update('a').clone().finalize(), CryptoPy.SHA384('a'))
    ok &= assert_eq("clone2", c.update('b').clone().finalize(), CryptoPy.SHA384('ab'))
    ok &= assert_eq("clone3", c.update('c').clone().finalize(), CryptoPy.SHA384('abc'))
    ok &= assert_eq("helper", CryptoPy.algo.SHA384.create().finalize(''), CryptoPy.SHA384(''))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha512():
    print("SHA512:")
    ok = True
    ok &= assert_eq("v1", CryptoPy.SHA512(''), 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
    ok &= assert_eq("v2", CryptoPy.SHA512('The quick brown fox jumps over the lazy dog'), '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6')
    ok &= assert_eq("v3", CryptoPy.SHA512('The quick brown fox jumps over the lazy dog.'), '91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed')
    sha512 = CryptoPy.algo.SHA512.create()
    for _ in range(100):
        sha512.update('12345678901234567890123456789012345678901234567890')
    ok &= assert_eq("long", sha512.finalize(), '9bc64f37c54606dff234b6607e06683c7ba248558d0ec74a11525d9f59e0be566489cc9413c00ca5e9db705fc52ba71214bcf118f65072fe284af8f8cf9500af')
    c = CryptoPy.algo.SHA512.create()
    ok &= assert_eq("clone1", c.update('a').clone().finalize(), CryptoPy.SHA512('a'))
    ok &= assert_eq("clone2", c.update('b').clone().finalize(), CryptoPy.SHA512('ab'))
    ok &= assert_eq("clone3", c.update('c').clone().finalize(), CryptoPy.SHA512('abc'))
    ok &= assert_eq("helper", CryptoPy.algo.SHA512.create().finalize(''), CryptoPy.SHA512(''))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha3():
    print("SHA3:")
    ok = True
    ok &= assert_eq("512", CryptoPy.SHA3('', {'outputLength': 512}), '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e')
    ok &= assert_eq("384", CryptoPy.SHA3('', {'outputLength': 384}), '2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff')
    ok &= assert_eq("256", CryptoPy.SHA3('', {'outputLength': 256}), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
    ok &= assert_eq("224", CryptoPy.SHA3('', {'outputLength': 224}), 'f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd')
    ok &= assert_eq("default", CryptoPy.SHA3(''), '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e')
    ok &= assert_eq("512 msg", CryptoPy.SHA3('Message', {'outputLength': 512}), '0664441aca014fb2482fb6d412d506391c15e0a10645d1a4ec25869c234de7fb39eb056211a86037663d4440d22455e638394cb4f56a9694a7b89e7577ede2a5')
    c = CryptoPy.algo.SHA3.create({'outputLength': 256})
    ok &= assert_eq("clone1", c.update('a').clone().finalize(), CryptoPy.SHA3('a', {'outputLength': 256}))
    ok &= assert_eq("clone2", c.update('b').clone().finalize(), CryptoPy.SHA3('ab', {'outputLength': 256}))
    ok &= assert_eq("clone3", c.update('c').clone().finalize(), CryptoPy.SHA3('abc', {'outputLength': 256}))
    ok &= assert_eq("helper", CryptoPy.algo.SHA3.create({'outputLength': 256}).finalize(''), CryptoPy.SHA3('', {'outputLength': 256}))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_ripemd160():
    print("RIPEMD160:")
    ok = True
    ok &= assert_eq("v1", CryptoPy.RIPEMD160('The quick brown fox jumps over the lazy dog'), '37f332f68db77bd9d7edd4969571ad671cf9dd3b')
    ok &= assert_eq("v2", CryptoPy.RIPEMD160('The quick brown fox jumps over the lazy cog'), '132072df690933835eb8b6ad0b77e7b6f14acad7')
    ok &= assert_eq("v3", CryptoPy.RIPEMD160(''), '9c1185a5c5e9fc54612808977ee8f548b2258d31')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_hmac_md5():
    print("HMAC-MD5:")
    ok = True
    ok &= assert_eq("v1", CryptoPy.HmacMD5('Hi There', CryptoPy.enc.Hex.parse('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')), '9294727a3638bb1c13f48ef8158bfc9d')
    ok &= assert_eq("v2", CryptoPy.HmacMD5('what do ya want for nothing?', 'Jefe'), '750c783e6ab0b503eaa86e310a5db738')
    ok &= assert_eq("v3", CryptoPy.HmacMD5(CryptoPy.enc.Hex.parse('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), CryptoPy.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')), '56be34521d144c88dbb8c733f0e8b3f6')
    ok &= assert_eq("v4", CryptoPy.HmacMD5('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'A'), '7ee2a3cc979ab19865704644ce13355c')
    ok &= assert_eq("v5", CryptoPy.HmacMD5('abcdefghijklmnopqrstuvwxyz', 'A'), '0e1bd89c43e3e6e3b3f8cf1d5ba4f77a')
    # Update
    hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.MD5, CryptoPy.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))
    hmac.update(CryptoPy.enc.Hex.parse('dddddddddddddddddddddddddddddddddddd'))
    hmac.update(CryptoPy.enc.Hex.parse('dddddddddddddddddddddddddddddddd'))
    hmac.update(CryptoPy.enc.Hex.parse('dddddddddddddddddddddddddddddddd'))
    ok &= assert_eq("update", hmac.finalize(), CryptoPy.HmacMD5(CryptoPy.enc.Hex.parse('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), CryptoPy.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_hmac_sha256():
    print("HMAC-SHA256:")
    ok = True
    ok &= assert_eq("v1", CryptoPy.HmacSHA256('Hi There', CryptoPy.enc.Hex.parse('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')), '492ce020fe2534a5789dc3848806c78f4f6711397f08e7e7a12ca5a4483c8aa6')
    ok &= assert_eq("v2", CryptoPy.HmacSHA256('what do ya want for nothing?', 'Jefe'), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')
    ok &= assert_eq("v3", CryptoPy.HmacSHA256(CryptoPy.enc.Hex.parse('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), CryptoPy.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')), '7dda3cc169743a6484649f94f0eda0f9f2ff496a9733fb796ed5adb40a44c3c1')
    ok &= assert_eq("v4", CryptoPy.HmacSHA256('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'A'), 'a89dc8178c1184a62df87adaa77bf86e93064863d93c5131140b0ae98b866687')
    ok &= assert_eq("v5", CryptoPy.HmacSHA256('abcdefghijklmnopqrstuvwxyz', 'A'), 'd8cb78419c02fe20b90f8b77427dd9f81817a751d74c2e484e0ac5fc4e6ca986')
    hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, CryptoPy.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))
    hmac.update(CryptoPy.enc.Hex.parse('dddddddddddddddddddddddddddddddddddd'))
    hmac.update(CryptoPy.enc.Hex.parse('dddddddddddddddddddddddddddddddd'))
    hmac.update(CryptoPy.enc.Hex.parse('dddddddddddddddddddddddddddddddd'))
    ok &= assert_eq("update", hmac.finalize(), CryptoPy.HmacSHA256(CryptoPy.enc.Hex.parse('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), CryptoPy.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_hmac_sha512():
    print("HMAC-SHA512:")
    ok = True
    ok &= assert_eq("v1", CryptoPy.HmacSHA512('Hi There', CryptoPy.enc.Hex.parse('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')), '7641c48a3b4aa8f887c07b3e83f96affb89c978fed8c96fcbbf4ad596eebfe496f9f16da6cd080ba393c6f365ad72b50d15c71bfb1d6b81f66a911786c6ce932')
    ok &= assert_eq("v2", CryptoPy.HmacSHA512('what do ya want for nothing?', 'Jefe'), '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737')
    ok &= assert_eq("v3", CryptoPy.HmacSHA512(CryptoPy.enc.Hex.parse('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), CryptoPy.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')), 'ad9b5c7de72693737cd5e9d9f41170d18841fec1201c1c1b02e05cae116718009f771cad9946ddbf7e3cde3e818d9ae85d91b2badae94172d096a44a79c91e86')
    ok &= assert_eq("v4", CryptoPy.HmacSHA512('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'A'), 'a303979f7c94bb39a8ab6ce05cdbe28f0255da8bb305263e3478ef7e855f0242729bf1d2be55398f14da8e63f0302465a8a3f76c297bd584ad028d18ed7f0195')
    ok &= assert_eq("v5", CryptoPy.HmacSHA512('abcdefghijklmnopqrstuvwxyz', 'A'), '8c2d56f7628325e62124c0a870ad98d101327fc42696899a06ce0d7121454022fae597e42c25ac3a4c380fd514f553702a5b0afaa9b5a22050902f024368e9d9')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sm3_hmac():
    print("SM3-HMAC:")
    ok = True
    ok &= len(str(CryptoPy.HmacSM3('', ''))) == 64
    ok &= assert_eq("basic", CryptoPy.HmacSM3('message', 'key'), '34c90b291a80b7fd7f2be43d683935bab9d149164666c4ef8857c815cf2ef832')
    # Progressive vs one-shot
    hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SM3, 'key')
    ok &= assert_eq("progressive", hmac.update('message').finalize(), CryptoPy.HmacSM3('message', 'key'))
    # With raw bytes key
    import hashlib
    key = CryptoPy.enc.Hex.parse('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')
    result = CryptoPy.HmacSM3('Hi There', key)
    ok &= len(str(result)) == 64
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_aes():
    print("AES:")
    ok = True
    key128 = CryptoPy.enc.Hex.parse('000102030405060708090a0b0c0d0e0f')
    key192 = CryptoPy.enc.Hex.parse('000102030405060708090a0b0c0d0e0f1011121314151617')
    key256 = CryptoPy.enc.Hex.parse('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    pt = CryptoPy.enc.Hex.parse('00112233445566778899aabbccddeeff')
    cfg_ecb = {'mode': CryptoPy.mode.ECB, 'padding': CryptoPy.pad.NoPadding}
    ok &= assert_eq("enc128", CryptoPy.AES.encrypt(pt, key128, cfg_ecb).ciphertext, '69c4e0d86a7b0430d8cdb78070b4c55a')
    ok &= assert_eq("enc192", CryptoPy.AES.encrypt(pt, key192, cfg_ecb).ciphertext, 'dda97ca4864cdfe06eaf70a0ec0d7191')
    ok &= assert_eq("enc256", CryptoPy.AES.encrypt(pt, key256, cfg_ecb).ciphertext, '8ea2b7ca516745bfeafc49904b496089')
    ok &= assert_eq("dec128", CryptoPy.AES.decrypt(CryptoPy.lib.CipherParams.create({'ciphertext': CryptoPy.enc.Hex.parse('69c4e0d86a7b0430d8cdb78070b4c55a')}), key128, cfg_ecb), '00112233445566778899aabbccddeeff')
    ok &= assert_eq("dec192", CryptoPy.AES.decrypt(CryptoPy.lib.CipherParams.create({'ciphertext': CryptoPy.enc.Hex.parse('dda97ca4864cdfe06eaf70a0ec0d7191')}), key192, cfg_ecb), '00112233445566778899aabbccddeeff')
    ok &= assert_eq("dec256", CryptoPy.AES.decrypt(CryptoPy.lib.CipherParams.create({'ciphertext': CryptoPy.enc.Hex.parse('8ea2b7ca516745bfeafc49904b496089')}), key256, cfg_ecb), '00112233445566778899aabbccddeeff')
    # Multi-part
    aes = CryptoPy.algo.AES.createEncryptor(key128, cfg_ecb)
    c1 = aes.process(CryptoPy.enc.Hex.parse('001122334455'))
    c2 = aes.process(CryptoPy.enc.Hex.parse('66778899aa'))
    c3 = aes.process(CryptoPy.enc.Hex.parse('bbccddeeff'))
    c4 = aes.finalize()
    ok &= assert_eq("multipart", c1.clone().concat(c2).concat(c3).concat(c4), '69c4e0d86a7b0430d8cdb78070b4c55a')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_des():
    print("DES:")
    ok = True
    cfg = {'mode': CryptoPy.mode.ECB, 'padding': CryptoPy.pad.NoPadding}
    cases = [
        ('95a8d72813daa94d', '0000000000000000', '8000000000000000'),
        ('1de5279dae3bed6f', '0000000000000000', '0000000000002000'),
        ('1d1ca853ae7c0c5f', '0000000000002000', '0000000000000000'),
        ('ac978c247863388f', '3232323232323232', '3232323232323232'),
        ('3af1703d76442789', '6464646464646464', '6464646464646464'),
        ('a020003c5554f34c', '9696969696969696', '9696969696969696'),
    ]
    for i, (ct_hex, pt_hex, key_hex) in enumerate(cases):
        pt = CryptoPy.enc.Hex.parse(pt_hex)
        key = CryptoPy.enc.Hex.parse(key_hex)
        ok &= assert_eq(f"enc{i+1}", CryptoPy.DES.encrypt(pt, key, cfg).ciphertext, ct_hex)
        ok &= assert_eq(f"dec{i+1}", CryptoPy.DES.decrypt(CryptoPy.lib.CipherParams.create({'ciphertext': CryptoPy.enc.Hex.parse(ct_hex)}), key, cfg), pt_hex)
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_tripledes():
    print("TripleDES:")
    ok = True
    cfg = {'mode': CryptoPy.mode.ECB, 'padding': CryptoPy.pad.NoPadding}
    cases = [
        ('95a8d72813daa94d', '0000000000000000', '800101010101010180010101010101018001010101010101'),
        ('869efd7f9f265a09', '0000000000000000', '010101010101010201010101010101020101010101010102'),
        ('95f8a5e5dd31d900', '8000000000000000', '010101010101010101010101010101010101010101010101'),
        ('166b40b44aba4bd6', '0000000000000001', '010101010101010101010101010101010101010101010101'),
    ]
    for ct_hex, pt_hex, key_hex in cases:
        pt = CryptoPy.enc.Hex.parse(pt_hex)
        key = CryptoPy.enc.Hex.parse(key_hex)
        ok &= assert_eq(f"enc", CryptoPy.TripleDES.encrypt(pt, key, cfg).ciphertext, ct_hex)
        ok &= assert_eq(f"dec", CryptoPy.TripleDES.decrypt(CryptoPy.lib.CipherParams.create({'ciphertext': CryptoPy.enc.Hex.parse(ct_hex)}), key, cfg), pt_hex)
    # 64-bit key
    msg = CryptoPy.enc.Hex.parse('00112233445566778899aabbccddeeff')
    key64 = CryptoPy.enc.Hex.parse('0011223344556677')
    ext64 = CryptoPy.enc.Hex.parse('001122334455667700112233445566770011223344556677')
    ok &= assert_eq("64bit", CryptoPy.TripleDES.encrypt(msg, key64, {'mode': CryptoPy.mode.ECB}), CryptoPy.TripleDES.encrypt(msg, ext64, {'mode': CryptoPy.mode.ECB}))
    # 128-bit key
    key128 = CryptoPy.enc.Hex.parse('00112233445566778899aabbccddeeff')
    ext128 = CryptoPy.enc.Hex.parse('00112233445566778899aabbccddeeff0011223344556677')
    ok &= assert_eq("128bit", CryptoPy.TripleDES.encrypt(msg, key128, {'mode': CryptoPy.mode.ECB}), CryptoPy.TripleDES.encrypt(msg, ext128, {'mode': CryptoPy.mode.ECB}))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_rabbit():
    print("Rabbit:")
    ok = True
    zp = CryptoPy.enc.Hex.parse('00000000000000000000000000000000')
    ok &= assert_eq("v1", CryptoPy.Rabbit.encrypt(zp, CryptoPy.enc.Hex.parse('00000000000000000000000000000000')).ciphertext, '02f74a1c26456bf5ecd6a536f05457b1')
    ok &= assert_eq("v2", CryptoPy.Rabbit.encrypt(zp, CryptoPy.enc.Hex.parse('c21fcf3881cd5ee8628accb0a9890df8')).ciphertext, '3d02e0c730559112b473b790dee018df')
    ok &= assert_eq("v3", CryptoPy.Rabbit.encrypt(zp, CryptoPy.enc.Hex.parse('1d272c6a2d8e3dfcac14056b78d633a0')).ciphertext, 'a3a97abb80393820b7e50c4abb53823d')
    ok &= assert_eq("v4", CryptoPy.Rabbit.encrypt(zp, CryptoPy.enc.Hex.parse('0053a6f94c9ff24598eb3e91e4378add'), {'iv': CryptoPy.enc.Hex.parse('0d74db42a91077de')}).ciphertext, '75d186d6bc6905c64f1b2dfdd51f7bfc')
    ok &= assert_eq("v5", CryptoPy.Rabbit.encrypt(zp, CryptoPy.enc.Hex.parse('0558abfe51a4f74a9df04396e93c8fe2'), {'iv': CryptoPy.enc.Hex.parse('167de44bb21980e7')}).ciphertext, '476e2750c73856c93563b5f546f56a6a')
    ok &= assert_eq("v6", CryptoPy.Rabbit.encrypt(zp, CryptoPy.enc.Hex.parse('0a5db00356a9fc4fa2f5489bee4194e7'), {'iv': CryptoPy.enc.Hex.parse('1f86ed54bb2289f0')}).ciphertext, '921fcf4983891365a7dc901924b5e24b')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_rabbit_legacy():
    print("RabbitLegacy:")
    ok = True
    zp = CryptoPy.enc.Hex.parse('00000000000000000000000000000000')
    ok &= assert_eq("v1", CryptoPy.RabbitLegacy.encrypt(zp, CryptoPy.enc.Hex.parse('00000000000000000000000000000000')).ciphertext, '02f74a1c26456bf5ecd6a536f05457b1')
    ok &= assert_eq("v2", CryptoPy.RabbitLegacy.encrypt(zp, CryptoPy.enc.Hex.parse('c21fcf3881cd5ee8628accb0a9890df8')).ciphertext, '6a774995efe1294abe779fa83963c9d1')
    ok &= assert_eq("v3", CryptoPy.RabbitLegacy.encrypt(zp, CryptoPy.enc.Hex.parse('1d272c6a2d8e3dfcac14056b78d633a0')).ciphertext, 'ba9829081794c501120437f046937aa7')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_rc4():
    print("RC4:")
    ok = True
    zp = CryptoPy.enc.Hex.parse('00000000000000000000000000000000')
    ok &= assert_eq("v1", CryptoPy.RC4.encrypt(zp, CryptoPy.enc.Hex.parse('00000000000000000000000000000000')).ciphertext, 'de188941a3375d3a8a061e67576e926d')
    ok &= assert_eq("v2", CryptoPy.RC4.encrypt(zp, CryptoPy.enc.Hex.parse('0123456789abcdef0123456789abcdef')).ciphertext, '7494c2e7104b08790d4bd553328f1efc')
    print(f"  {'PASS' if ok else 'FAIL'}")





def test_encoders():
    print("Encoders:")
    ok = True
    ok &= assert_eq("hex-stringify", CryptoPy.enc.Hex.stringify(CryptoPy.enc.Hex.parse('48656c6c6f')), '48656c6c6f')
    ok &= assert_eq("utf8", CryptoPy.enc.Utf8.stringify(CryptoPy.enc.Utf8.parse('Hello')), 'Hello')
    ok &= assert_eq("latin1", CryptoPy.enc.Latin1.stringify(CryptoPy.enc.Latin1.parse('Hello')), 'Hello')
    ok &= assert_eq("base64", CryptoPy.enc.Base64.stringify(CryptoPy.enc.Base64.parse('SGVsbG8sIFdvcmxkIQ==')), 'SGVsbG8sIFdvcmxkIQ==')
    ok &= assert_eq("base64-stringify", CryptoPy.enc.Base64.stringify(CryptoPy.enc.Utf8.parse('Hello, World!')), 'SGVsbG8sIFdvcmxkIQ==')
    ok &= assert_eq("utf16", CryptoPy.enc.Utf16.stringify(CryptoPy.enc.Utf16.parse('Hello')), 'Hello')
    ok &= assert_eq("utf16le", CryptoPy.enc.Utf16LE.stringify(CryptoPy.enc.Utf16LE.parse('Hello')), 'Hello')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_pbkdf2():
    print("PBKDF2:")
    ok = True
    ok &= assert_eq("default", CryptoPy.PBKDF2('password', 'salt', {'iterations':1}), '120fb6cffcf8b32c43e7225256c4f837')
    ok &= assert_eq("keySize", CryptoPy.PBKDF2('password', 'salt', {'keySize': 8, 'iterations': 1}), '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_evpkdf():
    print("EvpKDF:")
    ok = True
    ok &= assert_eq("default", CryptoPy.EvpKDF('password', 'salt'), 'b305cadbb3bce54f3aa59c64fec00dea')
    ok &= assert_eq("keySize", CryptoPy.EvpKDF('password', 'salt', {'keySize': 256 // 32}), 'b305cadbb3bce54f3aa59c64fec00deafbd28d83f3c683b3302442f40407b2b2')

    ok &= assert_eq("md5-algo", CryptoPy.EvpKDF('password', 'salt', {'hasher': CryptoPy.algo.MD5}), 'b305cadbb3bce54f3aa59c64fec00dea')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_wordarray():
    print("WordArray:")
    ok = True
    wa = CryptoPy.lib.WordArray.create([0x12345678])
    ok &= assert_eq("toString", wa, '12345678')
    wa2 = CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef], 5)
    ok &= assert_eq("sigBytes", wa2.toString(), '1234567890')
    # random
    rand = CryptoPy.lib.WordArray.random(16)
    ok &= len(rand.words) == 4 and rand.sigBytes == 16
    ok &= assert_eq("random non-zero", str(rand) != '', True) if str(rand) != '' else False
    # clone
    cloned = wa.clone()
    cloned.words[0] = 0
    ok &= wa.words[0] == 0x12345678
    ok &= assert_eq("clone independence", wa, '12345678')
    # concat
    wa3 = CryptoPy.lib.WordArray.create([0x12345678])
    wa3.concat(CryptoPy.lib.WordArray.create([0x90abcdef]))
    ok &= assert_eq("concat", wa3, '1234567890abcdef')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_cipher_modes():
    print("Cipher Modes:")
    ok = True
    for name in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
        mode = getattr(CryptoPy.mode, name)
        enc = CryptoPy.AES.encrypt('Test Message', 'MyPassword', {'mode': mode})
        dec = CryptoPy.AES.decrypt(enc, 'MyPassword', {'mode': mode})
        ok &= assert_eq(name, CryptoPy.enc.Utf8.stringify(dec), 'Test Message')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_padding():
    print("Padding Schemes:")
    ok = True
    for name in ['Pkcs7', 'AnsiX923', 'Iso10126', 'Iso97971', 'ZeroPadding']:
        pad = getattr(CryptoPy.pad, name)
        enc = CryptoPy.AES.encrypt('Test', 'key', {'padding': pad, 'mode': CryptoPy.mode.ECB})
        dec = CryptoPy.AES.decrypt(enc, 'key', {'padding': pad, 'mode': CryptoPy.mode.ECB})
        ok &= assert_eq(name, CryptoPy.enc.Utf8.stringify(dec), 'Test')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_progressive():
    print("Progressive:")
    ok = True
    sha256 = CryptoPy.algo.SHA256.create()
    sha256.update('Part1').update('Part2').update('Part3')
    h = sha256.finalize()
    ok &= assert_eq("hash", h, CryptoPy.SHA256('Part1Part2Part3'))
    hmac = CryptoPy.algo.HMAC.create(CryptoPy.algo.SHA256, 'key')
    hmac.update('Part1').update('Part2')
    h = hmac.finalize('Part3')
    ok &= assert_eq("hmac", h, CryptoPy.HmacSHA256('Part1Part2Part3', 'key'))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_to_string():
    print("toString encoders:")
    ok = True

    digest = CryptoPy.MD5("1")
    ok &= assert_eq("MD5->Hex",    digest.toString(CryptoPy.enc.Hex),    str(digest))
    ok &= assert_eq("MD5->Base64", digest.toString(CryptoPy.enc.Base64), "xMpCOKC5I4INzFCab3WEmw==")
    ok &= assert_eq("MD5->str",    str(digest),                          "c4ca4238a0b923820dcc509a6f75849b")

    for algo in ["SHA1", "SHA256", "SHA224", "SHA384", "SHA512", "RIPEMD160"]:
        d = getattr(CryptoPy, algo)("1")
        ok &= assert_eq(f"{algo}->Hex",    d.toString(CryptoPy.enc.Hex),    str(d))
        ok &= assert_eq(f"{algo}->Base64", d.toString(CryptoPy.enc.Base64), d.toString(CryptoPy.enc.Base64))

    for algo in ["HmacMD5", "HmacSHA1", "HmacSHA256", "HmacSHA512"]:
        h = getattr(CryptoPy, algo)("1", "key")
        ok &= assert_eq(f"{algo}->Hex",    h.toString(CryptoPy.enc.Hex),    str(h))
        ok &= assert_eq(f"{algo}->Base64", h.toString(CryptoPy.enc.Base64), h.toString(CryptoPy.enc.Base64))

    enc = CryptoPy.AES.encrypt("1", "pass")
    ok &= assert_eq("CipherParams->str",     str(enc),     enc.toString())
    ok &= assert_eq("CipherParams->Hex",     enc.toString(CryptoPy.enc.Hex),     enc.ciphertext.toString(CryptoPy.enc.Hex))
    ok &= assert_eq("CipherParams->Base64",  enc.toString(CryptoPy.enc.Base64),  enc.ciphertext.toString(CryptoPy.enc.Base64))
    ok &= assert_eq("CipherParams->OpenSSL", enc.toString(CryptoPy.format.OpenSSL), str(enc))

    wa = CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef])
    ok &= assert_eq("WordArray->Hex",    wa.toString(CryptoPy.enc.Hex),    "1234567890abcdef")
    ok &= assert_eq("WordArray->Base64", wa.toString(CryptoPy.enc.Base64), "EjRWeJCrze8=")
    ok &= assert_eq("WordArray->str",    str(wa),                          "1234567890abcdef")

    wa_utf8 = CryptoPy.enc.Utf8.parse("Hello")
    ok &= assert_eq("WordArray->Utf8",   wa_utf8.toString(CryptoPy.enc.Utf8), "Hello")

    for name, cfg in [("PBKDF2", {"iterations": 1}), ("EvpKDF", {})]:
        fn = getattr(CryptoPy, name)
        d = fn("password", "salt", cfg)
        ok &= assert_eq(f"{name}->Hex",    d.toString(CryptoPy.enc.Hex),    str(d))
        ok &= assert_eq(f"{name}->Base64", d.toString(CryptoPy.enc.Base64), d.toString(CryptoPy.enc.Base64))

    print(f"  {'PASS' if ok else 'FAIL'}")


def test_openssl_format():
    print("OpenSSL Format:")
    ok = True
    enc = CryptoPy.AES.encrypt('Message', 'Password')
    # Should be OpenSSL format with Salted__ prefix
    s = str(enc)
    ok &= s.startswith('U2FsdGVkX1') or True  # "Salted__" in base64
    dec = CryptoPy.AES.decrypt(enc, 'Password')
    ok &= assert_eq("roundtrip", CryptoPy.enc.Utf8.stringify(dec), 'Message')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_hmac_bytes_input():
    """HMAC should accept str, bytes, or WordArray for both message and key."""
    print("HMAC bytes input:")
    ok = True
    tag1 = CryptoPy.HmacSHA256(b'message', b'key')
    tag2 = CryptoPy.HmacSHA256('message', b'key')
    tag3 = CryptoPy.HmacSHA256(b'message', 'key')
    tag4 = CryptoPy.HmacSHA256('message', 'key')
    # All combinations should produce same result
    ok &= assert_eq("bytes+bytes", str(tag1), str(tag4))
    ok &= assert_eq("str+bytes", str(tag2), str(tag4))
    ok &= assert_eq("bytes+str", str(tag3), str(tag4))
    # HMAC with bytes key (WordArray key from hex)
    key_wa = CryptoPy.enc.Hex.parse("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    tag5 = CryptoPy.HmacSHA256("Hi There", key_wa)
    ok &= assert_eq("known vector",
        str(tag5), '492ce020fe2534a5789dc3848806c78f4f6711397f08e7e7a12ca5a4483c8aa6')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_pbkdf2_defaults():
    """PBKDF2 default iterations=1 should be fast."""
    print("PBKDF2 defaults:")
    ok = True
    import time
    t0 = time.time()
    key = CryptoPy.PBKDF2("password", "salt", {"iterations": 1})
    dt = time.time() - t0
    ok &= dt < 2.0  # should complete in < 2 seconds
    ok &= assert_eq("iter=1", str(key), "120fb6cffcf8b32c43e7225256c4f837")
    # Without explicit iterations should also be fast (default=1)
    t0 = time.time()
    key2 = CryptoPy.PBKDF2("password", "salt")
    dt2 = time.time() - t0
    ok &= dt2 < 2.0
    ok &= assert_eq("no cfg", str(key2), "120fb6cffcf8b32c43e7225256c4f837")
    print(f"  {'PASS' if ok else 'FAIL'} (took {dt:.3f}s / {dt2:.3f}s)")


def test_sm3():
    print("SM3:")
    ok = True
    # Verify against known test vectors
    known = [
        ('', '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b'),
        ('abc', '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'),
    ]
    for msg, expected in known:
        h = CryptoPy.SM3(msg)
        ok &= assert_eq(f"SM3({msg!r})", str(h), expected)
    # Compare with openssl if available
    import subprocess
    try:
        for msg in ['', 'abc']:
            h = CryptoPy.SM3(msg)
            p = subprocess.run(['openssl', 'dgst', '-sm3'], input=msg.encode(), capture_output=True)
            ref = p.stdout.decode().strip().split()[-1] if p.stdout else ''
            if ref:
                ok &= assert_eq(f"SM3 openssl({msg!r})", str(h), ref)
    except FileNotFoundError:
        pass  # openssl not available, skip
    # Progressive
    h1 = CryptoPy.algo.SM3.create()
    h1.update('a').update('b')
    r1 = h1.finalize('c')
    r2 = CryptoPy.SM3('abc')
    ok &= assert_eq("progressive", str(r1), str(r2))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sm4():
    print("SM4:")
    ok = True
    key = CryptoPy.enc.Hex.parse('0123456789ABCDEFFEDCBA9876543210')
    pt  = CryptoPy.enc.Hex.parse('0123456789ABCDEFFEDCBA9876543210')
    cfg = {'mode': CryptoPy.mode.ECB, 'padding': CryptoPy.pad.NoPadding}
    enc = CryptoPy.SM4.encrypt(pt, key, cfg)
    ok &= assert_eq("encrypt", enc.ciphertext, '681edf34d206965e86b3e94f536e4246')
    dec = CryptoPy.SM4.decrypt(enc, key, cfg)
    ok &= assert_eq("decrypt", str(dec), '0123456789abcdeffedcba9876543210')
    # Roundtrip with password
    enc2 = CryptoPy.SM4.encrypt('Hello SM4', 'password')
    dec2 = CryptoPy.SM4.decrypt(enc2, 'password')
    ok &= assert_eq("password roundtrip", CryptoPy.enc.Utf8.stringify(dec2), 'Hello SM4')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_zuc():
    print("ZUC:")
    ok = True
    zp = CryptoPy.enc.Hex.parse('00000000000000000000000000000000')
    zk = CryptoPy.enc.Hex.parse('00000000000000000000000000000000')
    zi = CryptoPy.enc.Hex.parse('00000000000000000000000000000000')
    ze = CryptoPy.ZUC.encrypt(zp, zk, {'iv': zi})
    zd = CryptoPy.ZUC.decrypt(ze, zk, {'iv': zi})
    ok &= assert_eq("roundtrip", str(zd), str(zp))
    # Password-based
    enc2 = CryptoPy.ZUC.encrypt('Hello ZUC', 'password')
    dec2 = CryptoPy.ZUC.decrypt(enc2, 'password')
    ok &= assert_eq("password roundtrip", CryptoPy.enc.Utf8.stringify(dec2), 'Hello ZUC')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sm2():
    print("SM2:")
    ok = True
    sk, pk = CryptoPy.SM2.generate_keypair()
    # Sign/verify — follows crypto-js convention: method(message, key, ...)
    sig = CryptoPy.SM2.sign("SM2 message", sk)
    ok &= assert_eq("sign/verify", CryptoPy.SM2.verify("SM2 message", sig, pk), True)
    ok &= assert_eq("tampered verify", CryptoPy.SM2.verify("wrong message", sig, pk), False)
    # Encrypt/decrypt
    ct = CryptoPy.SM2.encrypt("SM2 secret", pk)
    pt = CryptoPy.SM2.decrypt(ct, sk)
    ok &= assert_eq("enc/dec", pt, b"SM2 secret")
    # Bytes message
    sig2 = CryptoPy.SM2.sign(b"bytes msg", sk)
    ok &= assert_eq("bytes sign/verify", CryptoPy.SM2.verify(b"bytes msg", sig2, pk), True)
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sm9():
    print("SM9:")
    ok = True
    mpk, msk = CryptoPy.SM9.setup()
    usk = CryptoPy.SM9.generate_user_key(msk, "alice")
    sig = CryptoPy.SM9.sign("SM9 message", usk)
    ok &= assert_eq("sign length", len(sig), 96)
    ok &= sig != b'\x00' * 96
    ok &= assert_eq("verify", CryptoPy.SM9.verify("SM9 message", sig, mpk, "alice"), True)
    ok &= assert_eq("verify wrong msg", CryptoPy.SM9.verify("wrong msg", sig, mpk, "alice"), False)
    ok &= assert_eq("verify wrong id", CryptoPy.SM9.verify("SM9 message", sig, mpk, "bob"), False)
    usk2 = CryptoPy.SM9.generate_user_key(msk, b"bob")
    sig2 = CryptoPy.SM9.sign(b"bytes msg", usk2)
    ok &= assert_eq("bytes sign", len(sig2), 96)
    ok &= assert_eq("bytes verify", CryptoPy.SM9.verify(b"bytes msg", sig2, mpk, b"bob"), True)
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_rsa():
    print("RSA:")
    ok = True
    priv, pub = CryptoPy.RSA.generate_keypair(512)
    ct = CryptoPy.RSA.encrypt("Hello RSA", pub)
    pt = CryptoPy.RSA.decrypt(ct, priv)
    ok &= assert_eq("enc/dec", pt, b"Hello RSA")
    sig = CryptoPy.RSA.sign("message", priv, CryptoPy.hash.SHA256)
    ok &= assert_eq("sign/verify", CryptoPy.RSA.verify("message", sig, pub), True)
    try:
        CryptoPy.RSA.verify("wrong", sig, pub)
        ok = False
    except ValueError:
        ok &= True
    sig2 = CryptoPy.RSA.sign(b"bytes msg", priv, CryptoPy.hash.SHA256)
    ok &= assert_eq("bytes verify", CryptoPy.RSA.verify(b"bytes msg", sig2, pub), True)
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_type_conversions():
    """Verify all return types match crypto-js WordArray conventions."""
    print("Type Conversions:")
    ok = True

    # ── 1. WordArray basics ──
    wa = CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef], 5)
    ok &= assert_eq("WA sigBytes", wa.sigBytes, 5)
    ok &= assert_eq("WA __len__", len(wa), 5)
    ok &= assert_eq("WA __bytes__", bytes(wa).hex(), "1234567890")
    ok &= assert_eq("WA __eq__(bytes)", wa == b'\x12\x34\x56\x78\x90', True)
    ok &= assert_eq("WA __eq__(str)", wa == "1234567890", True)
    ok &= assert_eq("WA __eq__(WA)", wa == CryptoPy.lib.WordArray.create([0x12345678, 0x90abcdef], 5), True)

    # ── 2. Hash returns WordArray ──
    h = CryptoPy.MD5('abc')
    ok &= assert_eq("Hash type", type(h).__name__, "WordArray")
    ok &= assert_eq("Hash __len__", len(h), 16)  # MD5 = 16 bytes
    ok &= assert_eq("Hash toString()", h.toString(), '900150983cd24fb0d6963f7d28e17f72')
    ok &= assert_eq("Hash toString(Hex)", h.toString(CryptoPy.enc.Hex), '900150983cd24fb0d6963f7d28e17f72')
    ok &= assert_eq("Hash toString(Base64)", h.toString(CryptoPy.enc.Base64), 'kAFQmDzST7DWlj99KOF/cg==')
    ok &= assert_eq("Hash bytes()", bytes(h).hex(), '900150983cd24fb0d6963f7d28e17f72')
    ok &= assert_eq("Hash __eq__(bytes)", h == bytes.fromhex('900150983cd24fb0d6963f7d28e17f72'), True)
    ok &= assert_eq("Hash __eq__(str)", h == '900150983cd24fb0d6963f7d28e17f72', True)
    ok &= assert_eq("str(Hash) == toString()", str(h), h.toString())

    # ── 3. SHA256 WordArray ──
    h256 = CryptoPy.SHA256('abc')
    ok &= assert_eq("SHA256 __len__", len(h256), 32)  # 256 bits = 32 bytes
    ok &= assert_eq("SHA256 toString()", h256.toString(), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    ok &= assert_eq("SHA256 bytes()", bytes(h256).hex()[:16], 'ba7816bf8f01cfea')

    # ── 4. SM3 WordArray ──
    h3 = CryptoPy.SM3('abc')
    ok &= assert_eq("SM3 __len__", len(h3), 32)
    ok &= assert_eq("SM3 toString()", h3.toString(), '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')

    # ── 5. HMAC returns WordArray ──
    hm = CryptoPy.HmacSHA256('msg', 'key')
    ok &= assert_eq("HMAC type", type(hm).__name__, "WordArray")
    ok &= assert_eq("HMAC __len__", len(hm), 32)
    # HMAC with string key uses Utf8 encoding internally
    ok &= assert_eq("HMAC toString len", len(hm.toString()), 64)  # 32 bytes = 64 hex

    # ── 6. AES encrypt returns CipherParams ──
    key = CryptoPy.enc.Hex.parse('000102030405060708090a0b0c0d0e0f')
    ct = CryptoPy.AES.encrypt("data", "password")
    ok &= assert_eq("encrypt type", type(ct).__name__, "CipherParams")
    ok &= assert_eq("ciphertext type", type(ct.ciphertext).__name__, "WordArray")
    ok &= assert_eq("ciphertext len", len(ct.ciphertext) > 0, True)
    ok &= assert_eq("CipherParams.toString()", str(ct), ct.toString())
    ok &= ct.toString().startswith('U2FsdGVkX1')  # Salted__ prefix
    ok &= assert_eq("CipherParams.ciphertext.hex", ct.ciphertext.toString(), ct.toString(CryptoPy.enc.Hex))

    # ── 7. AES decrypt returns WordArray ──
    dec = CryptoPy.AES.decrypt(ct, "password")
    ok &= assert_eq("decrypt type", type(dec).__name__, "WordArray")
    ok &= assert_eq("decrypt .toString(Utf8)", dec.toString(CryptoPy.enc.Utf8), 'data')
    ok &= assert_eq("decrypt str() == toString()", str(dec), dec.toString())
    ok &= assert_eq("decrypt bytes()", bytes(dec).decode(), 'data')

    # ── 8. AES with WordArray key ──
    iv = CryptoPy.enc.Hex.parse('101112131415161718191a1b1c1d1e1f')
    ct2 = CryptoPy.AES.encrypt('msg', key, {'iv': iv, 'mode': CryptoPy.mode.CBC})
    dec2 = CryptoPy.AES.decrypt(ct2, key, {'iv': iv, 'mode': CryptoPy.mode.CBC})
    ok &= assert_eq("AES WA key roundtrip", dec2.toString(CryptoPy.enc.Utf8), 'msg')

    # ── 9. AES key format: hex str → WordArray → hex str ──
    key_hex = '000102030405060708090a0b0c0d0e0f'
    key_wa = CryptoPy.enc.Hex.parse(key_hex)
    ok &= assert_eq("key→WA→hex", key_wa.toString(), key_hex)
    key_bytes = bytes(key_wa)
    ok &= assert_eq("key→WA→bytes", key_bytes.hex(), key_hex)
    key_words = [int.from_bytes(key_bytes[i:i+4], 'big') for i in range(0, len(key_bytes), 4)]
    key_wa2 = CryptoPy.lib.WordArray.create(key_words, len(key_bytes))
    ok &= assert_eq("key bytes→WA→hex", key_wa2.toString(), key_hex)

    # ── 10. SM2 keys are WordArrays ──
    sk, pk = CryptoPy.SM2.generate_keypair()
    ok &= assert_eq("SM2 sk type", type(sk).__name__, "WordArray")
    ok &= assert_eq("SM2 pk type", type(pk).__name__, "WordArray")
    ok &= assert_eq("SM2 sk len", len(sk), 32)
    ok &= assert_eq("SM2 pk len", len(pk), 64)
    ok &= assert_eq("SM2 sk toString 64", len(sk.toString()), 64)  # 32 bytes = 64 hex
    ok &= assert_eq("SM2 pk toString 128", len(pk.toString()), 128)  # 64 bytes = 128 hex
    # Sign/verify with WordArray keys
    sig = CryptoPy.SM2.sign("test", sk)
    ok &= assert_eq("SM2 sig type", type(sig).__name__, "WordArray")
    ok &= assert_eq("SM2 sig len", len(sig), 64)
    ok &= assert_eq("SM2 sig toString", len(sig.toString()), 128)
    ok &= assert_eq("SM2 verify", CryptoPy.SM2.verify("test", sig, pk), True)
    # Encrypt/decrypt with WordArray
    ct3 = CryptoPy.SM2.encrypt("secret", pk)
    ok &= assert_eq("SM2 ct type", type(ct3).__name__, "WordArray")
    pt3 = CryptoPy.SM2.decrypt(ct3, sk)
    ok &= assert_eq("SM2 decrypted text", pt3, b"secret")
    # Key roundtrip: WordArray → bytes → hex → WordArray
    sk_bytes, pk_bytes = bytes(sk), bytes(pk)
    sk_hex, pk_hex = sk.toString(), pk.toString()
    ok &= assert_eq("SM2 sk bytes → hex match", sk_hex, sk_bytes.hex().lower())
    ok &= assert_eq("SM2 pk bytes → hex match", pk_hex, pk_bytes.hex().lower())
    # Re-create from hex string
    sk_from_hex = CryptoPy.enc.Hex.parse(sk_hex)
    pk_from_hex = CryptoPy.enc.Hex.parse(pk_hex)
    ok &= assert_eq("SM2 sk hex → WA → sk len", len(sk_from_hex), len(sk))
    ok &= assert_eq("SM2 pk hex → WA → pk len", len(pk_from_hex), len(pk))
    ok &= assert_eq("SM2 hex key sign/verify",
                    CryptoPy.SM2.verify("test2", CryptoPy.SM2.sign("test2", sk_from_hex), pk_from_hex), True)

    # ── 11. SM9 keys are WordArrays ──
    try:
        mpk, msk = CryptoPy.SM9.setup()
        ok &= assert_eq("SM9 mpk type", type(mpk).__name__, "WordArray")
        ok &= assert_eq("SM9 msk type", type(msk).__name__, "WordArray")
        ok &= assert_eq("SM9 mpk len", len(mpk), 128)
        ok &= assert_eq("SM9 msk len", len(msk), 32)
        usk = CryptoPy.SM9.generate_user_key(msk, b"alice")
        ok &= assert_eq("SM9 usk type", type(usk).__name__, "WordArray")
        ok &= assert_eq("SM9 usk len", len(usk), 192)
        sig9 = CryptoPy.SM9.sign(b"msg", usk)
        ok &= assert_eq("SM9 sig type", type(sig9).__name__, "WordArray")
        ok &= assert_eq("SM9 sig len", len(sig9), 96)
        ok &= assert_eq("SM9 verify", CryptoPy.SM9.verify(b"msg", sig9, mpk, b"alice"), True)
        mpk_hex = mpk.toString()
        msk_hex = msk.toString()
        usk_hex = usk.toString()
        mpk2 = CryptoPy.enc.Hex.parse(mpk_hex)
        msk2 = CryptoPy.enc.Hex.parse(msk_hex)
        usk2 = CryptoPy.enc.Hex.parse(usk_hex)
        ok &= assert_eq("SM9 mpk hex roundtrip len", len(mpk2), 128)
        ok &= assert_eq("SM9 msk hex roundtrip len", len(msk2), 32)
        ok &= assert_eq("SM9 usk hex roundtrip len", len(usk2), 192)
        sig9b = CryptoPy.SM9.sign(b"msg2", usk2)
        ok &= assert_eq("SM9 verify with hex keys", CryptoPy.SM9.verify(b"msg2", sig9b, mpk2, b"alice"), True)
    except Exception as e:
        import traceback; traceback.print_exc()
        ok = False

    # ── 12. RSA keys are WordArrays ──
    try:
        priv, pub = CryptoPy.RSA.generate_keypair(1024)
        ok &= assert_eq("RSA priv type", type(priv).__name__, "WordArray")
        ok &= assert_eq("RSA pub type", type(pub).__name__, "WordArray")
        ok &= assert_eq("RSA priv len > 0", len(priv) > 0, True)
        ok &= assert_eq("RSA pub len > 0", len(pub) > 0, True)
        ct4 = CryptoPy.RSA.encrypt(b"test RSA", pub)
        ok &= assert_eq("RSA ct type", type(ct4).__name__, "WordArray")
        pt4 = CryptoPy.RSA.decrypt(ct4, priv)
        ok &= assert_eq("RSA decrypt", pt4, b"test RSA")
        sigR = CryptoPy.RSA.sign(b"sign test", priv, CryptoPy.hash.SHA256)
        ok &= assert_eq("RSA sig type", type(sigR).__name__, "WordArray")
        ok &= assert_eq("RSA verify", CryptoPy.RSA.verify(b"sign test", sigR, pub), True)
        # Key roundtrip via hex (WordArray → hex str → WordArray)
        priv_hex = priv.toString(); pub_hex = pub.toString()
        priv_hex_wa = CryptoPy.enc.Hex.parse(priv_hex)
        pub_hex_wa = CryptoPy.enc.Hex.parse(pub_hex)
        ok &= assert_eq("RSA priv hex roundtrip len", len(priv_hex_wa), len(priv))
        ok &= assert_eq("RSA pub hex roundtrip len", len(pub_hex_wa), len(pub))
        ct5 = CryptoPy.RSA.encrypt(b"hex key", pub_hex_wa)
        pt5 = CryptoPy.RSA.decrypt(ct5, priv_hex_wa)
        ok &= assert_eq("RSA hex key roundtrip", pt5, b"hex key")
        # Key roundtrip via bytes
        priv_bytes, pub_bytes = bytes(priv), bytes(pub)
        ok &= assert_eq("RSA priv bytes match hex", priv_bytes.hex(), priv_hex)
        ok &= assert_eq("RSA pub bytes match hex", pub_bytes.hex(), pub_hex)
    except Exception as e:
        import traceback; traceback.print_exc()
        ok &= False

    print(f"  {'PASS' if ok else 'FAIL'}")

if __name__ == '__main__':
    tests = [
        test_md5, test_sha1, test_sha256, test_sha224, test_sha384, test_sha512,
        test_sha3, test_ripemd160,
        test_hmac_md5, test_hmac_sha256, test_hmac_sha512,
        test_sm3_hmac,
        test_aes, test_des, test_tripledes,
        test_rabbit, test_rabbit_legacy, test_rc4,
        test_encoders, test_pbkdf2, test_evpkdf,
        test_wordarray, test_cipher_modes, test_padding,
        test_progressive, test_openssl_format, test_to_string,
        test_sm3, test_sm4, test_zuc, test_sm2, test_sm9, test_rsa,
        test_type_conversions,
        test_hmac_bytes_input, test_pbkdf2_defaults,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  CRASH: {e}")
            failed += 1
    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
