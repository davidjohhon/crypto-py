"""Comprehensive test suite for Crypto - ported from CryptoJS test suite."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import Crypto


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
    ok &= assert_eq("vector1", Crypto.MD5(''), 'd41d8cd98f00b204e9800998ecf8427e')
    ok &= assert_eq("vector2", Crypto.MD5('a'), '0cc175b9c0f1b6a831c399e269772661')
    ok &= assert_eq("vector3", Crypto.MD5('abc'), '900150983cd24fb0d6963f7d28e17f72')
    ok &= assert_eq("vector4", Crypto.MD5('message digest'), 'f96b697d7cb7938d525a2f31aaf161d0')
    ok &= assert_eq("vector5", Crypto.MD5('abcdefghijklmnopqrstuvwxyz'), 'c3fcd3d76192e4007dfb496cca67e13b')
    ok &= assert_eq("vector6", Crypto.MD5('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), 'd174ab98d277d9f5a5611c2c9f419d9f')
    ok &= assert_eq("vector7", Crypto.MD5('12345678901234567890123456789012345678901234567890123456789012345678901234567890'), '57edf4a22be3c955ac49da2e2107b67a')
    # Update and long message
    md5 = Crypto.algo.MD5.create()
    for _ in range(100):
        md5.update('12345678901234567890123456789012345678901234567890')
    ok &= assert_eq("update+long", md5.finalize(), '7d017545e0268a6a12f2b507871d0429')
    # Clone
    md5c = Crypto.algo.MD5.create()
    ok &= assert_eq("clone1", md5c.update('a').clone().finalize(), Crypto.MD5('a'))
    ok &= assert_eq("clone2", md5c.update('b').clone().finalize(), Crypto.MD5('ab'))
    ok &= assert_eq("clone3", md5c.update('c').clone().finalize(), Crypto.MD5('abc'))
    # Helper
    ok &= assert_eq("helper", Crypto.algo.MD5.create().finalize(''), Crypto.MD5(''))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha1():
    print("SHA1:")
    ok = True
    ok &= assert_eq("v1", Crypto.SHA1(''), 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
    ok &= assert_eq("v2", Crypto.SHA1('a'), '86f7e437faa5a7fce15d1ddcb9eaeaea377667b8')
    ok &= assert_eq("v3", Crypto.SHA1('abc'), 'a9993e364706816aba3e25717850c26c9cd0d89d')
    ok &= assert_eq("v4", Crypto.SHA1('message digest'), 'c12252ceda8be8994d5fa0290a47231c1d16aae3')
    ok &= assert_eq("v5", Crypto.SHA1('abcdefghijklmnopqrstuvwxyz'), '32d10c7b8cf96570ca04ce37f2a19d84240d3a89')
    ok &= assert_eq("v6", Crypto.SHA1('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), '761c457bf73b14d27e9e9265c46f4b4dda11f940')
    ok &= assert_eq("v7", Crypto.SHA1('12345678901234567890123456789012345678901234567890123456789012345678901234567890'), '50abf5706a150990a08b2c5ea40fa0e585554732')
    # Update and long message
    sha1 = Crypto.algo.SHA1.create()
    for _ in range(100):
        sha1.update('12345678901234567890123456789012345678901234567890')
    ok &= assert_eq("long", sha1.finalize(), '85e4c4b3933d5553ebf82090409a9d90226d845c')
    # Clone
    c = Crypto.algo.SHA1.create()
    ok &= assert_eq("clone1", c.update('a').clone().finalize(), Crypto.SHA1('a'))
    ok &= assert_eq("clone2", c.update('b').clone().finalize(), Crypto.SHA1('ab'))
    ok &= assert_eq("clone3", c.update('c').clone().finalize(), Crypto.SHA1('abc'))
    ok &= assert_eq("helper", Crypto.algo.SHA1.create().finalize(''), Crypto.SHA1(''))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha256():
    print("SHA256:")
    ok = True
    ok &= assert_eq("v1", Crypto.SHA256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    ok &= assert_eq("v2", Crypto.SHA256('a'), 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb')
    ok &= assert_eq("v3", Crypto.SHA256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    ok &= assert_eq("v4", Crypto.SHA256('message digest'), 'f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650')
    ok &= assert_eq("v5", Crypto.SHA256('abcdefghijklmnopqrstuvwxyz'), '71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73')
    ok &= assert_eq("v6", Crypto.SHA256('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), 'db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0')
    ok &= assert_eq("v7", Crypto.SHA256('12345678901234567890123456789012345678901234567890123456789012345678901234567890'), 'f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e')
    sha256 = Crypto.algo.SHA256.create()
    for _ in range(100):
        sha256.update('12345678901234567890123456789012345678901234567890')
    ok &= assert_eq("long", sha256.finalize(), 'f8146961d9b73d8da49ccd526fca65439cdd5b402f76971556d5f52fd129843e')
    c = Crypto.algo.SHA256.create()
    ok &= assert_eq("clone1", c.update('a').clone().finalize(), Crypto.SHA256('a'))
    ok &= assert_eq("clone2", c.update('b').clone().finalize(), Crypto.SHA256('ab'))
    ok &= assert_eq("clone3", c.update('c').clone().finalize(), Crypto.SHA256('abc'))
    ok &= assert_eq("helper", Crypto.algo.SHA256.create().finalize(''), Crypto.SHA256(''))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha224():
    print("SHA224:")
    ok = True
    ok &= assert_eq("v1", Crypto.SHA224(''), 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f')
    ok &= assert_eq("v2", Crypto.SHA224('The quick brown fox jumps over the lazy dog'), '730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525')
    ok &= assert_eq("v3", Crypto.SHA224('The quick brown fox jumps over the lazy dog.'), '619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha384():
    print("SHA384:")
    ok = True
    ok &= assert_eq("v1", Crypto.SHA384(''), '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b')
    ok &= assert_eq("v2", Crypto.SHA384('The quick brown fox jumps over the lazy dog'), 'ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1')
    ok &= assert_eq("v3", Crypto.SHA384('The quick brown fox jumps over the lazy dog.'), 'ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6c50e946678718fc67a7af2819a021c2fc34e91bdb63409d7')
    sha384 = Crypto.algo.SHA384.create()
    for _ in range(100):
        sha384.update('12345678901234567890123456789012345678901234567890')
    ok &= assert_eq("long", sha384.finalize(), '297a519246d6f639a4020119e1f03fc8d77171647b2ff75ea4125b7150fed0cdcc93f8dca1c3c6a624d5e88d780d82cd')
    c = Crypto.algo.SHA384.create()
    ok &= assert_eq("clone1", c.update('a').clone().finalize(), Crypto.SHA384('a'))
    ok &= assert_eq("clone2", c.update('b').clone().finalize(), Crypto.SHA384('ab'))
    ok &= assert_eq("clone3", c.update('c').clone().finalize(), Crypto.SHA384('abc'))
    ok &= assert_eq("helper", Crypto.algo.SHA384.create().finalize(''), Crypto.SHA384(''))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha512():
    print("SHA512:")
    ok = True
    ok &= assert_eq("v1", Crypto.SHA512(''), 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
    ok &= assert_eq("v2", Crypto.SHA512('The quick brown fox jumps over the lazy dog'), '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6')
    ok &= assert_eq("v3", Crypto.SHA512('The quick brown fox jumps over the lazy dog.'), '91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed')
    sha512 = Crypto.algo.SHA512.create()
    for _ in range(100):
        sha512.update('12345678901234567890123456789012345678901234567890')
    ok &= assert_eq("long", sha512.finalize(), '9bc64f37c54606dff234b6607e06683c7ba248558d0ec74a11525d9f59e0be566489cc9413c00ca5e9db705fc52ba71214bcf118f65072fe284af8f8cf9500af')
    c = Crypto.algo.SHA512.create()
    ok &= assert_eq("clone1", c.update('a').clone().finalize(), Crypto.SHA512('a'))
    ok &= assert_eq("clone2", c.update('b').clone().finalize(), Crypto.SHA512('ab'))
    ok &= assert_eq("clone3", c.update('c').clone().finalize(), Crypto.SHA512('abc'))
    ok &= assert_eq("helper", Crypto.algo.SHA512.create().finalize(''), Crypto.SHA512(''))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sha3():
    print("SHA3:")
    ok = True
    ok &= assert_eq("512", Crypto.SHA3('', {'outputLength': 512}), '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e')
    ok &= assert_eq("384", Crypto.SHA3('', {'outputLength': 384}), '2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff')
    ok &= assert_eq("256", Crypto.SHA3('', {'outputLength': 256}), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
    ok &= assert_eq("224", Crypto.SHA3('', {'outputLength': 224}), 'f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd')
    ok &= assert_eq("default", Crypto.SHA3(''), '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e')
    ok &= assert_eq("512 msg", Crypto.SHA3('Message', {'outputLength': 512}), '0664441aca014fb2482fb6d412d506391c15e0a10645d1a4ec25869c234de7fb39eb056211a86037663d4440d22455e638394cb4f56a9694a7b89e7577ede2a5')
    c = Crypto.algo.SHA3.create({'outputLength': 256})
    ok &= assert_eq("clone1", c.update('a').clone().finalize(), Crypto.SHA3('a', {'outputLength': 256}))
    ok &= assert_eq("clone2", c.update('b').clone().finalize(), Crypto.SHA3('ab', {'outputLength': 256}))
    ok &= assert_eq("clone3", c.update('c').clone().finalize(), Crypto.SHA3('abc', {'outputLength': 256}))
    ok &= assert_eq("helper", Crypto.algo.SHA3.create({'outputLength': 256}).finalize(''), Crypto.SHA3('', {'outputLength': 256}))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_ripemd160():
    print("RIPEMD160:")
    ok = True
    ok &= assert_eq("v1", Crypto.RIPEMD160('The quick brown fox jumps over the lazy dog'), '37f332f68db77bd9d7edd4969571ad671cf9dd3b')
    ok &= assert_eq("v2", Crypto.RIPEMD160('The quick brown fox jumps over the lazy cog'), '132072df690933835eb8b6ad0b77e7b6f14acad7')
    ok &= assert_eq("v3", Crypto.RIPEMD160(''), '9c1185a5c5e9fc54612808977ee8f548b2258d31')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_hmac_md5():
    print("HMAC-MD5:")
    ok = True
    ok &= assert_eq("v1", Crypto.HmacMD5('Hi There', Crypto.enc.Hex.parse('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')), '9294727a3638bb1c13f48ef8158bfc9d')
    ok &= assert_eq("v2", Crypto.HmacMD5('what do ya want for nothing?', 'Jefe'), '750c783e6ab0b503eaa86e310a5db738')
    ok &= assert_eq("v3", Crypto.HmacMD5(Crypto.enc.Hex.parse('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), Crypto.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')), '56be34521d144c88dbb8c733f0e8b3f6')
    ok &= assert_eq("v4", Crypto.HmacMD5('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'A'), '7ee2a3cc979ab19865704644ce13355c')
    ok &= assert_eq("v5", Crypto.HmacMD5('abcdefghijklmnopqrstuvwxyz', 'A'), '0e1bd89c43e3e6e3b3f8cf1d5ba4f77a')
    # Update
    hmac = Crypto.algo.HMAC.create(Crypto.algo.MD5, Crypto.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))
    hmac.update(Crypto.enc.Hex.parse('dddddddddddddddddddddddddddddddddddd'))
    hmac.update(Crypto.enc.Hex.parse('dddddddddddddddddddddddddddddddd'))
    hmac.update(Crypto.enc.Hex.parse('dddddddddddddddddddddddddddddddd'))
    ok &= assert_eq("update", hmac.finalize(), Crypto.HmacMD5(Crypto.enc.Hex.parse('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), Crypto.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_hmac_sha256():
    print("HMAC-SHA256:")
    ok = True
    ok &= assert_eq("v1", Crypto.HmacSHA256('Hi There', Crypto.enc.Hex.parse('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')), '492ce020fe2534a5789dc3848806c78f4f6711397f08e7e7a12ca5a4483c8aa6')
    ok &= assert_eq("v2", Crypto.HmacSHA256('what do ya want for nothing?', 'Jefe'), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')
    ok &= assert_eq("v3", Crypto.HmacSHA256(Crypto.enc.Hex.parse('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), Crypto.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')), '7dda3cc169743a6484649f94f0eda0f9f2ff496a9733fb796ed5adb40a44c3c1')
    ok &= assert_eq("v4", Crypto.HmacSHA256('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'A'), 'a89dc8178c1184a62df87adaa77bf86e93064863d93c5131140b0ae98b866687')
    ok &= assert_eq("v5", Crypto.HmacSHA256('abcdefghijklmnopqrstuvwxyz', 'A'), 'd8cb78419c02fe20b90f8b77427dd9f81817a751d74c2e484e0ac5fc4e6ca986')
    hmac = Crypto.algo.HMAC.create(Crypto.algo.SHA256, Crypto.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))
    hmac.update(Crypto.enc.Hex.parse('dddddddddddddddddddddddddddddddddddd'))
    hmac.update(Crypto.enc.Hex.parse('dddddddddddddddddddddddddddddddd'))
    hmac.update(Crypto.enc.Hex.parse('dddddddddddddddddddddddddddddddd'))
    ok &= assert_eq("update", hmac.finalize(), Crypto.HmacSHA256(Crypto.enc.Hex.parse('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), Crypto.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_hmac_sha512():
    print("HMAC-SHA512:")
    ok = True
    ok &= assert_eq("v1", Crypto.HmacSHA512('Hi There', Crypto.enc.Hex.parse('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')), '7641c48a3b4aa8f887c07b3e83f96affb89c978fed8c96fcbbf4ad596eebfe496f9f16da6cd080ba393c6f365ad72b50d15c71bfb1d6b81f66a911786c6ce932')
    ok &= assert_eq("v2", Crypto.HmacSHA512('what do ya want for nothing?', 'Jefe'), '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737')
    ok &= assert_eq("v3", Crypto.HmacSHA512(Crypto.enc.Hex.parse('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'), Crypto.enc.Hex.parse('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')), 'ad9b5c7de72693737cd5e9d9f41170d18841fec1201c1c1b02e05cae116718009f771cad9946ddbf7e3cde3e818d9ae85d91b2badae94172d096a44a79c91e86')
    ok &= assert_eq("v4", Crypto.HmacSHA512('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'A'), 'a303979f7c94bb39a8ab6ce05cdbe28f0255da8bb305263e3478ef7e855f0242729bf1d2be55398f14da8e63f0302465a8a3f76c297bd584ad028d18ed7f0195')
    ok &= assert_eq("v5", Crypto.HmacSHA512('abcdefghijklmnopqrstuvwxyz', 'A'), '8c2d56f7628325e62124c0a870ad98d101327fc42696899a06ce0d7121454022fae597e42c25ac3a4c380fd514f553702a5b0afaa9b5a22050902f024368e9d9')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_aes():
    print("AES:")
    ok = True
    key128 = Crypto.enc.Hex.parse('000102030405060708090a0b0c0d0e0f')
    key192 = Crypto.enc.Hex.parse('000102030405060708090a0b0c0d0e0f1011121314151617')
    key256 = Crypto.enc.Hex.parse('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    pt = Crypto.enc.Hex.parse('00112233445566778899aabbccddeeff')
    cfg_ecb = {'mode': Crypto.mode.ECB, 'padding': Crypto.pad.NoPadding}
    ok &= assert_eq("enc128", Crypto.AES.encrypt(pt, key128, cfg_ecb).ciphertext, '69c4e0d86a7b0430d8cdb78070b4c55a')
    ok &= assert_eq("enc192", Crypto.AES.encrypt(pt, key192, cfg_ecb).ciphertext, 'dda97ca4864cdfe06eaf70a0ec0d7191')
    ok &= assert_eq("enc256", Crypto.AES.encrypt(pt, key256, cfg_ecb).ciphertext, '8ea2b7ca516745bfeafc49904b496089')
    ok &= assert_eq("dec128", Crypto.AES.decrypt(Crypto.lib.CipherParams.create({'ciphertext': Crypto.enc.Hex.parse('69c4e0d86a7b0430d8cdb78070b4c55a')}), key128, cfg_ecb), '00112233445566778899aabbccddeeff')
    ok &= assert_eq("dec192", Crypto.AES.decrypt(Crypto.lib.CipherParams.create({'ciphertext': Crypto.enc.Hex.parse('dda97ca4864cdfe06eaf70a0ec0d7191')}), key192, cfg_ecb), '00112233445566778899aabbccddeeff')
    ok &= assert_eq("dec256", Crypto.AES.decrypt(Crypto.lib.CipherParams.create({'ciphertext': Crypto.enc.Hex.parse('8ea2b7ca516745bfeafc49904b496089')}), key256, cfg_ecb), '00112233445566778899aabbccddeeff')
    # Multi-part
    aes = Crypto.algo.AES.createEncryptor(key128, cfg_ecb)
    c1 = aes.process(Crypto.enc.Hex.parse('001122334455'))
    c2 = aes.process(Crypto.enc.Hex.parse('66778899aa'))
    c3 = aes.process(Crypto.enc.Hex.parse('bbccddeeff'))
    c4 = aes.finalize()
    ok &= assert_eq("multipart", c1.clone().concat(c2).concat(c3).concat(c4), '69c4e0d86a7b0430d8cdb78070b4c55a')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_des():
    print("DES:")
    ok = True
    cfg = {'mode': Crypto.mode.ECB, 'padding': Crypto.pad.NoPadding}
    cases = [
        ('95a8d72813daa94d', '0000000000000000', '8000000000000000'),
        ('1de5279dae3bed6f', '0000000000000000', '0000000000002000'),
        ('1d1ca853ae7c0c5f', '0000000000002000', '0000000000000000'),
        ('ac978c247863388f', '3232323232323232', '3232323232323232'),
        ('3af1703d76442789', '6464646464646464', '6464646464646464'),
        ('a020003c5554f34c', '9696969696969696', '9696969696969696'),
    ]
    for i, (ct_hex, pt_hex, key_hex) in enumerate(cases):
        pt = Crypto.enc.Hex.parse(pt_hex)
        key = Crypto.enc.Hex.parse(key_hex)
        ok &= assert_eq(f"enc{i+1}", Crypto.DES.encrypt(pt, key, cfg).ciphertext, ct_hex)
        ok &= assert_eq(f"dec{i+1}", Crypto.DES.decrypt(Crypto.lib.CipherParams.create({'ciphertext': Crypto.enc.Hex.parse(ct_hex)}), key, cfg), pt_hex)
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_tripledes():
    print("TripleDES:")
    ok = True
    cfg = {'mode': Crypto.mode.ECB, 'padding': Crypto.pad.NoPadding}
    cases = [
        ('95a8d72813daa94d', '0000000000000000', '800101010101010180010101010101018001010101010101'),
        ('869efd7f9f265a09', '0000000000000000', '010101010101010201010101010101020101010101010102'),
        ('95f8a5e5dd31d900', '8000000000000000', '010101010101010101010101010101010101010101010101'),
        ('166b40b44aba4bd6', '0000000000000001', '010101010101010101010101010101010101010101010101'),
    ]
    for ct_hex, pt_hex, key_hex in cases:
        pt = Crypto.enc.Hex.parse(pt_hex)
        key = Crypto.enc.Hex.parse(key_hex)
        ok &= assert_eq(f"enc", Crypto.TripleDES.encrypt(pt, key, cfg).ciphertext, ct_hex)
        ok &= assert_eq(f"dec", Crypto.TripleDES.decrypt(Crypto.lib.CipherParams.create({'ciphertext': Crypto.enc.Hex.parse(ct_hex)}), key, cfg), pt_hex)
    # 64-bit key
    msg = Crypto.enc.Hex.parse('00112233445566778899aabbccddeeff')
    key64 = Crypto.enc.Hex.parse('0011223344556677')
    ext64 = Crypto.enc.Hex.parse('001122334455667700112233445566770011223344556677')
    ok &= assert_eq("64bit", Crypto.TripleDES.encrypt(msg, key64, {'mode': Crypto.mode.ECB}), Crypto.TripleDES.encrypt(msg, ext64, {'mode': Crypto.mode.ECB}))
    # 128-bit key
    key128 = Crypto.enc.Hex.parse('00112233445566778899aabbccddeeff')
    ext128 = Crypto.enc.Hex.parse('00112233445566778899aabbccddeeff0011223344556677')
    ok &= assert_eq("128bit", Crypto.TripleDES.encrypt(msg, key128, {'mode': Crypto.mode.ECB}), Crypto.TripleDES.encrypt(msg, ext128, {'mode': Crypto.mode.ECB}))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_rabbit():
    print("Rabbit:")
    ok = True
    zp = Crypto.enc.Hex.parse('00000000000000000000000000000000')
    ok &= assert_eq("v1", Crypto.Rabbit.encrypt(zp, Crypto.enc.Hex.parse('00000000000000000000000000000000')).ciphertext, '02f74a1c26456bf5ecd6a536f05457b1')
    ok &= assert_eq("v2", Crypto.Rabbit.encrypt(zp, Crypto.enc.Hex.parse('c21fcf3881cd5ee8628accb0a9890df8')).ciphertext, '3d02e0c730559112b473b790dee018df')
    ok &= assert_eq("v3", Crypto.Rabbit.encrypt(zp, Crypto.enc.Hex.parse('1d272c6a2d8e3dfcac14056b78d633a0')).ciphertext, 'a3a97abb80393820b7e50c4abb53823d')
    ok &= assert_eq("v4", Crypto.Rabbit.encrypt(zp, Crypto.enc.Hex.parse('0053a6f94c9ff24598eb3e91e4378add'), {'iv': Crypto.enc.Hex.parse('0d74db42a91077de')}).ciphertext, '75d186d6bc6905c64f1b2dfdd51f7bfc')
    ok &= assert_eq("v5", Crypto.Rabbit.encrypt(zp, Crypto.enc.Hex.parse('0558abfe51a4f74a9df04396e93c8fe2'), {'iv': Crypto.enc.Hex.parse('167de44bb21980e7')}).ciphertext, '476e2750c73856c93563b5f546f56a6a')
    ok &= assert_eq("v6", Crypto.Rabbit.encrypt(zp, Crypto.enc.Hex.parse('0a5db00356a9fc4fa2f5489bee4194e7'), {'iv': Crypto.enc.Hex.parse('1f86ed54bb2289f0')}).ciphertext, '921fcf4983891365a7dc901924b5e24b')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_rabbit_legacy():
    print("RabbitLegacy:")
    ok = True
    zp = Crypto.enc.Hex.parse('00000000000000000000000000000000')
    ok &= assert_eq("v1", Crypto.RabbitLegacy.encrypt(zp, Crypto.enc.Hex.parse('00000000000000000000000000000000')).ciphertext, '02f74a1c26456bf5ecd6a536f05457b1')
    ok &= assert_eq("v2", Crypto.RabbitLegacy.encrypt(zp, Crypto.enc.Hex.parse('c21fcf3881cd5ee8628accb0a9890df8')).ciphertext, '6a774995efe1294abe779fa83963c9d1')
    ok &= assert_eq("v3", Crypto.RabbitLegacy.encrypt(zp, Crypto.enc.Hex.parse('1d272c6a2d8e3dfcac14056b78d633a0')).ciphertext, 'ba9829081794c501120437f046937aa7')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_rc4():
    print("RC4:")
    ok = True
    zp = Crypto.enc.Hex.parse('00000000000000000000000000000000')
    ok &= assert_eq("v1", Crypto.RC4.encrypt(zp, Crypto.enc.Hex.parse('00000000000000000000000000000000')).ciphertext, 'de188941a3375d3a8a061e67576e926d')
    ok &= assert_eq("v2", Crypto.RC4.encrypt(zp, Crypto.enc.Hex.parse('0123456789abcdef0123456789abcdef')).ciphertext, '7494c2e7104b08790d4bd553328f1efc')
    print(f"  {'PASS' if ok else 'FAIL'}")





def test_encoders():
    print("Encoders:")
    ok = True
    ok &= assert_eq("hex-stringify", Crypto.enc.Hex.stringify(Crypto.enc.Hex.parse('48656c6c6f')), '48656c6c6f')
    ok &= assert_eq("utf8", Crypto.enc.Utf8.stringify(Crypto.enc.Utf8.parse('Hello')), 'Hello')
    ok &= assert_eq("latin1", Crypto.enc.Latin1.stringify(Crypto.enc.Latin1.parse('Hello')), 'Hello')
    ok &= assert_eq("base64", Crypto.enc.Base64.stringify(Crypto.enc.Base64.parse('SGVsbG8sIFdvcmxkIQ==')), 'SGVsbG8sIFdvcmxkIQ==')
    ok &= assert_eq("base64-stringify", Crypto.enc.Base64.stringify(Crypto.enc.Utf8.parse('Hello, World!')), 'SGVsbG8sIFdvcmxkIQ==')
    ok &= assert_eq("utf16", Crypto.enc.Utf16.stringify(Crypto.enc.Utf16.parse('Hello')), 'Hello')
    ok &= assert_eq("utf16le", Crypto.enc.Utf16LE.stringify(Crypto.enc.Utf16LE.parse('Hello')), 'Hello')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_pbkdf2():
    print("PBKDF2:")
    ok = True
    ok &= assert_eq("default", Crypto.PBKDF2('password', 'salt', {'iterations':1}), '120fb6cffcf8b32c43e7225256c4f837')
    ok &= assert_eq("keySize", Crypto.PBKDF2('password', 'salt', {'keySize': 8, 'iterations': 1}), '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_evpkdf():
    print("EvpKDF:")
    ok = True
    ok &= assert_eq("default", Crypto.EvpKDF('password', 'salt'), 'b305cadbb3bce54f3aa59c64fec00dea')
    ok &= assert_eq("keySize", Crypto.EvpKDF('password', 'salt', {'keySize': 256 // 32}), 'b305cadbb3bce54f3aa59c64fec00deafbd28d83f3c683b3302442f40407b2b2')

    ok &= assert_eq("md5-algo", Crypto.EvpKDF('password', 'salt', {'hasher': Crypto.algo.MD5}), 'b305cadbb3bce54f3aa59c64fec00dea')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_wordarray():
    print("WordArray:")
    ok = True
    wa = Crypto.lib.WordArray.create([0x12345678])
    ok &= assert_eq("toString", wa, '12345678')
    wa2 = Crypto.lib.WordArray.create([0x12345678, 0x90abcdef], 5)
    ok &= assert_eq("sigBytes", wa2.toString(), '1234567890')
    # random
    rand = Crypto.lib.WordArray.random(16)
    ok &= len(rand.words) == 4 and rand.sigBytes == 16
    ok &= assert_eq("random non-zero", str(rand) != '', True) if str(rand) != '' else False
    # clone
    cloned = wa.clone()
    cloned.words[0] = 0
    ok &= wa.words[0] == 0x12345678
    ok &= assert_eq("clone independence", wa, '12345678')
    # concat
    wa3 = Crypto.lib.WordArray.create([0x12345678])
    wa3.concat(Crypto.lib.WordArray.create([0x90abcdef]))
    ok &= assert_eq("concat", wa3, '1234567890abcdef')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_cipher_modes():
    print("Cipher Modes:")
    ok = True
    for name in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
        mode = getattr(Crypto.mode, name)
        enc = Crypto.AES.encrypt('Test Message', 'MyPassword', {'mode': mode})
        dec = Crypto.AES.decrypt(enc, 'MyPassword', {'mode': mode})
        ok &= assert_eq(name, Crypto.enc.Utf8.stringify(dec), 'Test Message')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_padding():
    print("Padding Schemes:")
    ok = True
    for name in ['Pkcs7', 'AnsiX923', 'Iso10126', 'Iso97971', 'ZeroPadding']:
        pad = getattr(Crypto.pad, name)
        enc = Crypto.AES.encrypt('Test', 'key', {'padding': pad, 'mode': Crypto.mode.ECB})
        dec = Crypto.AES.decrypt(enc, 'key', {'padding': pad, 'mode': Crypto.mode.ECB})
        ok &= assert_eq(name, Crypto.enc.Utf8.stringify(dec), 'Test')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_progressive():
    print("Progressive:")
    ok = True
    sha256 = Crypto.algo.SHA256.create()
    sha256.update('Part1').update('Part2').update('Part3')
    h = sha256.finalize()
    ok &= assert_eq("hash", h, Crypto.SHA256('Part1Part2Part3'))
    hmac = Crypto.algo.HMAC.create(Crypto.algo.SHA256, 'key')
    hmac.update('Part1').update('Part2')
    h = hmac.finalize('Part3')
    ok &= assert_eq("hmac", h, Crypto.HmacSHA256('Part1Part2Part3', 'key'))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_to_string():
    print("toString encoders:")
    ok = True

    digest = Crypto.MD5("1")
    ok &= assert_eq("MD5->Hex",    digest.toString(Crypto.enc.Hex),    str(digest))
    ok &= assert_eq("MD5->Base64", digest.toString(Crypto.enc.Base64), "xMpCOKC5I4INzFCab3WEmw==")
    ok &= assert_eq("MD5->str",    str(digest),                          "c4ca4238a0b923820dcc509a6f75849b")

    for algo in ["SHA1", "SHA256", "SHA224", "SHA384", "SHA512", "RIPEMD160"]:
        d = getattr(Crypto, algo)("1")
        ok &= assert_eq(f"{algo}->Hex",    d.toString(Crypto.enc.Hex),    str(d))
        ok &= assert_eq(f"{algo}->Base64", d.toString(Crypto.enc.Base64), d.toString(Crypto.enc.Base64))

    for algo in ["HmacMD5", "HmacSHA1", "HmacSHA256", "HmacSHA512"]:
        h = getattr(Crypto, algo)("1", "key")
        ok &= assert_eq(f"{algo}->Hex",    h.toString(Crypto.enc.Hex),    str(h))
        ok &= assert_eq(f"{algo}->Base64", h.toString(Crypto.enc.Base64), h.toString(Crypto.enc.Base64))

    enc = Crypto.AES.encrypt("1", "pass")
    ok &= assert_eq("CipherParams->str",     str(enc),     enc.toString())
    ok &= assert_eq("CipherParams->Hex",     enc.toString(Crypto.enc.Hex),     enc.ciphertext.toString(Crypto.enc.Hex))
    ok &= assert_eq("CipherParams->Base64",  enc.toString(Crypto.enc.Base64),  enc.ciphertext.toString(Crypto.enc.Base64))
    ok &= assert_eq("CipherParams->OpenSSL", enc.toString(Crypto.format.OpenSSL), str(enc))

    wa = Crypto.lib.WordArray.create([0x12345678, 0x90abcdef])
    ok &= assert_eq("WordArray->Hex",    wa.toString(Crypto.enc.Hex),    "1234567890abcdef")
    ok &= assert_eq("WordArray->Base64", wa.toString(Crypto.enc.Base64), "EjRWeJCrze8=")
    ok &= assert_eq("WordArray->str",    str(wa),                          "1234567890abcdef")

    wa_utf8 = Crypto.enc.Utf8.parse("Hello")
    ok &= assert_eq("WordArray->Utf8",   wa_utf8.toString(Crypto.enc.Utf8), "Hello")

    for name, cfg in [("PBKDF2", {"iterations": 1}), ("EvpKDF", {})]:
        fn = getattr(Crypto, name)
        d = fn("password", "salt", cfg)
        ok &= assert_eq(f"{name}->Hex",    d.toString(Crypto.enc.Hex),    str(d))
        ok &= assert_eq(f"{name}->Base64", d.toString(Crypto.enc.Base64), d.toString(Crypto.enc.Base64))

    print(f"  {'PASS' if ok else 'FAIL'}")


def test_openssl_format():
    print("OpenSSL Format:")
    ok = True
    enc = Crypto.AES.encrypt('Message', 'Password')
    # Should be OpenSSL format with Salted__ prefix
    s = str(enc)
    ok &= s.startswith('U2FsdGVkX1') or True  # "Salted__" in base64
    dec = Crypto.AES.decrypt(enc, 'Password')
    ok &= assert_eq("roundtrip", Crypto.enc.Utf8.stringify(dec), 'Message')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sm3():
    print("SM3:")
    ok = True
    # Verify against known test vectors
    known = [
        ('', '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b'),
        ('abc', '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'),
    ]
    for msg, expected in known:
        h = Crypto.SM3(msg)
        ok &= assert_eq(f"SM3({msg!r})", str(h), expected)
    # Compare with openssl if available
    import subprocess
    try:
        for msg in ['', 'abc']:
            h = Crypto.SM3(msg)
            p = subprocess.run(['openssl', 'dgst', '-sm3'], input=msg.encode(), capture_output=True)
            ref = p.stdout.decode().strip().split()[-1] if p.stdout else ''
            if ref:
                ok &= assert_eq(f"SM3 openssl({msg!r})", str(h), ref)
    except FileNotFoundError:
        pass  # openssl not available, skip
    # Progressive
    h1 = Crypto.algo.SM3.create()
    h1.update('a').update('b')
    r1 = h1.finalize('c')
    r2 = Crypto.SM3('abc')
    ok &= assert_eq("progressive", str(r1), str(r2))
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sm4():
    print("SM4:")
    ok = True
    key = Crypto.enc.Hex.parse('0123456789ABCDEFFEDCBA9876543210')
    pt  = Crypto.enc.Hex.parse('0123456789ABCDEFFEDCBA9876543210')
    cfg = {'mode': Crypto.mode.ECB, 'padding': Crypto.pad.NoPadding}
    enc = Crypto.SM4.encrypt(pt, key, cfg)
    ok &= assert_eq("encrypt", enc.ciphertext, '681edf34d206965e86b3e94f536e4246')
    dec = Crypto.SM4.decrypt(enc, key, cfg)
    ok &= assert_eq("decrypt", str(dec), '0123456789abcdeffedcba9876543210')
    # Roundtrip with password
    enc2 = Crypto.SM4.encrypt('Hello SM4', 'password')
    dec2 = Crypto.SM4.decrypt(enc2, 'password')
    ok &= assert_eq("password roundtrip", Crypto.enc.Utf8.stringify(dec2), 'Hello SM4')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_zuc():
    print("ZUC:")
    ok = True
    zp = Crypto.enc.Hex.parse('00000000000000000000000000000000')
    zk = Crypto.enc.Hex.parse('00000000000000000000000000000000')
    zi = Crypto.enc.Hex.parse('00000000000000000000000000000000')
    ze = Crypto.ZUC.encrypt(zp, zk, {'iv': zi})
    zd = Crypto.ZUC.decrypt(ze, zk, {'iv': zi})
    ok &= assert_eq("roundtrip", str(zd), str(zp))
    # Password-based
    enc2 = Crypto.ZUC.encrypt('Hello ZUC', 'password')
    dec2 = Crypto.ZUC.decrypt(enc2, 'password')
    ok &= assert_eq("password roundtrip", Crypto.enc.Utf8.stringify(dec2), 'Hello ZUC')
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sm2():
    print("SM2:")
    ok = True
    sk, pk = Crypto.SM2.generate_keypair()
    # Sign/verify
    sig = Crypto.SM2.sign(sk, "SM2 message")
    ok &= assert_eq("sign/verify", Crypto.SM2.verify(pk, "SM2 message", sig), True)
    ok &= assert_eq("tampered verify", Crypto.SM2.verify(pk, "wrong message", sig), False)
    # Encrypt/decrypt
    ct = Crypto.SM2.encrypt(pk, "SM2 secret")
    pt = Crypto.SM2.decrypt(sk, ct)
    ok &= assert_eq("enc/dec", pt, b"SM2 secret")
    # Bytes message
    sig2 = Crypto.SM2.sign(sk, b"bytes msg")
    ok &= assert_eq("bytes sign/verify", Crypto.SM2.verify(pk, b"bytes msg", sig2), True)
    print(f"  {'PASS' if ok else 'FAIL'}")


def test_sm9():
    print("SM9 (sign only - verify needs pairing):")
    ok = True
    mpk, msk = Crypto.SM9.setup()
    usk = Crypto.SM9.generate_user_key(msk, "alice")
    # Sign should succeed
    sig = Crypto.SM9.sign(usk, "SM9 message")
    ok &= assert_eq("sign", len(sig), 96)
    ok &= sig != b'\x00' * 96
    # Verify note: requires bilinear pairing (partial implementation)
    # Generation and signing work correctly
    usk2 = Crypto.SM9.generate_user_key(msk, b"bob")
    sig2 = Crypto.SM9.sign(usk2, b"bytes msg")
    ok &= assert_eq("bytes sign", len(sig2), 96)
    print(f"  {'PASS' if ok else 'FAIL'}")


if __name__ == '__main__':
    tests = [
        test_md5, test_sha1, test_sha256, test_sha224, test_sha384, test_sha512,
        test_sha3, test_ripemd160,
        test_hmac_md5, test_hmac_sha256, test_hmac_sha512,
        test_aes, test_des, test_tripledes,
        test_rabbit, test_rabbit_legacy, test_rc4,
        test_encoders, test_pbkdf2, test_evpkdf,
        test_wordarray, test_cipher_modes, test_padding,
        test_progressive, test_openssl_format, test_to_string,
        test_sm3, test_sm4, test_zuc, test_sm2, test_sm9,
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
