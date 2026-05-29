"""
Crypto — Python port of CryptoJS.

Usage:
    import CryptoPy
    CryptoPy.MD5("message")
    CryptoPy.SHA256("message")
    CryptoPy.AES.encrypt("data", "password")
    CryptoPy.enc.Hex.parse("48656c6c6f")
    CryptoPy.mode.CBC
"""

from CryptoPy.core import Base, WordArray, BufferedBlockAlgorithm, Hasher, Hex, Latin1, Utf8, _32, urs
from CryptoPy.x64core import X64Word, X64WordArray
from CryptoPy.enc_base64 import Base64
from CryptoPy.enc_base64url import Base64url
from CryptoPy.enc_utf16 import Utf16, Utf16BE, Utf16LE
from CryptoPy.cipher_core import (
    CipherParams, OpenSSLFormatter, HexFormatter,
    SerializableCipher, PasswordBasedCipher, OpenSSLKdf,
    Cipher, StreamCipher, BlockCipherMode,
    BlockCipher,
    CBC, CFB, CTR, ECB, OFB,
    Pkcs7, AnsiX923, Iso10126, Iso97971, ZeroPadding, NoPadding
)
from CryptoPy.md5 import MD5 as _MD5
from CryptoPy.sha1 import SHA1 as _SHA1
from CryptoPy.sha256 import SHA256 as _SHA256
from CryptoPy.sha224 import SHA224 as _SHA224
from CryptoPy.sha384 import SHA384 as _SHA384
from CryptoPy.sha512 import SHA512 as _SHA512
from CryptoPy.sha3 import SHA3 as _SHA3
from CryptoPy.ripemd160 import RIPEMD160 as _RIPEMD160
from CryptoPy.hmac import HMAC
from CryptoPy.evpkdf import EvpKDF as _EvpKDF
from CryptoPy.pbkdf2 import PBKDF2 as _PBKDF2
from CryptoPy.aes import AES as _AES
from CryptoPy.tripledes import DES as _DES, TripleDES as _TripleDES
from CryptoPy.rabbit import Rabbit as _Rabbit
from CryptoPy.rabbit_legacy import RabbitLegacy as _RabbitLegacy
from CryptoPy.rc4 import RC4 as _RC4, RC4Drop as _RC4Drop
from CryptoPy.sm3 import SM3 as _SM3
from CryptoPy.sm4 import SM4 as _SM4
from CryptoPy.zuc import ZUC as _ZUC
from CryptoPy.sm2 import (generate_keypair as _sm2_genkey,
                        sign as _sm2_sign, verify as _sm2_verify,
                        encrypt as _sm2_encrypt, decrypt as _sm2_decrypt)
from CryptoPy.sm9 import (setup as _sm9_setup,
                        generate_user_key as _sm9_genkey,
                        sign as _sm9_sign,
                        verify as _sm9_verify)
from CryptoPy.rsa import (generate_keypair as _rsa_genkey,
                          encrypt as _rsa_encrypt,
                          decrypt as _rsa_decrypt,
                          sign as _rsa_sign,
                          verify as _rsa_verify)

class _lib:
    Base = Base
    WordArray = WordArray
    BufferedBlockAlgorithm = BufferedBlockAlgorithm
    Hasher = Hasher
    CipherParams = CipherParams
    SerializableCipher = SerializableCipher
    PasswordBasedCipher = PasswordBasedCipher
    StreamCipher = StreamCipher
    BlockCipherMode = BlockCipherMode
    BlockCipher = BlockCipher
    Cipher = Cipher

lib = _lib()


class _algo:
    MD5 = _MD5
    SHA1 = _SHA1
    SHA256 = _SHA256
    SHA224 = _SHA224
    SHA384 = _SHA384
    SHA512 = _SHA512
    SHA3 = _SHA3
    RIPEMD160 = _RIPEMD160
    HMAC = HMAC
    EvpKDF = _EvpKDF
    PBKDF2 = _PBKDF2
    AES = _AES
    DES = _DES
    TripleDES = _TripleDES
    Rabbit = _Rabbit
    RabbitLegacy = _RabbitLegacy
    RC4 = _RC4
    RC4Drop = _RC4Drop
    SM3 = _SM3
    SM4 = _SM4
    ZUC = _ZUC

algo = _algo()


class _enc:
    Hex = Hex
    Latin1 = Latin1
    Utf8 = Utf8
    Utf16 = Utf16
    Utf16BE = Utf16BE
    Utf16LE = Utf16LE
    Base64 = Base64
    Base64url = Base64url

enc = _enc()


class _mode:
    CBC = CBC
    CFB = CFB
    CTR = CTR
    ECB = ECB
    OFB = OFB

mode = _mode()


class _pad:
    Pkcs7 = Pkcs7
    AnsiX923 = AnsiX923
    Iso10126 = Iso10126
    Iso97971 = Iso97971
    ZeroPadding = ZeroPadding
    NoPadding = NoPadding

pad = _pad()


class _hash:
    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"

hash = _hash()


class _format:
    OpenSSL = OpenSSLFormatter
    Hex = HexFormatter

format = _format()


class _kdf:
    OpenSSL = OpenSSLKdf

kdf = _kdf()


class _x64:
    Word = X64Word
    WordArray = X64WordArray

x64 = _x64()


def _bytes_to_wa(data):
    """Convert bytes to WordArray (4 bytes per 32-bit word)."""
    words = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        if len(chunk) < 4:
            chunk += b'\x00' * (4 - len(chunk))
        words.append(int.from_bytes(chunk, 'big'))
    return WordArray.create(words, len(data))


def _derive_key(password, key_bytes):
    """Derive key from password string using SHA256, truncated to key_bytes."""
    from CryptoPy.sha256 import SHA256 as _SHA256_for_key
    h = _SHA256_for_key.create()
    h.update(password if isinstance(password, str) else str(password))
    d = h.finalize()
    raw = bytes([(d.words[i // 4] >> (24 - (i % 4) * 8)) & 0xFF for i in range(min(key_bytes, d.sigBytes))])
    if key_bytes > d.sigBytes:
        extra = bytes([0]) * (key_bytes - d.sigBytes)
        raw = raw + extra
    words = []
    for i in range(0, len(raw), 4):
        chunk = raw[i:i + 4]
        if len(chunk) < 4:
            chunk += b'\x00' * (4 - len(chunk))
        words.append(int.from_bytes(chunk, 'big'))
    return WordArray.create(words, len(raw))


class _util:
    bytes_to_wa = staticmethod(_bytes_to_wa)

    @staticmethod
    def digest_all(data):
        """Run all digest algorithms and print a comparison table.
        
        Args:
            data: str, bytes, or WordArray to hash.
        
        Returns:
            str: formatted table.
        """
        digests = [
            ("MD5",       MD5),
            ("SHA1",      SHA1),
            ("RIPEMD160", RIPEMD160),
            ("SHA224",    SHA224),
            ("SM3",       SM3),
            ("SHA256",    SHA256),
            ("SHA3-224",  lambda d: SHA3(d, {"outputLength": 224})),
            ("SHA3-256",  lambda d: SHA3(d, {"outputLength": 256})),
            ("SHA384",    SHA384),
            ("SHA3-384",  lambda d: SHA3(d, {"outputLength": 384})),
            ("SHA512",    SHA512),
            ("SHA3-512",  lambda d: SHA3(d, {"outputLength": 512})),
        ]
        sep = "-" * 72
        w = 96
        lines = [sep, "Digest Algorithms  | Bits | Result (hex)", sep]
        for name, fn in digests:
            result = fn(data)
            h = result.toString()
            lines.append(f"  {name:<18} | {len(result)*8:>4} | {h[:w]}{'...' if len(h)>w else ''}")
        lines.append(sep)
        output = "\n".join(lines)
        print(output)
        return output

    @staticmethod
    def encrypt_all(data, key, iv=None):
        """Encrypt data with all symmetric ciphers and print a comparison table.
        
        Args:
            data: plaintext (str, bytes, or WordArray).
            key: password string for key derivation.
            iv: optional IV string (for block cipher modes).
        
        Returns:
            str: formatted table.
        """
        # Build cipher list: (name, cipher_class, key_bits, modes)
        ciphers = []
        for bits in [128, 256]:
            ciphers.append((f"AES-{bits}-ECB", AES, bits, [mode.ECB]))
            if iv:
                ciphers.append((f"AES-{bits}-CBC", AES, bits, [mode.CBC]))
                ciphers.append((f"AES-{bits}-CFB", AES, bits, [mode.CFB]))
                ciphers.append((f"AES-{bits}-OFB", AES, bits, [mode.OFB]))
                ciphers.append((f"AES-{bits}-CTR", AES, bits, [mode.CTR]))
        ciphers.append(("DES-ECB",   DES, 64,  [mode.ECB]))
        if iv:
            ciphers.append(("DES-CBC",   DES, 64,  [mode.CBC]))
        ciphers.append(("3DES-ECB",  TripleDES, 192, [mode.ECB]))
        if iv:
            ciphers.append(("3DES-CBC",  TripleDES, 192, [mode.CBC]))
        ciphers.append(("SM4-ECB",   SM4, 128, [mode.ECB]))
        if iv:
            ciphers.append(("SM4-CBC",   SM4, 128, [mode.CBC]))
        ciphers.append(("Rabbit",    Rabbit, 128, None))
        ciphers.append(("RC4",       RC4, 128, None))
        ciphers.append(("ZUC",       ZUC, 128, None))

        sep = "-" * 72
        lines = [sep, "Cipher            | KeySize | Ciphertext (hex)", sep]
        for name, cls, key_bits, modes in ciphers:
            try:
                key_wa = _derive_key(key, key_bits // 8)
                if modes is None:
                    cfg = {}
                    if iv:
                        cfg['iv'] = _derive_key(iv, 16)
                    ct = cls.encrypt(data, key_wa, cfg)
                else:
                    for m in modes:
                        cfg = {'mode': m, 'padding': pad.Pkcs7}
                        if m != mode.ECB:
                            if iv:
                                cfg['iv'] = _derive_key(iv, 16)
                            else:
                                cfg['iv'] = WordArray.create([0, 0, 0, 0], 16)
                        ct = cls.encrypt(data, key_wa, cfg)
                        ct_hex = ct.ciphertext.toString() if hasattr(ct, 'ciphertext') else str(ct)
                        display = ct_hex[:56] + "..." if len(ct_hex) > 60 else ct_hex
                        lines.append(f"  {name:<18} | {key_bits:>7} | {display}")
            except Exception as e:
                lines.append(f"  {name:<18} | {key_bits:>7} | ❌ {str(e)[:40]}")
        lines.append(sep)
        output = "\n".join(lines)
        print(output)
        return output

    @staticmethod
    def decrypt_all(data, key, iv=None):
        """Test all cipher roundtrips: encrypt → decrypt → verify.
        
        Args:
            data: plaintext (str, bytes, or WordArray).
            key: password string for key derivation.
            iv: optional IV string.
        
        Returns:
            str: formatted table with PASS/FAIL.
        """
        if isinstance(data, str):
            raw = data.encode()
        elif isinstance(data, WordArray):
            raw = bytes(data)
        else:
            raw = data

        ref = _bytes_to_wa(raw)

        ciphers = []
        for bits in [128, 256]:
            ciphers.append((f"AES-{bits}-ECB", AES, bits, [mode.ECB]))
            if iv:
                ciphers.append((f"AES-{bits}-CBC", AES, bits, [mode.CBC]))
                ciphers.append((f"AES-{bits}-CFB", AES, bits, [mode.CFB]))
                ciphers.append((f"AES-{bits}-OFB", AES, bits, [mode.OFB]))
                ciphers.append((f"AES-{bits}-CTR", AES, bits, [mode.CTR]))
        ciphers.append(("DES-ECB",   DES, 64,  [mode.ECB]))
        if iv:
            ciphers.append(("DES-CBC",   DES, 64,  [mode.CBC]))
        ciphers.append(("3DES-ECB",  TripleDES, 192, [mode.ECB]))
        if iv:
            ciphers.append(("3DES-CBC",  TripleDES, 192, [mode.CBC]))
        ciphers.append(("SM4-ECB",   SM4, 128, [mode.ECB]))
        if iv:
            ciphers.append(("SM4-CBC",   SM4, 128, [mode.CBC]))
        ciphers.append(("Rabbit",    Rabbit, 128, None))
        ciphers.append(("RC4",       RC4, 128, None))
        ciphers.append(("ZUC",       ZUC, 128, None))

        sep = "-" * 72
        lines = [sep, "Cipher            | KeySize | Status", sep]
        ok_count = 0
        total = 0
        for name, cls, key_bits, modes in ciphers:
            try:
                key_wa = _derive_key(key, key_bits // 8)
                if modes is None:
                    cfg = {}
                    if iv:
                        cfg['iv'] = _derive_key(iv, 16)
                    ct = cls.encrypt(data, key_wa, cfg)
                    pt = cls.decrypt(ct, key_wa, cfg)
                else:
                    for m in modes:
                        cfg = {'mode': m, 'padding': pad.Pkcs7}
                        if m != mode.ECB:
                            if iv:
                                cfg['iv'] = _derive_key(iv, 16)
                            else:
                                cfg['iv'] = WordArray.create([0, 0, 0, 0], 16)
                        ct = cls.encrypt(data, key_wa, cfg)
                        pt = cls.decrypt(ct, key_wa, cfg)
                ok = str(pt) == str(ref)
                total += 1
                if ok:
                    ok_count += 1
                mark = "✅ PASS" if ok else "❌ FAIL"
                lines.append(f"  {name:<18} | {key_bits:>7} | {mark}")
            except Exception as e:
                total += 1
                lines.append(f"  {name:<18} | {key_bits:>7} | ❌ {str(e)[:30]}")
        lines.append(sep)
        lines.append(f"  Result: {ok_count}/{total} passed")
        lines.append(sep)
        output = "\n".join(lines)
        print(output)
        return output

    @staticmethod
    def crypto_all(data, key=None, iv=None):
        """Run all applicable algorithms (digest + HMAC + cipher) in one shot."""
        sep = "-" * 72
        w = 96  # display width for hex (SHA384 needs 96 chars)
        out = [sep, "Digest Algorithms  | Bits | Result (hex)", sep]
        for name, fn in [("MD5",MD5),("SHA1",SHA1),("RIPEMD160",RIPEMD160),
                         ("SHA224",SHA224),("SM3",SM3),("SHA256",SHA256),
                         ("SHA3-224",lambda d:SHA3(d,{"outputLength":224})),
                         ("SHA3-256",lambda d:SHA3(d,{"outputLength":256})),
                         ("SHA384",SHA384),
                         ("SHA3-384",lambda d:SHA3(d,{"outputLength":384})),
                         ("SHA512",SHA512),
                         ("SHA3-512",lambda d:SHA3(d,{"outputLength":512}))]:
            r = fn(data)
            h = r.toString()
            out.append(f"  {name:<18} | {len(r)*8:>4} | {h[:w]}{'...' if len(h)>w else ''}")
        if key:
            out += [sep, "HMAC Algorithm     | Bits | Tag (hex)", sep]
            for name,fn in [("HmacMD5",HmacMD5),("HmacSHA1",HmacSHA1),
                            ("HmacRIPEMD160",HmacRIPEMD160),("HmacSHA224",HmacSHA224),
                            ("HmacSM3",HmacSM3),("HmacSHA256",HmacSHA256),
                            ("HmacSHA384",HmacSHA384),("HmacSHA512",HmacSHA512),
                            ("HmacSHA3",HmacSHA3)]:
                r = fn(data, key)
                h = r.toString()
                out.append(f"  {name:<18} | {len(r)*8:>4} | {h[:w]}{'...' if len(h)>w else ''}")
        out.append(sep)
        r = "\n".join(out)
        print(r)
        return r

    @staticmethod
    def _hmac_all(data, key):
        """Internal: run all HMAC algorithms, return formatted table."""
        hmacs = [
            ("HmacMD5",       HmacMD5),
            ("HmacSHA1",      HmacSHA1),
            ("HmacRIPEMD160", HmacRIPEMD160),
            ("HmacSHA224",    HmacSHA224),
            ("HmacSM3",       HmacSM3),
            ("HmacSHA256",    HmacSHA256),
            ("HmacSHA384",    HmacSHA384),
            ("HmacSHA512",    HmacSHA512),
            ("HmacSHA3",      HmacSHA3),
        ]
        sep = "-" * 72
        w = 96
        lines = [sep, "HMAC Algorithm     | Bits | Tag (hex)", sep]
        for name, fn in hmacs:
            result = fn(data, key)
            h = result.toString()
            lines.append(f"  {name:<18} | {len(result)*8:>4} | {h[:w]}{'...' if len(h)>w else ''}")
        lines.append(sep)
        output = "\n".join(lines)
        print(output)
        return output

util = _util()


MD5 = Hasher._createHelper(_MD5)
SHA1 = Hasher._createHelper(_SHA1)
SHA256 = Hasher._createHelper(_SHA256)
SHA224 = Hasher._createHelper(_SHA224)
SHA384 = Hasher._createHelper(_SHA384)
SHA512 = Hasher._createHelper(_SHA512)
SHA3 = Hasher._createHelper(_SHA3)
RIPEMD160 = Hasher._createHelper(_RIPEMD160)

HmacMD5 = Hasher._createHmacHelper(_MD5)
HmacSHA1 = Hasher._createHmacHelper(_SHA1)
HmacSHA256 = Hasher._createHmacHelper(_SHA256)
HmacSHA224 = Hasher._createHmacHelper(_SHA224)
HmacSHA384 = Hasher._createHmacHelper(_SHA384)
HmacSHA512 = Hasher._createHmacHelper(_SHA512)
HmacSHA3 = Hasher._createHmacHelper(_SHA3)
HmacRIPEMD160 = Hasher._createHmacHelper(_RIPEMD160)

PBKDF2 = lambda password, salt, cfg=None: _PBKDF2.create(cfg).compute(password, salt)
EvpKDF = lambda password, salt, cfg=None: _EvpKDF.create(cfg).compute(password, salt)

AES = BlockCipher._createHelper(_AES)
DES = BlockCipher._createHelper(_DES)
TripleDES = BlockCipher._createHelper(_TripleDES)
Rabbit = StreamCipher._createHelper(_Rabbit)
RabbitLegacy = StreamCipher._createHelper(_RabbitLegacy)
RC4 = StreamCipher._createHelper(_RC4)
RC4Drop = StreamCipher._createHelper(_RC4Drop)

SM3 = Hasher._createHelper(_SM3)
HmacSM3 = Hasher._createHmacHelper(_SM3)
SM4 = BlockCipher._createHelper(_SM4)
ZUC = StreamCipher._createHelper(_ZUC)


class SM2:
    """SM2 public key cryptography (GM/T 0003-2012).
    
    Follows crypto-js convention: method(message, key, ...).
    
    Usage:
        sk, pk = CryptoPy.SM2.generate_keypair()
        sig = CryptoPy.SM2.sign("message", sk)
        ok  = CryptoPy.SM2.verify("message", sig, pk)
        ct  = CryptoPy.SM2.encrypt("message", pk)
        pt  = CryptoPy.SM2.decrypt(ct, sk)
    """
    generate_keypair = staticmethod(_sm2_genkey)
    sign = staticmethod(lambda msg, key, ida=None: _sm2_sign(msg, key, ida=ida))
    verify = staticmethod(lambda msg, sig, key, ida=None: _sm2_verify(msg, sig, key, ida=ida))
    encrypt = staticmethod(lambda msg, key: _sm2_encrypt(msg, key))
    decrypt = staticmethod(lambda ct, key: _sm2_decrypt(ct, key))


class SM9:
    """SM9 identity-based cryptography (GM/T 0044-2016).
    
    Follows crypto-js convention: method(message, key, ...).
    
    Usage:
        mpk, msk = CryptoPy.SM9.setup()
        usk = CryptoPy.SM9.generate_user_key(msk, b"alice")
        sig = CryptoPy.SM9.sign(b"message", usk)
        ok  = CryptoPy.SM9.verify(b"message", sig, mpk, b"alice")
    """
    setup = staticmethod(_sm9_setup)
    generate_user_key = staticmethod(_sm9_genkey)
    sign = staticmethod(lambda msg, key: _sm9_sign(msg, key))
    verify = staticmethod(lambda msg, sig, mpk, id, hid=0x01: _sm9_verify(msg, sig, mpk, id, hid=hid))


class RSA:
    """RSA public key cryptography (PKCS#1 v1.5).

    Follows crypto-js convention: method(message, key, ...).
    verify() returns True on success (not hash name).

    Usage:
        priv, pub = CryptoPy.RSA.generate_keypair(2048)
        ct  = CryptoPy.RSA.encrypt("message", pub)
        pt  = CryptoPy.RSA.decrypt(ct, priv)
        sig = CryptoPy.RSA.sign("message", priv, "SHA-256")
        ok  = CryptoPy.RSA.verify("message", sig, pub)
    """
    generate_keypair = staticmethod(_rsa_genkey)
    encrypt = staticmethod(_rsa_encrypt)
    decrypt = staticmethod(_rsa_decrypt)
    sign = staticmethod(_rsa_sign)
    verify = staticmethod(_rsa_verify)


algo.SM2 = SM2
algo.SM9 = SM9
algo.RSA = RSA
