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
                        sign as _sm9_sign, verify as _sm9_verify)


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
    """SM2 public key cryptography.
    
    Usage:
        sk, pk = CryptoPy.SM2.generate_keypair()
        sig = CryptoPy.SM2.sign(sk, "message")
        ok  = CryptoPy.SM2.verify(pk, "message", sig)
        ct  = CryptoPy.SM2.encrypt(pk, "message")
        pt  = CryptoPy.SM2.decrypt(sk, ct)
    """
    generate_keypair = staticmethod(_sm2_genkey)
    sign = staticmethod(_sm2_sign)
    verify = staticmethod(_sm2_verify)
    encrypt = staticmethod(_sm2_encrypt)
    decrypt = staticmethod(_sm2_decrypt)


class SM9:
    """SM9 identity-based cryptography.
    
    Usage:
        mpk, msk = CryptoPy.SM9.setup()
        usk = CryptoPy.SM9.generate_user_key(msk, "alice")
        sig = CryptoPy.SM9.sign(usk, "message")
        ok  = CryptoPy.SM9.verify(mpk, "alice", "message", sig)
    """
    setup = staticmethod(_sm9_setup)
    generate_user_key = staticmethod(_sm9_genkey)
    sign = staticmethod(_sm9_sign)
    verify = staticmethod(_sm9_verify)


algo.SM2 = SM2
algo.SM9 = SM9
