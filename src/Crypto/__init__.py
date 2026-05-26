"""
Crypto — Python port of CryptoJS.

Usage:
    import Crypto
    Crypto.MD5("message")
    Crypto.SHA256("message")
    Crypto.AES.encrypt("data", "password")
    Crypto.enc.Hex.parse("48656c6c6f")
    Crypto.mode.CBC
"""

from Crypto.core import Base, WordArray, BufferedBlockAlgorithm, Hasher, Hex, Latin1, Utf8, _32, urs
from Crypto.x64core import X64Word, X64WordArray
from Crypto.enc_base64 import Base64
from Crypto.enc_base64url import Base64url
from Crypto.enc_utf16 import Utf16, Utf16BE, Utf16LE
from Crypto.cipher_core import (
    CipherParams, OpenSSLFormatter, HexFormatter,
    SerializableCipher, PasswordBasedCipher, OpenSSLKdf,
    Cipher, StreamCipher, BlockCipherMode,
    BlockCipher,
    CBC, CFB, CTR, ECB, OFB,
    Pkcs7, AnsiX923, Iso10126, Iso97971, ZeroPadding, NoPadding
)
from Crypto.md5 import MD5 as _MD5
from Crypto.sha1 import SHA1 as _SHA1
from Crypto.sha256 import SHA256 as _SHA256
from Crypto.sha224 import SHA224 as _SHA224
from Crypto.sha384 import SHA384 as _SHA384
from Crypto.sha512 import SHA512 as _SHA512
from Crypto.sha3 import SHA3 as _SHA3
from Crypto.ripemd160 import RIPEMD160 as _RIPEMD160
from Crypto.hmac import HMAC
from Crypto.evpkdf import EvpKDF as _EvpKDF
from Crypto.pbkdf2 import PBKDF2 as _PBKDF2
from Crypto.aes import AES as _AES
from Crypto.tripledes import DES as _DES, TripleDES as _TripleDES
from Crypto.rabbit import Rabbit as _Rabbit
from Crypto.rabbit_legacy import RabbitLegacy as _RabbitLegacy
from Crypto.rc4 import RC4 as _RC4, RC4Drop as _RC4Drop
from Crypto.sm3 import SM3 as _SM3
from Crypto.sm4 import SM4 as _SM4
from Crypto.zuc import ZUC as _ZUC


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
SM4 = BlockCipher._createHelper(_SM4)
ZUC = StreamCipher._createHelper(_ZUC)
