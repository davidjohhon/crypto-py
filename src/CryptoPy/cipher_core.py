"""
cipher_core.py — Cipher infrastructure, block cipher modes, and padding schemes.

Provides the base classes for symmetric encryption:
  - Cipher / StreamCipher / BlockCipher: algorithm hierarchy.
  - BlockCipherMode: mode of operation (CBC, CFB, CTR, ECB, OFB).
  - Padding schemes: Pkcs7, AnsiX923, Iso10126, Iso97971, ZeroPadding, NoPadding.
  - SerializableCipher: high-level encrypt/decrypt with serialisation.
  - PasswordBasedCipher: password-based key derivation + encryption.
  - OpenSSLFormatter / HexFormatter: ciphertext serialisation formats.
  - OpenSSLKdf: OpenSSL-compatible key derivation (EVP_BytesToKey).

Design notes:
  - Cipher modes use a paired Encryptor/Decryptor class pattern.  Modes
    like CTR and OFB share the same encryptor for both directions because
    they are stream modes (encrypt and decrypt are XOR-identical).
  - BlockCipher's _doFinalize applies padding before flush on encrypt,
    and removes padding after flush on decrypt.
"""

import math
from CryptoPy.core import WordArray, BufferedBlockAlgorithm, Base, _32, urs
from CryptoPy.enc_base64 import Base64


def _merge_cfg(base_cfg, override_cfg):
    """
    Merge two config objects (or dicts) into a new anonymous object.

    Properties from override_cfg take precedence over base_cfg.
    Supports both dict and object (namespace) sources.
    """
    merged = type('merged', (), {})()
    if base_cfg:
        if isinstance(base_cfg, dict):
            for k, v in base_cfg.items():
                setattr(merged, k, v)
        else:
            for k in dir(base_cfg):
                if not k.startswith('_'):
                    setattr(merged, k, getattr(base_cfg, k))
    if override_cfg:
        if isinstance(override_cfg, dict):
            for k, v in override_cfg.items():
                setattr(merged, k, v)
        else:
            for k in dir(override_cfg):
                if not k.startswith('_'):
                    setattr(merged, k, getattr(override_cfg, k))
    return merged


class CipherParams(Base):
    """
    Container for ciphertext, key, iv, salt, algorithm, mode, padding, etc.

    Used as the return type for SerializableCipher.encrypt() and as an
    intermediate when parsing OpenSSL-formatted ciphertext.
    """

    def init(self, params=None):
        if params:
            self.mixIn(params)

    def toString(self, formatter=None):
        if formatter is None:
            formatter = self.formatter
        try:
            return formatter.stringify(self)
        except (AttributeError, TypeError):
            return formatter.stringify(self.ciphertext)

    def __str__(self):
        return self.toString()


class OpenSSLFormatter:
    """
    OpenSSL-compatible ciphertext serialisation.

    Format: Base64("Salted__" + 8-byte salt + ciphertext).

    The magic bytes 0x53616c74, 0x65645f5f are the ASCII for "Salted__".
    """

    @staticmethod
    def stringify(cipherParams):
        """Encode ciphertext + optional salt to OpenSSL Base64 format."""
        ciphertext = cipherParams.ciphertext
        salt = getattr(cipherParams, 'salt', None)
        if salt:
            wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext)
        else:
            wordArray = ciphertext
        return wordArray.toString(Base64)

    @staticmethod
    def parse(openSSLStr):
        """Parse an OpenSSL-formatted Base64 string into CipherParams."""
        salt = None
        ciphertext = Base64.parse(openSSLStr)
        ciphertextWords = ciphertext.words
        if len(ciphertextWords) >= 2 and ciphertextWords[0] == 0x53616c74 and ciphertextWords[1] == 0x65645f5f:
            salt = WordArray.create(ciphertextWords[2:4])
            del ciphertextWords[:4]
            ciphertext.sigBytes -= 16
        return CipherParams.create({'ciphertext': ciphertext, 'salt': salt})


class HexFormatter:
    """Hex ciphertext serialisation."""

    @staticmethod
    def stringify(cipherParams):
        from CryptoPy.core import Hex
        return cipherParams.ciphertext.toString(Hex)

    @staticmethod
    def parse(inputStr):
        from CryptoPy.core import Hex
        ciphertext = Hex.parse(inputStr)
        return CipherParams.create({'ciphertext': ciphertext})


class SerializableCipher(Base):
    """
    High-level encryption/decryption with configurable serialisation.

    Delegates to a Cipher subclass for the actual cryptographic operation,
    then wraps the result in a CipherParams object with metadata.
    """

    cfg = type('cfg', (), {'format': OpenSSLFormatter})()

    @classmethod
    def encrypt(cls, cipher, message, key, cfg=None):
        """Encrypt a message with the given cipher and key."""
        cfg = _merge_cfg(cls.cfg, cfg)

        encryptor = cipher.createEncryptor(key, cfg)
        ciphertext = encryptor.finalize(message)
        cipherCfg = encryptor.cfg

        return CipherParams.create({
            'ciphertext': ciphertext,
            'key': key,
            'iv': getattr(cipherCfg, 'iv', None),
            'algorithm': cipher,
            'mode': getattr(cipherCfg, 'mode', None),
            'padding': getattr(cipherCfg, 'padding', None),
            'blockSize': cipher.blockSize,
            'formatter': getattr(cfg, 'format', OpenSSLFormatter)
        })

    @classmethod
    def decrypt(cls, cipher, ciphertext, key, cfg=None):
        """Decrypt ciphertext with the given cipher and key."""
        cfg = _merge_cfg(cls.cfg, cfg)

        if isinstance(ciphertext, str):
            ciphertext = getattr(cfg, 'format', OpenSSLFormatter).parse(ciphertext)

        plaintext = cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext)
        return plaintext


class OpenSSLKdf:
    """OpenSSL-compatible key derivation (EVP_BytesToKey wrapper)."""

    @staticmethod
    def execute(password, keySize, ivSize, salt=None, hasher=None):
        """
        Derive key and IV from password using EvpKDF.

        Returns a CipherParams with 'key', 'iv', and 'salt'.
        """
        if salt is None:
            salt = WordArray.random(64 // 8)
        from CryptoPy.evpkdf import EvpKDF
        if hasher is None:
            derived = EvpKDF.create({'keySize': keySize + ivSize}).compute(password, salt)
        else:
            derived = EvpKDF.create({'keySize': keySize + ivSize, 'hasher': hasher}).compute(password, salt)

        iv = WordArray.create(derived.words[keySize:], ivSize * 4)
        derived.sigBytes = keySize * 4

        return CipherParams.create({'key': derived, 'iv': iv, 'salt': salt})


class PasswordBasedCipher(SerializableCipher):
    """
    Password-based encryption using a KDF.

    The password is run through the configured KDF (default OpenSSLKdf)
    to produce a key and IV, then encryption proceeds as normal.
    """

    cfg = type('cfg', (), {'format': OpenSSLFormatter, 'kdf': OpenSSLKdf})()

    @classmethod
    def encrypt(cls, cipher, message, password, cfg=None):
        """Encrypt a message using a password (KDF-derived key)."""
        cfg = _merge_cfg(cls.cfg, cfg)

        kdf = getattr(cfg, 'kdf', OpenSSLKdf)
        derivedParams = kdf.execute(password, cipher.keySize, cipher.ivSize,
                                     getattr(cfg, 'salt', None), getattr(cfg, 'hasher', None))
        cfg.iv = derivedParams.iv

        ciphertext = SerializableCipher.encrypt(cipher, message, derivedParams.key, cfg)
        ciphertext.mixIn({'salt': derivedParams.salt})
        if hasattr(ciphertext, 'iv') and ciphertext.iv is None:
            ciphertext.iv = derivedParams.iv
        return ciphertext

    @classmethod
    def decrypt(cls, cipher, ciphertext, password, cfg=None):
        """Decrypt ciphertext using a password (KDF-derived key)."""
        cfg = _merge_cfg(cls.cfg, cfg)

        if isinstance(ciphertext, str):
            ciphertext = getattr(cfg, 'format', OpenSSLFormatter).parse(ciphertext)

        kdf = getattr(cfg, 'kdf', OpenSSLKdf)
        derivedParams = kdf.execute(password, cipher.keySize, cipher.ivSize,
                                     getattr(ciphertext, 'salt', None), getattr(cfg, 'hasher', None))
        cfg.iv = derivedParams.iv

        plaintext = SerializableCipher.decrypt(cipher, ciphertext, derivedParams.key, cfg)
        return plaintext


class Cipher(BufferedBlockAlgorithm):
    """
    Base class for all cipher algorithms.

    Subclasses must define:
      - keySize, ivSize (in 32-bit words).
      - _doReset(): initialise cipher state from self._key.
      - _doProcessBlock(M, offset): process one block.
      - _doFinalize(): finalise and return the output.

    Modes:
      _ENC_XFORM_MODE = 1 (encrypting)
      _DEC_XFORM_MODE = 2 (decrypting)
    """

    keySize = 128 // 32
    ivSize = 128 // 32
    _ENC_XFORM_MODE = 1
    _DEC_XFORM_MODE = 2

    def __init__(self, *args, **kwargs):
        super().__init__()

    def init(self, xformMode, key, cfg=None):
        self.cfg = _merge_cfg(None, cfg)
        self._xformMode = xformMode
        self._key = key
        self.reset()

    @classmethod
    def createEncryptor(cls, key, cfg=None):
        """Create an encryptor instance."""
        return cls.create(cls._ENC_XFORM_MODE, key, cfg)

    @classmethod
    def createDecryptor(cls, key, cfg=None):
        """Create a decryptor instance."""
        return cls.create(cls._DEC_XFORM_MODE, key, cfg)

    def reset(self):
        BufferedBlockAlgorithm.reset(self)
        self._doReset()

    def process(self, dataUpdate):
        """Process more data (progressive API)."""
        self._append(dataUpdate)
        return self._process()

    def finalize(self, dataUpdate=None):
        """Finalise the cipher operation, returning the remaining output."""
        if dataUpdate:
            self._append(dataUpdate)
        return self._doFinalize()

    @staticmethod
    def _createHelper(cipher):
        """
        Return a convenience Helper class with encrypt/decrypt static methods.

        When 'key' is a string, the helper uses PasswordBasedCipher
        (password → KDF → key).  When it is a WordArray (raw key),
        it uses SerializableCipher directly.
        """
        def selectCipherStrategy(key):
            if isinstance(key, str):
                return PasswordBasedCipher
            else:
                return SerializableCipher

        class Helper:
            @staticmethod
            def encrypt(message, key, cfg=None):
                return selectCipherStrategy(key).encrypt(cipher, message, key, cfg)

            @staticmethod
            def decrypt(ciphertext, key, cfg=None):
                return selectCipherStrategy(key).decrypt(cipher, ciphertext, key, cfg)

        return Helper


class StreamCipher(Cipher):
    """
    Base class for stream ciphers (blockSize = 1 word).

    XOR-based stream ciphers process data in arbitrarily small units.
    _doFinalize simply flushes remaining buffered data.
    """

    blockSize = 1

    def _doFinalize(self):
        return self._process(doFlush=True)


class BlockCipherMode(Base):
    """
    Base class for block cipher modes of operation.

    Each mode typically defines two subclasses: Encryptor and Decryptor.
    A mode can reuse the same class for both directions (CTR, OFB).
    """

    def init(self, cipher, iv):
        self._cipher = cipher
        self._iv = iv

    @classmethod
    def createEncryptor(cls, cipher, iv):
        return cls.Encryptor.create(cipher, iv) if hasattr(cls, 'Encryptor') else cls.create(cipher, iv)

    @classmethod
    def createDecryptor(cls, cipher, iv):
        return cls.Decryptor.create(cipher, iv) if hasattr(cls, 'Decryptor') else cls.create(cipher, iv)


class CBC(BlockCipherMode):
    """
    Cipher Block Chaining (CBC) mode.

    Each plaintext block is XORed with the previous ciphertext block
    (or IV for the first block) before encryption.
    """
    pass


class CBCEncryptor(BlockCipherMode):
    def processBlock(self, words, offset):
        cipher = self._cipher
        blockSize = cipher.blockSize
        self._xorBlock(words, offset, blockSize)
        cipher.encryptBlock(words, offset)
        self._prevBlock = words[offset:offset + blockSize]

    def _xorBlock(self, words, offset, blockSize):
        iv = getattr(self, '_iv', None)
        if iv:
            block = iv
            self._iv = None
        else:
            block = self._prevBlock
        for i in range(blockSize):
            words[offset + i] ^= block[i]


class CBCDecryptor(BlockCipherMode):
    def processBlock(self, words, offset):
        cipher = self._cipher
        blockSize = cipher.blockSize
        thisBlock = words[offset:offset + blockSize]
        cipher.decryptBlock(words, offset)
        self._xorBlock(words, offset, blockSize)
        self._prevBlock = thisBlock

    def _xorBlock(self, words, offset, blockSize):
        iv = getattr(self, '_iv', None)
        if iv:
            block = iv
            self._iv = None
        else:
            block = self._prevBlock
        for i in range(blockSize):
            words[offset + i] ^= block[i]


CBC.Encryptor = CBCEncryptor
CBC.Decryptor = CBCDecryptor


class CFB(BlockCipherMode):
    """
    Cipher Feedback (CFB) mode.

    The previous ciphertext block is encrypted and the result is XORed
    with the plaintext to produce the next ciphertext block.
    """
    pass


class CFBEncryptor(BlockCipherMode):
    def processBlock(self, words, offset):
        cipher = self._cipher
        blockSize = cipher.blockSize
        iv = getattr(self, '_iv', None)
        if iv:
            keystream = iv[:]
            self._iv = None
        else:
            keystream = self._prevBlock
        cipher.encryptBlock(keystream, 0)
        for i in range(blockSize):
            words[offset + i] ^= keystream[i]
        self._prevBlock = words[offset:offset + blockSize]


class CFBDecryptor(BlockCipherMode):
    def processBlock(self, words, offset):
        cipher = self._cipher
        blockSize = cipher.blockSize
        thisBlock = words[offset:offset + blockSize]
        iv = getattr(self, '_iv', None)
        if iv:
            keystream = iv[:]
            self._iv = None
        else:
            keystream = self._prevBlock
        cipher.encryptBlock(keystream, 0)
        for i in range(blockSize):
            words[offset + i] ^= keystream[i]
        self._prevBlock = thisBlock


CFB.Encryptor = CFBEncryptor
CFB.Decryptor = CFBDecryptor


class CTR(BlockCipherMode):
    """
    Counter (CTR) mode.

    A counter block is encrypted and XORed with the plaintext.
    The counter is incremented for each subsequent block.
    Encrypt and decrypt are identical operations.
    """
    pass


class CTREncryptor(BlockCipherMode):
    def processBlock(self, words, offset):
        cipher = self._cipher
        blockSize = cipher.blockSize
        iv = getattr(self, '_iv', None)
        counter = getattr(self, '_counter', None)
        if iv:
            counter = self._counter = iv[:]
            self._iv = None
        keystream = counter[:]
        cipher.encryptBlock(keystream, 0)
        counter[blockSize - 1] = _32(counter[blockSize - 1] + 1)
        for i in range(blockSize):
            words[offset + i] ^= keystream[i]


CTR.Encryptor = CTREncryptor
CTR.Decryptor = CTREncryptor


class ECB(BlockCipherMode):
    """
    Electronic Codebook (ECB) mode.

    Each block is encrypted independently.  Not semantically secure;
    mainly included for compatibility.
    """
    pass


class ECBEncryptor(BlockCipherMode):
    def processBlock(self, words, offset):
        self._cipher.encryptBlock(words, offset)


class ECBDecryptor(BlockCipherMode):
    def processBlock(self, words, offset):
        self._cipher.decryptBlock(words, offset)


ECB.Encryptor = ECBEncryptor
ECB.Decryptor = ECBDecryptor


class OFB(BlockCipherMode):
    """
    Output Feedback (OFB) mode.

    The encryption output is fed back as input for the next block,
    creating a keystream that is XORed with the plaintext.
    Encrypt and decrypt are identical.
    """
    pass


class OFBEncryptor(BlockCipherMode):
    def processBlock(self, words, offset):
        cipher = self._cipher
        blockSize = cipher.blockSize
        iv = getattr(self, '_iv', None)
        keystream = getattr(self, '_keystream', None)
        if iv:
            keystream = self._keystream = iv[:]
            self._iv = None
        cipher.encryptBlock(keystream, 0)
        for i in range(blockSize):
            words[offset + i] ^= keystream[i]


OFB.Encryptor = OFBEncryptor
OFB.Decryptor = OFBEncryptor


class Pkcs7:
    """
    PKCS#7 / RFC 5652 padding.

    Pad bytes each have the value of the number of padding bytes.
    For example, 3 bytes of padding are each 0x03.
    """

    @staticmethod
    def pad(data, blockSize):
        blockSizeBytes = blockSize * 4
        nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes
        paddingWord = (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes
        paddingWords = [paddingWord] * int(math.ceil(nPaddingBytes / 4))
        padding = WordArray.create(paddingWords, nPaddingBytes)
        data.concat(padding)

    @staticmethod
    def unpad(data):
        nPaddingBytes = data.words[(data.sigBytes - 1) >> 2] & 0xFF
        data.sigBytes -= nPaddingBytes


class AnsiX923:
    """
    ANSI X.923 padding.

    Pad with zeros except for the last byte, which contains the number
    of padding bytes.
    """

    @staticmethod
    def pad(data, blockSize):
        dataSigBytes = data.sigBytes
        blockSizeBytes = blockSize * 4
        nPaddingBytes = blockSizeBytes - dataSigBytes % blockSizeBytes
        lastBytePos = dataSigBytes + nPaddingBytes - 1
        data.clamp()
        while len(data.words) <= (lastBytePos >> 2):
            data.words.append(0)
        data.words[lastBytePos >> 2] = _32(data.words[lastBytePos >> 2] | (nPaddingBytes << (24 - (lastBytePos % 4) * 8)))
        data.sigBytes += nPaddingBytes

    @staticmethod
    def unpad(data):
        nPaddingBytes = data.words[(data.sigBytes - 1) >> 2] & 0xFF
        data.sigBytes -= nPaddingBytes


class Iso10126:
    """
    ISO 10126 padding.

    Pad with random bytes; the last byte contains the number of padding bytes.
    Withdrawn standard, included for compatibility.
    """

    @staticmethod
    def pad(data, blockSize):
        blockSizeBytes = blockSize * 4
        nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes
        random_part = WordArray.random(nPaddingBytes - 1)
        last_byte = WordArray.create([nPaddingBytes << 24], 1)
        data.concat(random_part).concat(last_byte)

    @staticmethod
    def unpad(data):
        nPaddingBytes = data.words[(data.sigBytes - 1) >> 2] & 0xFF
        data.sigBytes -= nPaddingBytes


class Iso97971:
    """
    ISO 9797-1 Method 1 / ISO 7816-4 padding.

    Append a single 0x80 byte, then pad with zeros to the block boundary.
    """

    @staticmethod
    def pad(data, blockSize):
        data.concat(WordArray.create([0x80000000], 1))
        ZeroPadding.pad(data, blockSize)

    @staticmethod
    def unpad(data):
        ZeroPadding.unpad(data)
        data.sigBytes -= 1


class ZeroPadding:
    """
    Zero padding.

    Pad with zero bytes.  Unpad by stripping trailing zeros.
    Note: this is ambiguous if the original data ends with zeros.
    """

    @staticmethod
    def pad(data, blockSize):
        blockSizeBytes = blockSize * 4
        data.clamp()
        data.sigBytes += blockSizeBytes - ((data.sigBytes % blockSizeBytes) or blockSizeBytes)

    @staticmethod
    def unpad(data):
        i = data.sigBytes - 1
        while i >= 0:
            if (data.words[i >> 2] >> (24 - (i % 4) * 8)) & 0xFF:
                data.sigBytes = i + 1
                break
            i -= 1


class NoPadding:
    """No padding — data must already be block-aligned."""

    @staticmethod
    def pad(data, blockSize):
        pass

    @staticmethod
    def unpad(data):
        pass


class BlockCipher(Cipher):
    """
    Base class for block ciphers (e.g. AES, DES, TripleDES).

    Default blockSize = 4 words (128 bits), mode = CBC, padding = Pkcs7.

    At reset(), the configured mode's Encryptor/Decryptor is created.
    On finalization, padding is applied (encrypt) or removed (decrypt).
    """

    blockSize = 128 // 32

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def init(self, xformMode, key, cfg=None):
        super().init(xformMode, key, cfg)
        if not hasattr(self.cfg, 'mode') or self.cfg.mode is None:
            self.cfg.mode = CBC
        if not hasattr(self.cfg, 'padding') or self.cfg.padding is None:
            self.cfg.padding = Pkcs7

    def reset(self):
        Cipher.reset(self)
        cfg = self.cfg
        iv = getattr(cfg, 'iv', None)
        mode = getattr(cfg, 'mode', CBC)

        if self._xformMode == self._ENC_XFORM_MODE:
            modeCreator = mode.createEncryptor
        else:
            modeCreator = mode.createDecryptor
            self._minBufferSize = 1

        self._mode = modeCreator(self, iv.words if iv else None)

    def _doProcessBlock(self, words, offset):
        self._mode.processBlock(words, offset)

    def _doFinalize(self):
        padding = getattr(self.cfg, 'padding', Pkcs7)
        if self._xformMode == self._ENC_XFORM_MODE:
            padding.pad(self._data, self.blockSize)
            finalProcessedBlocks = self._process(doFlush=True)
        else:
            finalProcessedBlocks = self._process(doFlush=True)
            padding.unpad(finalProcessedBlocks)
        return finalProcessedBlocks
