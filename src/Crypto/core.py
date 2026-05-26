"""
core.py — Foundation classes for Crypto (port of CryptoJS core).

Provides the base class hierarchy, 32-bit integer helpers, the WordArray
data type, progressive hashing infrastructure, and string encoders.

Key design notes:
  - This is a port of JavaScript CryptoJS. Python ints are arbitrary
    precision, whereas JS numbers are 32-bit for bitwise ops.  The _32()
    and urs() helpers emulate unsigned 32-bit truncation and the JS >>>
    (unsigned right shift) operator respectively.
  - The Base.create() / init() pattern mirrors JS prototypal inheritance.
    Base.extend() creates a subclass with optional overrides; Base.create()
    instantiates and calls init() in one step.
  - WordArray stores data as big-endian 32-bit words.  Byte i maps to
    word i>>2, bits 24-(i%4)*8.
  - The BufferedBlockAlgorithm provides a progressive data processing
    pipeline: data is accumulated (via _append) and processed in blocks
    (via _process).
  - Hasher implements the update()/finalize() progressive API.
"""

import secrets
import math


def _32(x):
    """Truncate x to unsigned 32-bit integer (emulates JS 32-bit overflow)."""
    return x & 0xFFFFFFFF


def urs(x, n):
    """Unsigned right shift — emulates JS >>> operator on 32-bit values."""
    return (x & 0xFFFFFFFF) >> n


class Base:
    """
    Root class implementing a CryptoJS-like pseudo-class system.

    JS prototypal inheritance is emulated through:
      - extend(cls) → creates a subclass with method overrides.
      - create(*args, **kwargs) → allocates and calls init().
      - mixIn(props) → copies properties onto an instance.
      - clone() → shallow-copies all __dict__ attributes.
    """

    @classmethod
    def extend(cls, overrides=None):
        """Create a subclass of cls, optionally overriding methods/attrs."""
        class Subtype(cls):
            pass
        Subtype._super = cls
        if overrides:
            for k, v in overrides.items():
                setattr(Subtype, k, v)
        if not hasattr(Subtype, 'init') or cls.init.__func__ == Subtype.init.__func__:
            def init(self, *args, **kwargs):
                cls.init(self, *args, **kwargs)
            Subtype.init = init
        return Subtype

    @classmethod
    def create(cls, *args, **kwargs):
        """Create and initialize an instance in one call."""
        instance = cls()
        instance.init(*args, **kwargs)
        return instance

    def init(self):
        """Subclass hook — called by create() after construction."""
        pass

    def mixIn(self, properties):
        """Copy key-value pairs (excluding 'toString') onto self."""
        if properties:
            for k, v in properties.items():
                if k != 'toString':
                    setattr(self, k, v)

    def clone(self):
        """Shallow-copy all instance attributes to a new instance."""
        clone = object.__new__(self.__class__)
        for k, v in self.__dict__.items():
            setattr(clone, k, v)
        return clone


class WordArray(Base):
    """
    Array of big-endian 32-bit words representing a byte sequence.

    Byte layout: byte i is stored in words[i>>2], occupying the
    (24 - (i%4)*8) .. (31 - (i%4)*8) bit range (big-endian within word).

    Attributes:
        words (list[int]): 32-bit words.
        sigBytes (int): number of significant bytes (may be < 4*len(words)).
    """

    def init(self, words=None, sigBytes=None):
        words = words or []
        self.words = [w & 0xFFFFFFFF for w in words]
        if sigBytes is not None:
            self.sigBytes = sigBytes
        else:
            self.sigBytes = len(self.words) * 4

    def toString(self, encoder=None):
        """Encode as a string using the given encoder (default Hex)."""
        if encoder is None:
            encoder = Hex
        return encoder.stringify(self)

    def __str__(self):
        return self.toString()

    def __repr__(self):
        return self.toString()

    def concat(self, wordArray):
        """Append another WordArray to this one, handling unaligned bytes."""
        self.clamp()
        if self.sigBytes % 4:
            # Partial last word: merge byte-by-byte to align correctly.
            for i in range(wordArray.sigBytes):
                thatByte = (wordArray.words[i >> 2] >> (24 - (i % 4) * 8)) & 0xFF
                idx = (self.sigBytes + i) >> 2
                if idx >= len(self.words):
                    self.words.append(0)
                self.words[idx] = _32(self.words[idx] | (thatByte << (24 - ((self.sigBytes + i) % 4) * 8)))
        else:
            # Word-aligned: fast path, copy whole words.
            for j in range(0, wordArray.sigBytes, 4):
                idx = (self.sigBytes + j) >> 2
                if idx >= len(self.words):
                    self.words.append(0)
                self.words[idx] = wordArray.words[j >> 2]
        self.sigBytes += wordArray.sigBytes
        return self

    def clamp(self):
        """
        Zero out unused bits in the last word and prune extra words.

        If sigBytes is not a multiple of 4, the trailing bytes in the
        last word that are not part of the data are zeroed.
        """
        if not self.words or self.sigBytes == 0:
            return
        idx = self.sigBytes >> 2
        if idx < len(self.words):
            self.words[idx] = _32(self.words[idx] & (0xFFFFFFFF << (32 - (self.sigBytes % 4) * 8)))
        self.words = self.words[:int(math.ceil(self.sigBytes / 4))]

    def clone(self):
        return WordArray.create(list(self.words), self.sigBytes)

    @staticmethod
    def random(nBytes):
        """Generate a WordArray filled with cryptographically random bytes."""
        words = []
        for i in range(0, nBytes, 4):
            rand_bytes = secrets.token_bytes(4)
            words.append(int.from_bytes(rand_bytes, 'big'))
        return WordArray.create(words, nBytes)


class BufferedBlockAlgorithm(Base):
    """
    Base for algorithms that process data in fixed-size blocks.

    Provides:
      - _data (WordArray): internal accumulator.
      - _nDataBytes: total bytes fed so far.
      - _append(data): add data to the buffer.
      - _process(doFlush): consume as many full blocks as possible.
      - Subclasses must define blockSize (in 32-bit words) and
        _doProcessBlock(M, offset).
    """

    _minBufferSize = 0

    def init(self):
        self.reset()

    def reset(self):
        self._data = WordArray.create()
        self._nDataBytes = 0

    def _append(self, data):
        """Append data (str or WordArray) to the internal buffer."""
        if isinstance(data, str):
            data = Utf8.parse(data)
        self._data.concat(data)
        self._nDataBytes += data.sigBytes

    def _process(self, doFlush=False):
        """
        Process buffered data, consuming full blocks.

        When doFlush is True, any remaining partial block is also
        processed (padded by the concrete subclass).
        """
        data = self._data
        dataWords = data.words
        dataSigBytes = data.sigBytes
        blockSize = self.blockSize
        blockSizeBytes = blockSize * 4

        nBlocksReady = dataSigBytes // blockSizeBytes
        if doFlush:
            remainder = 1 if dataSigBytes % blockSizeBytes else 0
            nBlocksReady += remainder
        else:
            nBlocksReady = max(nBlocksReady - self._minBufferSize, 0)

        nWordsReady = nBlocksReady * blockSize
        nBytesReady = min(nWordsReady * 4, dataSigBytes)

        processedWords = None
        if nWordsReady:
            while len(dataWords) < nWordsReady:
                dataWords.append(0)
            for offset in range(0, nWordsReady, blockSize):
                self._doProcessBlock(dataWords, offset)
            processedWords = dataWords[:nWordsReady]
            del dataWords[:nWordsReady]
            data.sigBytes -= nBytesReady

        return WordArray.create(processedWords or [], nBytesReady)

    def clone(self):
        clone = super().clone()
        clone._data = self._data.clone()
        return clone


class Hasher(BufferedBlockAlgorithm):
    """
    Base class for cryptographic hash algorithms.

    Provides the public API:
      - update(messageUpdate): feed more data.
      - finalize(messageUpdate): finish and return the hash digest.
      - reset(): restart.

    Subclasses must implement:
      - _doReset(): initialise hash state.
      - _doProcessBlock(M, offset): process one block.
      - _doFinalize(): pad, finalise, return digest.

    Helper class methods:
      - _createHelper(cls): returns a one-shot function(message, cfg).
      - _createHmacHelper(cls): returns an HMAC function(message, key).
    """

    blockSize = 512 // 32

    def init(self, cfg=None):
        self.cfg = cfg
        self.reset()

    def reset(self):
        BufferedBlockAlgorithm.reset(self)
        self._doReset()

    def update(self, messageUpdate):
        """Feed data into the progressive hash computation."""
        self._append(messageUpdate)
        self._process()
        return self

    def finalize(self, messageUpdate=None):
        """Finalise the hash, optionally processing a last piece of data."""
        if messageUpdate:
            self._append(messageUpdate)
        return self._doFinalize()

    @staticmethod
    def _createHelper(hasher_cls):
        """Return a convenience function: hash(message, cfg) -> WordArray."""
        def helper(message, cfg=None):
            return hasher_cls.create(cfg).finalize(message)
        return helper

    @staticmethod
    def _createHmacHelper(hasher_cls):
        """Return a convenience function: HMAC(message, key) -> WordArray."""
        def helper(message, key):
            from Crypto.hmac import HMAC
            return HMAC.create(hasher_cls, key).finalize(message)
        return helper


class Hex:
    """Hexadecimal encoder/decoder."""

    @staticmethod
    def stringify(wordArray):
        """Convert a WordArray to a lowercase hex string."""
        if not hasattr(wordArray, 'words'):
            raise TypeError(f'Hex.stringify requires a WordArray, got {type(wordArray).__name__}')
        words = wordArray.words
        sigBytes = wordArray.sigBytes
        hexChars = []
        for i in range(sigBytes):
            idx = i >> 2
            if idx >= len(words):
                bite = 0
            else:
                bite = (words[idx] >> (24 - (i % 4) * 8)) & 0xFF
            hexChars.append('{:02x}'.format(bite))
        return ''.join(hexChars)

    @staticmethod
    def parse(hexStr):
        """Parse a hex string into a WordArray."""
        if not isinstance(hexStr, str):
            raise TypeError(f'Hex.parse requires a string, got {type(hexStr).__name__}')
        words = []
        hexStrLength = len(hexStr)
        for i in range(0, hexStrLength, 2):
            idx = i >> 3
            while len(words) <= idx:
                words.append(0)
            words[idx] = _32(words[idx] | (int(hexStr[i:i+2], 16) << (24 - (i % 8) * 4)))
        return WordArray.create(words, hexStrLength // 2)


class Latin1:
    """ISO-8859-1 / Latin-1 encoder/decoder."""

    @staticmethod
    def stringify(wordArray):
        """Convert a WordArray to a Latin-1 string."""
        if not hasattr(wordArray, 'words'):
            raise TypeError(f'Latin1.stringify requires a WordArray, got {type(wordArray).__name__}')
        words = wordArray.words
        sigBytes = wordArray.sigBytes
        latin1Chars = []
        for i in range(sigBytes):
            bite = (words[i >> 2] >> (24 - (i % 4) * 8)) & 0xFF
            latin1Chars.append(chr(bite))
        return ''.join(latin1Chars)

    @staticmethod
    def parse(latin1Str):
        """Encode a Latin-1 string into a WordArray."""
        if not isinstance(latin1Str, str):
            raise TypeError(f'Latin1.parse requires a string, got {type(latin1Str).__name__}')
        words = []
        for i, char in enumerate(latin1Str):
            idx = i >> 2
            while len(words) <= idx:
                words.append(0)
            words[idx] = _32(words[idx] | ((ord(char) & 0xFF) << (24 - (i % 4) * 8)))
        return WordArray.create(words, len(latin1Str))


class Utf8:
    """UTF-8 encoder/decoder."""

    @staticmethod
    def stringify(wordArray):
        """Convert a WordArray to a UTF-8 string."""
        if not hasattr(wordArray, 'words'):
            raise TypeError(f'Utf8.stringify requires a WordArray, got {type(wordArray).__name__}')
        byte_array = []
        words = wordArray.words
        for i in range(wordArray.sigBytes):
            byte_array.append((words[i >> 2] >> (24 - (i % 4) * 8)) & 0xFF)
        try:
            return bytes(byte_array).decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError('Malformed UTF-8 data')

    @staticmethod
    def parse(utf8Str):
        """Encode a UTF-8 string into a WordArray."""
        if not isinstance(utf8Str, str):
            raise TypeError(f'Utf8.parse requires a string, got {type(utf8Str).__name__}')
        byte_array = utf8Str.encode('utf-8')
        words = []
        for i, b in enumerate(byte_array):
            idx = i >> 2
            while len(words) <= idx:
                words.append(0)
            words[idx] = _32(words[idx] | (b << (24 - (i % 4) * 8)))
        return WordArray.create(words, len(byte_array))
