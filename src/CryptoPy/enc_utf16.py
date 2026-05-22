"""
enc_utf16.py — UTF-16 and UTF-16LE encoders/decoders.

Utf16 encodes in big-endian byte order (UTF-16 BE).
Utf16BE is an alias for Utf16.
Utf16LE encodes in little-endian byte order.

In CryptoJS convention, WordArray words are big-endian (most significant
byte first within each word).  When encoding UTF-16, each 16-bit code unit
occupies the upper or lower half of a 32-bit word depending on alignment.
"""

from CryptoPy.core import WordArray, _32


def swapEndian(word):
    """Swap byte order within a 32-bit word (endianness conversion)."""
    return ((word << 8) & 0xFF00FF00) | ((word >> 8) & 0x00FF00FF)


class Utf16:
    """UTF-16 Big-Endian encoder/decoder (default)."""

    @staticmethod
    def stringify(wordArray):
        """Convert a WordArray to a UTF-16 BE string."""
        words = wordArray.words
        sigBytes = wordArray.sigBytes
        chars = []
        for i in range(0, sigBytes, 2):
            codePoint = (words[i >> 2] >> (16 - (i % 4) * 8)) & 0xFFFF
            chars.append(chr(codePoint))
        return ''.join(chars)

    @staticmethod
    def parse(utf16Str):
        """Encode a string as UTF-16 BE into a WordArray."""
        words = []
        for i, char in enumerate(utf16Str):
            idx = i >> 1
            while len(words) <= idx:
                words.append(0)
            words[idx] = _32(words[idx] | (ord(char) << (16 - (i % 2) * 16)))
        return WordArray.create(words, len(utf16Str) * 2)


class Utf16BE(Utf16):
    """Alias for Utf16 (Big-Endian)."""
    pass


class Utf16LE:
    """UTF-16 Little-Endian encoder/decoder."""

    @staticmethod
    def stringify(wordArray):
        """Convert a WordArray to a UTF-16 LE string."""
        words = wordArray.words
        sigBytes = wordArray.sigBytes
        chars = []
        for i in range(0, sigBytes, 2):
            codePoint = swapEndian((words[i >> 2] >> (16 - (i % 4) * 8)) & 0xFFFF)
            chars.append(chr(codePoint))
        return ''.join(chars)

    @staticmethod
    def parse(utf16Str):
        """Encode a string as UTF-16 LE into a WordArray."""
        words = []
        for i, char in enumerate(utf16Str):
            idx = i >> 1
            while len(words) <= idx:
                words.append(0)
            val = swapEndian(ord(char) << (16 - (i % 2) * 16))
            words[idx] = _32(words[idx] | val)
        return WordArray.create(words, len(utf16Str) * 2)
