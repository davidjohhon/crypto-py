"""
enc_base64.py — Base64 encoder/decoder (RFC 4648).

Encodes WordArray data into Base64 strings and vice versa.
The Base64 alphabet uses A-Z, a-z, 0-9, +, / and = for padding.
"""

from Crypto.core import WordArray


_map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='


def parseLoop(base64Str, base64StrLength, reverseMap):
    """
    Core Base64 parsing loop.

    Processes the base64 string 4 characters at a time (3 output bytes).
    The reverse map converts encoded characters back to their 6-bit values.
    """
    words = []
    nBytes = 0
    for i in range(base64StrLength):
        if i % 4:
            bits1 = reverseMap[ord(base64Str[i - 1])] << ((i % 4) * 2)
            bits2 = reverseMap[ord(base64Str[i])] >> (6 - (i % 4) * 2)
            bitsCombined = bits1 | bits2
            idx = nBytes >> 2
            while len(words) <= idx:
                words.append(0)
            words[idx] = (words[idx] & 0xFFFFFFFF) | (bitsCombined << (24 - (nBytes % 4) * 8))
            nBytes += 1
    return WordArray.create(words, nBytes)


class Base64:
    """
    Base64 encoder/decoder.

    stringify(wordArray) -> Base64 string.
    parse(base64Str) -> WordArray.
    """

    _map = _map
    _reverseMap = None

    @classmethod
    def stringify(cls, wordArray):
        """Convert a WordArray to a Base64-encoded string."""
        if not hasattr(wordArray, 'words'):
            raise TypeError(f'Base64.stringify requires a WordArray, got {type(wordArray).__name__}')
        words = wordArray.words
        sigBytes = wordArray.sigBytes
        mapStr = cls._map
        wordArray.clamp()
        base64Chars = []
        i = 0
        while i < sigBytes:
            byte1 = (words[i >> 2] >> (24 - (i % 4) * 8)) & 0xFF
            byte2 = (words[(i + 1) >> 2] >> (24 - ((i + 1) % 4) * 8)) & 0xFF if (i + 1) < sigBytes else 0
            byte3 = (words[(i + 2) >> 2] >> (24 - ((i + 2) % 4) * 8)) & 0xFF if (i + 2) < sigBytes else 0
            triplet = (byte1 << 16) | (byte2 << 8) | byte3
            for j in range(4):
                if i + j * 0.75 < sigBytes:
                    base64Chars.append(mapStr[(triplet >> (6 * (3 - j))) & 0x3F])
            i += 3
        paddingChar = mapStr[64]
        if paddingChar:
            while len(base64Chars) % 4:
                base64Chars.append(paddingChar)
        return ''.join(base64Chars)

    @classmethod
    def parse(cls, base64Str):
        """Parse a Base64 string into a WordArray."""
        if not isinstance(base64Str, str):
            raise TypeError('Base64.parse requires a string')
        base64StrLength = len(base64Str)
        mapStr = cls._map
        if cls._reverseMap is None:
            cls._reverseMap = [-1] * 256
            for j in range(len(mapStr)):
                cls._reverseMap[ord(mapStr[j])] = j
        reverseMap = cls._reverseMap
        paddingChar = mapStr[64]
        if paddingChar:
            paddingIndex = base64Str.find(paddingChar)
            if paddingIndex != -1:
                base64StrLength = paddingIndex
        for ch in base64Str[:base64StrLength]:
            if ord(ch) >= 256 or reverseMap[ord(ch)] == -1:
                raise ValueError(f'Invalid Base64 character: {ch!r}')
        return parseLoop(base64Str, base64StrLength, reverseMap)
