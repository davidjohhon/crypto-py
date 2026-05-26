"""
enc_base64url.py — Base64url (URL-safe) encoder/decoder (RFC 4648 §5).

Same as Base64 but uses '-' and '_' instead of '+' and '/'.
The urlSafe parameter controls which alphabet is used.
"""

from Crypto.core import WordArray


_map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
_safe_map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'


def parseLoop(base64Str, base64StrLength, reverseMap):
    """
    Core Base64url parsing loop.

    Identical logic to Base64's parseLoop; the difference is in
    the alphabet used.
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


class Base64url:
    """
    URL-safe Base64 encoder/decoder.

    When urlSafe=True (default), uses '-' and '_' (no padding).
    When urlSafe=False, uses '+' and '/' (standard Base64 with '=' padding).
    """

    _map = _map
    _safe_map = _safe_map
    _reverseMap = None

    @classmethod
    def stringify(cls, wordArray, urlSafe=True):
        """Convert a WordArray to a Base64url-encoded string."""
        if not hasattr(wordArray, 'words'):
            raise TypeError(f'Base64url.stringify requires a WordArray, got {type(wordArray).__name__}')
        words = wordArray.words
        sigBytes = wordArray.sigBytes
        mapStr = cls._safe_map if urlSafe else cls._map
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
        paddingChar = mapStr[64] if len(mapStr) > 64 else ''
        if paddingChar:
            while len(base64Chars) % 4:
                base64Chars.append(paddingChar)
        return ''.join(base64Chars)

    @classmethod
    def parse(cls, base64Str, urlSafe=True):
        """Parse a Base64url string into a WordArray."""
        base64StrLength = len(base64Str)
        mapStr = cls._safe_map if urlSafe else cls._map
        if cls._reverseMap is None:
            cls._reverseMap = [0] * 256
            for j in range(len(mapStr)):
                cls._reverseMap[ord(mapStr[j])] = j
        reverseMap = cls._reverseMap
        paddingChar = mapStr[64] if len(mapStr) > 64 else ''
        if paddingChar:
            paddingIndex = base64Str.find(paddingChar)
            if paddingIndex != -1:
                base64StrLength = paddingIndex
        return parseLoop(base64Str, base64StrLength, reverseMap)
