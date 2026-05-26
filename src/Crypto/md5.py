"""
md5.py — MD5 hash algorithm implementation (RFC 1321).

MD5 processes 512-bit blocks in little-endian byte order internally,
unlike other hashes in this library which use big-endian.  The swapEndian
helper converts between the WordArray big-endian storage and MD5's native
little-endian representation.

The four rounds (FF, GG, HH, II) use different nonlinear functions:
  FF: F(X,Y,Z) = (X & Y) | (~X & Z)
  GG: G(X,Y,Z) = (X & Z) | (Y & ~Z)
  HH: H(X,Y,Z) = X ^ Y ^ Z
  II: I(X,Y,Z) = Y ^ (X | ~Z)
"""

import math
from Crypto.core import WordArray, Hasher, _32, urs


T = []
for i in range(64):
    T.append(int(abs(math.sin(i + 1)) * 0x100000000) & 0xFFFFFFFF)


def FF(a, b, c, d, x, s, t):
    """Round 1 function: F(X,Y,Z) = (X & Y) | (~X & Z)."""
    n = _32(a + ((b & c) | ((~b & 0xFFFFFFFF) & d)) + x + t)
    return _32(((n << s) | (n >> (32 - s))) + b)


def GG(a, b, c, d, x, s, t):
    """Round 2 function: G(X,Y,Z) = (X & Z) | (Y & ~Z)."""
    n = _32(a + ((b & d) | (c & ~d)) + x + t)
    return _32(((n << s) | (n >> (32 - s))) + b)


def HH(a, b, c, d, x, s, t):
    """Round 3 function: H(X,Y,Z) = X ^ Y ^ Z."""
    n = _32(a + (b ^ c ^ d) + x + t)
    return _32(((n << s) | (n >> (32 - s))) + b)


def II(a, b, c, d, x, s, t):
    """Round 4 function: I(X,Y,Z) = Y ^ (X | ~Z)."""
    n = _32(a + (c ^ (b | ~d)) + x + t)
    return _32(((n << s) | (n >> (32 - s))) + b)


def swapEndian(word):
    """Convert between big-endian and little-endian 32-bit word representation.

    MD5 operates in little-endian internally, but WordArray stores data
    big-endian.  This helper swaps byte order within a word.
    """
    return (
        (((word << 8) | (word >> 24)) & 0x00FF00FF) |
        (((word << 24) | (word >> 8)) & 0xFF00FF00)
    )


def _ensure_len(arr, n):
    """Grow list arr to at least index n (fill with zeros)."""
    while len(arr) <= n:
        arr.append(0)


class MD5(Hasher):
    """
    MD5 hash algorithm.

    Digest size: 128 bits (four 32-bit words).
    Block size: 512 bits (16 words).
    """

    blockSize = 512 // 32

    def _doReset(self):
        """Initialise MD5 state with standard IV values (little-endian)."""
        self._hash = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476])

    def _doProcessBlock(self, M, offset):
        """
        Process one 512-bit (16-word) block.

        MD5 processes data little-endian, so each word is byte-swapped
        before the compression function runs.
        """
        for i in range(16):
            offset_i = offset + i
            M_offset_i = M[offset_i]
            M[offset_i] = swapEndian(M_offset_i)

        H = self._hash.words
        M_offset = [M[offset + i] for i in range(16)]

        a, b, c, d = H[0], H[1], H[2], H[3]

        # Round 1: FF — 16 operations
        a = FF(a, b, c, d, M_offset[0],  7,  T[0])
        d = FF(d, a, b, c, M_offset[1],  12, T[1])
        c = FF(c, d, a, b, M_offset[2],  17, T[2])
        b = FF(b, c, d, a, M_offset[3],  22, T[3])
        a = FF(a, b, c, d, M_offset[4],  7,  T[4])
        d = FF(d, a, b, c, M_offset[5],  12, T[5])
        c = FF(c, d, a, b, M_offset[6],  17, T[6])
        b = FF(b, c, d, a, M_offset[7],  22, T[7])
        a = FF(a, b, c, d, M_offset[8],  7,  T[8])
        d = FF(d, a, b, c, M_offset[9],  12, T[9])
        c = FF(c, d, a, b, M_offset[10], 17, T[10])
        b = FF(b, c, d, a, M_offset[11], 22, T[11])
        a = FF(a, b, c, d, M_offset[12], 7,  T[12])
        d = FF(d, a, b, c, M_offset[13], 12, T[13])
        c = FF(c, d, a, b, M_offset[14], 17, T[14])
        b = FF(b, c, d, a, M_offset[15], 22, T[15])

        # Round 2: GG — 16 operations
        a = GG(a, b, c, d, M_offset[1],  5,  T[16])
        d = GG(d, a, b, c, M_offset[6],  9,  T[17])
        c = GG(c, d, a, b, M_offset[11], 14, T[18])
        b = GG(b, c, d, a, M_offset[0],  20, T[19])
        a = GG(a, b, c, d, M_offset[5],  5,  T[20])
        d = GG(d, a, b, c, M_offset[10], 9,  T[21])
        c = GG(c, d, a, b, M_offset[15], 14, T[22])
        b = GG(b, c, d, a, M_offset[4],  20, T[23])
        a = GG(a, b, c, d, M_offset[9],  5,  T[24])
        d = GG(d, a, b, c, M_offset[14], 9,  T[25])
        c = GG(c, d, a, b, M_offset[3],  14, T[26])
        b = GG(b, c, d, a, M_offset[8],  20, T[27])
        a = GG(a, b, c, d, M_offset[13], 5,  T[28])
        d = GG(d, a, b, c, M_offset[2],  9,  T[29])
        c = GG(c, d, a, b, M_offset[7],  14, T[30])
        b = GG(b, c, d, a, M_offset[12], 20, T[31])

        # Round 3: HH — 16 operations
        a = HH(a, b, c, d, M_offset[5],  4,  T[32])
        d = HH(d, a, b, c, M_offset[8],  11, T[33])
        c = HH(c, d, a, b, M_offset[11], 16, T[34])
        b = HH(b, c, d, a, M_offset[14], 23, T[35])
        a = HH(a, b, c, d, M_offset[1],  4,  T[36])
        d = HH(d, a, b, c, M_offset[4],  11, T[37])
        c = HH(c, d, a, b, M_offset[7],  16, T[38])
        b = HH(b, c, d, a, M_offset[10], 23, T[39])
        a = HH(a, b, c, d, M_offset[13], 4,  T[40])
        d = HH(d, a, b, c, M_offset[0],  11, T[41])
        c = HH(c, d, a, b, M_offset[3],  16, T[42])
        b = HH(b, c, d, a, M_offset[6],  23, T[43])
        a = HH(a, b, c, d, M_offset[9],  4,  T[44])
        d = HH(d, a, b, c, M_offset[12], 11, T[45])
        c = HH(c, d, a, b, M_offset[15], 16, T[46])
        b = HH(b, c, d, a, M_offset[2],  23, T[47])

        # Round 4: II — 16 operations
        a = II(a, b, c, d, M_offset[0],  6,  T[48])
        d = II(d, a, b, c, M_offset[7],  10, T[49])
        c = II(c, d, a, b, M_offset[14], 15, T[50])
        b = II(b, c, d, a, M_offset[5],  21, T[51])
        a = II(a, b, c, d, M_offset[12], 6,  T[52])
        d = II(d, a, b, c, M_offset[3],  10, T[53])
        c = II(c, d, a, b, M_offset[10], 15, T[54])
        b = II(b, c, d, a, M_offset[1],  21, T[55])
        a = II(a, b, c, d, M_offset[8],  6,  T[56])
        d = II(d, a, b, c, M_offset[15], 10, T[57])
        c = II(c, d, a, b, M_offset[6],  15, T[58])
        b = II(b, c, d, a, M_offset[13], 21, T[59])
        a = II(a, b, c, d, M_offset[4],  6,  T[60])
        d = II(d, a, b, c, M_offset[11], 10, T[61])
        c = II(c, d, a, b, M_offset[2],  15, T[62])
        b = II(b, c, d, a, M_offset[9],  21, T[63])

        # Add the result back to the hash state
        H[0] = _32(H[0] + a)
        H[1] = _32(H[1] + b)
        H[2] = _32(H[2] + c)
        H[3] = _32(H[3] + d)

    def _doFinalize(self):
        """
        Finalise MD5 hash with Merkle-Damgard padding.

        Padding: append 0x80, then zeros, then 64-bit bit-length
        (little-endian).  Unlike SHA-1/SHA-256, MD5 stores the
        length in little-endian and uses byte-swapped words for the
        final length fields.
        """
        data = self._data
        dataWords = data.words
        nBitsTotal = self._nDataBytes * 8
        nBitsLeft = data.sigBytes * 8

        _ensure_len(dataWords, nBitsLeft >> 5)
        dataWords[nBitsLeft >> 5] = _32(dataWords[nBitsLeft >> 5] | (0x80 << (24 - nBitsLeft % 32)))

        nBitsTotalH = nBitsTotal // 0x100000000
        nBitsTotalL = nBitsTotal & 0xFFFFFFFF

        idx14 = (((nBitsLeft + 64) >> 9) << 4) + 14
        idx15 = idx14 + 1
        _ensure_len(dataWords, idx15)
        dataWords[idx14] = swapEndian(nBitsTotalL)
        dataWords[idx15] = swapEndian(nBitsTotalH)
        data.sigBytes = (len(dataWords) + 1) * 4

        self._process()

        hash_result = self._hash
        H = hash_result.words
        for i in range(4):
            H[i] = swapEndian(H[i])

        return hash_result

    def clone(self):
        clone = Hasher.clone(self)
        clone._hash = self._hash.clone()
        return clone
