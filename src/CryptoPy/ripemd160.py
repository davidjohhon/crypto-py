"""
ripemd160.py — RIPEMD-160 hash algorithm.

RIPEMD-160 processes 512-bit blocks and produces a 160-bit digest
(five 32-bit words).  It uses two parallel lines (left and right)
with different message orderings, shift amounts, and nonlinear
functions, combined at the end of each block.

The five nonlinear functions across the 5 rounds of 16 steps each:
  f1: X ^ Y ^ Z
  f2: (X & Y) | (~X & Z)
  f3: (X | ~Y) ^ Z
  f4: (X & Z) | (Y & ~Z)
  f5: X ^ (Y | ~Z)

Constants h_l (left) and h_r (right) are derived from the fractional
parts of sqrt(2), sqrt(3), sqrt(5), sqrt(7), sqrt(11).
"""

import math
from CryptoPy.core import WordArray, Hasher, _32


_zl = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
       7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
       3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
       1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
       4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]

_zr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
       6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
       15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
       8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
       12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]

_sl = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
       7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
       11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
       11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
       9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]

_sr = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
       9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
       9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
       15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
       8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]

_hl = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_hr = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def f1(x, y, z):
    """Round 1: XOR."""
    return x ^ y ^ z


def f2(x, y, z):
    """Round 2: (x & y) | (~x & z)."""
    return (x & y) | ((~x & 0xFFFFFFFF) & z)


def f3(x, y, z):
    """Round 3: (x | ~y) ^ z."""
    return (x | (~y & 0xFFFFFFFF)) ^ z


def f4(x, y, z):
    """Round 4: (x & z) | (y & ~z)."""
    return (x & z) | (y & (~z & 0xFFFFFFFF))


def f5(x, y, z):
    """Round 5: x ^ (y | ~z)."""
    return x ^ (y | (~z & 0xFFFFFFFF))


def rotl(x, n):
    """Rotate 32-bit x left by n bits."""
    return _32((x << n) | (x >> (32 - n)))


def swapEndian(word):
    return (
        (((word << 8) | (word >> 24)) & 0x00FF00FF) |
        (((word << 24) | (word >> 8)) & 0xFF00FF00)
    )


class RIPEMD160(Hasher):
    """
    RIPEMD-160 hash algorithm.

    Digest size: 160 bits (five 32-bit words).
    Block size: 512 bits (16 words).
    Uses dual parallel compression lines (left and right).
    """

    blockSize = 512 // 32

    def _doReset(self):
        """Initialise RIPEMD-160 state with standard IV values."""
        self._hash = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0])

    def _doProcessBlock(self, M, offset):
        """
        Process one 512-bit (16-word) block through 80 steps.

        RIPEMD-160 uses little-endian word ordering internally.
        Words are byte-swapped before processing.

        Two parallel lines (left and right) each run 80 steps with
        different message orderings (_zl vs _zr), shift amounts
        (_sl vs _sr), functions (f1-f5), and constants (_hl vs _hr).

        After 80 steps, the left and right results are combined with
        the previous hash state in a specific cross-mixing pattern.
        """
        for i in range(16):
            offset_i = offset + i
            M_offset_i = M[offset_i]
            M[offset_i] = swapEndian(M_offset_i)

        H = self._hash.words

        ar = al = H[0]
        br = bl = H[1]
        cr = cl = H[2]
        dr = dl = H[3]
        er = el = H[4]

        for i in range(80):
            # Left line
            t = _32(al + M[offset + _zl[i]])
            if i < 16:
                t = _32(t + f1(bl, cl, dl) + _hl[0])
            elif i < 32:
                t = _32(t + f2(bl, cl, dl) + _hl[1])
            elif i < 48:
                t = _32(t + f3(bl, cl, dl) + _hl[2])
            elif i < 64:
                t = _32(t + f4(bl, cl, dl) + _hl[3])
            else:
                t = _32(t + f5(bl, cl, dl) + _hl[4])
            t = rotl(t, _sl[i])
            t = _32(t + el)
            al = el
            el = dl
            dl = rotl(cl, 10)
            cl = bl
            bl = t

            # Right line
            t = _32(ar + M[offset + _zr[i]])
            if i < 16:
                t = _32(t + f5(br, cr, dr) + _hr[0])
            elif i < 32:
                t = _32(t + f4(br, cr, dr) + _hr[1])
            elif i < 48:
                t = _32(t + f3(br, cr, dr) + _hr[2])
            elif i < 64:
                t = _32(t + f2(br, cr, dr) + _hr[3])
            else:
                t = _32(t + f1(br, cr, dr) + _hr[4])
            t = rotl(t, _sr[i])
            t = _32(t + er)
            ar = er
            er = dr
            dr = rotl(cr, 10)
            cr = br
            br = t

        # Combine left and right results with previous hash state
        t = _32(H[1] + cl + dr)
        H[1] = _32(H[2] + dl + er)
        H[2] = _32(H[3] + el + ar)
        H[3] = _32(H[4] + al + br)
        H[4] = _32(H[0] + bl + cr)
        H[0] = t

    def _doFinalize(self):
        """
        Finalise RIPEMD-160 with Merkle-Damgard padding.

        Padding: append 0x80, then zeros, then 64-bit little-endian
        bit length.  Unlike SHA-1, RIPEMD-160 uses little-endian for
        both word storage and length encoding.

        The final hash words are byte-swapped back to big-endian.
        """
        data = self._data
        dataWords = data.words
        nBitsTotal = self._nDataBytes * 8
        nBitsLeft = data.sigBytes * 8

        while len(dataWords) <= (nBitsLeft >> 5):
            dataWords.append(0)
        dataWords[nBitsLeft >> 5] = _32(dataWords[nBitsLeft >> 5] | (0x80 << (24 - nBitsLeft % 32)))

        idx14 = (((nBitsLeft + 64) >> 9) << 4) + 14
        idx15 = idx14 + 1
        while len(dataWords) <= idx15:
            dataWords.append(0)

        dataWords[idx14] = swapEndian(nBitsTotal)
        data.sigBytes = (len(dataWords) + 1) * 4

        self._process()

        hash_result = self._hash
        H = hash_result.words
        for i in range(5):
            H[i] = swapEndian(H[i])

        return hash_result

    def clone(self):
        clone = Hasher.clone(self)
        clone._hash = self._hash.clone()
        return clone
