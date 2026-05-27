"""
sm3.py — SM3 cryptographic hash algorithm (GM/T 0004-2012).

Output: 256 bits (32 bytes).
Block size: 512 bits (64 bytes).
"""

import math
from CryptoPy.core import WordArray, Hasher, _32

IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
      0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]


def FF0(x, y, z):
    return x ^ y ^ z


def FF1(x, y, z):
    return (x & y) | (x & z) | (y & z)


def GG0(x, y, z):
    return x ^ y ^ z


def GG1(x, y, z):
    return (x & y) | ((~x & 0xFFFFFFFF) & z)


def P0(x):
    return x ^ _32((x << 9) | (x >> 23)) ^ _32((x << 17) | (x >> 15))


def P1(x):
    return x ^ _32((x << 15) | (x >> 17)) ^ _32((x << 23) | (x >> 9))


class SM3(Hasher):
    blockSize = 512 // 32

    def _doReset(self):
        self._hash = WordArray.create(IV[:])

    def _doProcessBlock(self, M, offset):
        H = self._hash.words
        W = [0] * 68
        W2 = [0] * 64

        for i in range(16):
            W[i] = M[offset + i]

        for i in range(16, 68):
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ _32((W[i - 3] << 15) | (W[i - 3] >> 17))) ^ \
                   _32((W[i - 13] << 7) | (W[i - 13] >> 25)) ^ W[i - 6]

        for i in range(64):
            W2[i] = W[i] ^ W[i + 4]

        A, B, C, D = H[0], H[1], H[2], H[3]
        E, F, G, Hh = H[4], H[5], H[6], H[7]

        for j in range(16):
            SS1 = _32(_32((A << 12) | (A >> 20)) + E + _32((0x79CC4519 << (j % 32)) | (0x79CC4519 >> (32 - (j % 32)))))
            SS1 = _32((SS1 << 7) | (SS1 >> 25))
            SS2 = SS1 ^ _32((A << 12) | (A >> 20))
            TT1 = _32(FF0(A, B, C) + D + SS2 + W2[j])
            TT2 = _32(GG0(E, F, G) + Hh + SS1 + W[j])
            D = C
            C = _32((B << 9) | (B >> 23))
            B = A
            A = TT1
            Hh = G
            G = _32((F << 19) | (F >> 13))
            F = E
            E = P0(TT2)

        for j in range(16, 64):
            SS1 = _32(_32((A << 12) | (A >> 20)) + E + _32((0x7A879D8A << ((j) % 32)) | (0x7A879D8A >> (32 - ((j) % 32)))))
            SS1 = _32((SS1 << 7) | (SS1 >> 25))
            SS2 = SS1 ^ _32((A << 12) | (A >> 20))
            TT1 = _32(FF1(A, B, C) + D + SS2 + W2[j])
            TT2 = _32(GG1(E, F, G) + Hh + SS1 + W[j])
            D = C
            C = _32((B << 9) | (B >> 23))
            B = A
            A = TT1
            Hh = G
            G = _32((F << 19) | (F >> 13))
            F = E
            E = P0(TT2)

        H[0] = _32(H[0] ^ A)
        H[1] = _32(H[1] ^ B)
        H[2] = _32(H[2] ^ C)
        H[3] = _32(H[3] ^ D)
        H[4] = _32(H[4] ^ E)
        H[5] = _32(H[5] ^ F)
        H[6] = _32(H[6] ^ G)
        H[7] = _32(H[7] ^ Hh)

    def _doFinalize(self):
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
        dataWords[idx14] = nBitsTotal // 0x100000000
        dataWords[idx15] = nBitsTotal
        data.sigBytes = len(dataWords) * 4

        self._process()
        return self._hash

    def clone(self):
        clone = Hasher.clone(self)
        clone._hash = self._hash.clone()
        return clone
