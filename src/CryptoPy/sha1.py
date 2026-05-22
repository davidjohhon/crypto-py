"""
sha1.py — SHA-1 hash algorithm implementation (FIPS 180-4).

SHA-1 processes 512-bit blocks and produces a 160-bit digest
(five 32-bit words).  Four rounds with different nonlinear functions:
  - Round 1 (0-19):  f  = (B & C) | (~B & D)        + K=0x5A827999
  - Round 2 (20-39): f  = B ^ C ^ D                  + K=0x6ED9EBA1
  - Round 3 (40-59): f  = (B & C) | (B & D) | (C & D) + K=-0x70E44324
  - Round 4 (60-79): f  = B ^ C ^ D                  + K=-0x359D3E2A

The message schedule W[0..79] expands the 16-word block to 80 words.
"""

import math
from CryptoPy.core import WordArray, Hasher, _32


class SHA1(Hasher):
    """
    SHA-1 hash algorithm.

    Digest size: 160 bits (5 words).
    Block size: 512 bits (16 words).
    """

    blockSize = 512 // 32

    def _doReset(self):
        """Initialise SHA-1 state with standard IV values."""
        self._hash = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0])
        self.W = [0] * 80

    def _doProcessBlock(self, M, offset):
        """
        Process one 512-bit (16-word) block through 80 rounds.

        W[i] for i < 16 is copied directly from the block.
        W[i] for i >= 16 is the XOR of W[i-3], W[i-8], W[i-14], W[i-16],
        rotated left by 1.

        The state variables a-e are rotated each round:
          a → b → c → d → e, with c rotated left by 30 bits.
        """
        H = self._hash.words
        a, b, c, d, e = H[0], H[1], H[2], H[3], H[4]
        W = self.W
        for i in range(80):
            if i < 16:
                W[i] = M[offset + i] | 0
            else:
                n = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]
                W[i] = _32((n << 1) | (n >> 31))
            t = _32(_32((a << 5) | (a >> 27)) + e + W[i])
            if i < 20:
                t = _32(t + ((b & c) | (~b & d)) + 0x5A827999)
            elif i < 40:
                t = _32(t + (b ^ c ^ d) + 0x6ED9EBA1)
            elif i < 60:
                t = _32(t + ((b & c) | (b & d) | (c & d)) - 0x70E44324)
            else:
                t = _32(t + (b ^ c ^ d) - 0x359D3E2A)
            e = d
            d = c
            c = _32((b << 30) | (b >> 2))
            b = a
            a = t
        H[0] = _32(H[0] + a)
        H[1] = _32(H[1] + b)
        H[2] = _32(H[2] + c)
        H[3] = _32(H[3] + d)
        H[4] = _32(H[4] + e)

    def _doFinalize(self):
        """
        Finalise SHA-1 with Merkle-Damgard padding.

        Padding: append 0x80, then zeros, then 64-bit big-endian bit length.
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

        dataWords[idx14] = nBitsTotal // 0x100000000
        dataWords[idx15] = nBitsTotal
        data.sigBytes = len(dataWords) * 4

        self._process()
        return self._hash

    def clone(self):
        clone = Hasher.clone(self)
        clone._hash = self._hash.clone()
        clone.W = list(self.W)
        return clone
