"""
sha256.py — SHA-256 hash algorithm implementation (FIPS 180-4).

SHA-256 processes 512-bit blocks and produces a 256-bit digest
(eight 32-bit words).  Uses 64 rounds with the message schedule
expanded from 16 to 64 words.

The initial hash values (H) are the fractional parts of the square
roots of the first 8 primes.  The round constants (K) are the
fractional parts of the cube roots of the first 64 primes.
"""

import math
from Crypto.core import WordArray, Hasher, _32


def isPrime(n):
    """Primality test for small n (used to generate SHA-256 constants)."""
    sqrtN = int(math.sqrt(n))
    for factor in range(2, sqrtN + 1):
        if not (n % factor):
            return False
    return True


def getFractionalBits(n):
    """
    Extract the fractional part of n as a 32-bit value.

    Used to generate SHA-256 initial hash values and round constants.
    """
    return int((n - int(n)) * 0x100000000) & 0xFFFFFFFF


_H = []
_K = []

n = 2
nPrime = 0
while nPrime < 64:
    if isPrime(n):
        if nPrime < 8:
            _H.append(getFractionalBits(n ** (1 / 2)))
        _K.append(getFractionalBits(n ** (1 / 3)))
        nPrime += 1
    n += 1


class SHA256(Hasher):
    """
    SHA-256 hash algorithm.

    Digest size: 256 bits (8 words).
    Block size: 512 bits (16 words).
    """

    blockSize = 512 // 32

    def _doReset(self):
        """Initialise SHA-256 state with the first 8 prime square roots."""
        self._hash = WordArray.create(_H[:])
        self.W = [0] * 64

    def _doProcessBlock(self, M, offset):
        """
        Process one 512-bit (16-word) block through 64 rounds.

        The message schedule W[0..63] is expanded from the 16-word block:
          - W[i] for i < 16: direct copy.
          - W[i] for i >= 16: sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16].

        Each round computes:
          sigma0: rotation by 2, 13, 22 bits (on 'a').
          sigma1: rotation by 6, 11, 25 bits (on 'e').
          ch: (e & f) ^ (~e & g)
          maj: (a & b) ^ (a & c) ^ (b & c)
        """
        H = self._hash.words
        a, b, c, d, e, f, g, h = H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]
        W = self.W
        for i in range(64):
            if i < 16:
                W[i] = M[offset + i] | 0
            else:
                gamma0x = W[i - 15]
                gamma0 = _32(((gamma0x << 25) | (gamma0x >> 7)) ^
                             ((gamma0x << 14) | (gamma0x >> 18)) ^
                             (gamma0x >> 3))
                gamma1x = W[i - 2]
                gamma1 = _32(((gamma1x << 15) | (gamma1x >> 17)) ^
                             ((gamma1x << 13) | (gamma1x >> 19)) ^
                             (gamma1x >> 10))
                W[i] = _32(gamma0 + W[i - 7] + gamma1 + W[i - 16])

            # Choice function: select f or g based on e
            ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
            # Majority function: majority of a, b, c
            maj = (a & b) ^ (a & c) ^ (b & c)

            sigma0 = _32(((a << 30) | (a >> 2)) ^ ((a << 19) | (a >> 13)) ^ ((a << 10) | (a >> 22)))
            sigma1 = _32(((e << 26) | (e >> 6)) ^ ((e << 21) | (e >> 11)) ^ ((e << 7) | (e >> 25)))

            t1 = _32(h + sigma1 + ch + _K[i] + W[i])
            t2 = _32(sigma0 + maj)

            h = g
            g = f
            f = e
            e = _32(d + t1)
            d = c
            c = b
            b = a
            a = _32(t1 + t2)

        H[0] = _32(H[0] + a)
        H[1] = _32(H[1] + b)
        H[2] = _32(H[2] + c)
        H[3] = _32(H[3] + d)
        H[4] = _32(H[4] + e)
        H[5] = _32(H[5] + f)
        H[6] = _32(H[6] + g)
        H[7] = _32(H[7] + h)

    def _doFinalize(self):
        """
        Finalise SHA-256 with Merkle-Damgard padding.

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
