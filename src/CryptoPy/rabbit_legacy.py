"""
rabbit_legacy.py — RabbitLegacy stream cipher.

Legacy variant that does NOT endian-swap the key bytes before
initialising the internal state.  Use Rabbit for new code.
"""

from CryptoPy.cipher_core import StreamCipher, _32, urs


class RabbitLegacy(StreamCipher):
    """
    Legacy Rabbit stream cipher.

    Identical to Rabbit except the key bytes are NOT endian-swapped
    before initializing the internal state.  This was an error in
    early implementations; use Rabbit (not RabbitLegacy) for new code.

    Key size: 128 bits (4 words).
    IV size: 64 bits (2 words), optional.
    """

    blockSize = 128 // 32
    ivSize = 64 // 32

    def _doReset(self):
        K = self._key.words[:]
        iv = getattr(self.cfg, 'iv', None)

        self._X = [
            K[0], (K[3] << 16) | urs(K[2], 16),
            K[1], (K[0] << 16) | urs(K[3], 16),
            K[2], (K[1] << 16) | urs(K[0], 16),
            K[3], (K[2] << 16) | urs(K[1], 16)
        ]

        self._C = [
            (K[2] << 16) | urs(K[2], 16), (K[0] & 0xFFFF0000) | (K[1] & 0x0000FFFF),
            (K[3] << 16) | urs(K[3], 16), (K[1] & 0xFFFF0000) | (K[2] & 0x0000FFFF),
            (K[0] << 16) | urs(K[0], 16), (K[2] & 0xFFFF0000) | (K[3] & 0x0000FFFF),
            (K[1] << 16) | urs(K[1], 16), (K[3] & 0xFFFF0000) | (K[0] & 0x0000FFFF)
        ]

        self._b = 0
        self._scratch_C = [0] * 8
        self._scratch_G = [0] * 8

        for _ in range(4):
            self._nextState()

        X = self._X
        C = self._C
        for i in range(8):
            C[i] = _32(C[i] ^ X[(i + 4) & 7])

        if iv:
            IV = iv.words
            IV_0 = IV[0]
            IV_1 = IV[1]

            i0 = swapEndian(IV_0)
            i2 = swapEndian(IV_1)
            i1 = urs(i0, 16) | (i2 & 0xFFFF0000)
            i3 = (i2 << 16) | (i0 & 0x0000FFFF)

            C[0] ^= i0
            C[1] ^= i1
            C[2] ^= i2
            C[3] ^= i3
            C[4] ^= i0
            C[5] ^= i1
            C[6] ^= i2
            C[7] ^= i3

            for _ in range(4):
                self._nextState()

    def _nextState(self):
        X = self._X
        C = self._C
        C_ = self._scratch_C
        G = self._scratch_G
        for i in range(8):
            C_[i] = C[i]

        C[0] = _32(C[0] + 0x4D34D34D + self._b)
        C[1] = _32(C[1] + 0xD34D34D3 + (1 if urs(C[0], 0) < urs(C_[0], 0) else 0))
        C[2] = _32(C[2] + 0x34D34D34 + (1 if urs(C[1], 0) < urs(C_[1], 0) else 0))
        C[3] = _32(C[3] + 0x4D34D34D + (1 if urs(C[2], 0) < urs(C_[2], 0) else 0))
        C[4] = _32(C[4] + 0xD34D34D3 + (1 if urs(C[3], 0) < urs(C_[3], 0) else 0))
        C[5] = _32(C[5] + 0x34D34D34 + (1 if urs(C[4], 0) < urs(C_[4], 0) else 0))
        C[6] = _32(C[6] + 0x4D34D34D + (1 if urs(C[5], 0) < urs(C_[5], 0) else 0))
        C[7] = _32(C[7] + 0xD34D34D3 + (1 if urs(C[6], 0) < urs(C_[6], 0) else 0))
        self._b = 1 if urs(C[7], 0) < urs(C_[7], 0) else 0

        for i in range(8):
            gx = _32(X[i] + C[i])
            ga = gx & 0xFFFF
            gb = urs(gx, 16)
            gh = ((((ga * ga) >> 17) + ga * gb) >> 15) + gb * gb
            gl = _32(((gx & 0xFFFF0000) * gx) + ((gx & 0x0000FFFF) * gx))
            G[i] = gh ^ gl

        X[0] = _32(G[0] + ((G[7] << 16) | urs(G[7], 16)) + ((G[6] << 16) | urs(G[6], 16)))
        X[1] = _32(G[1] + ((G[0] << 8) | urs(G[0], 24)) + G[7])
        X[2] = _32(G[2] + ((G[1] << 16) | urs(G[1], 16)) + ((G[0] << 16) | urs(G[0], 16)))
        X[3] = _32(G[3] + ((G[2] << 8) | urs(G[2], 24)) + G[1])
        X[4] = _32(G[4] + ((G[3] << 16) | urs(G[3], 16)) + ((G[2] << 16) | urs(G[2], 16)))
        X[5] = _32(G[5] + ((G[4] << 8) | urs(G[4], 24)) + G[3])
        X[6] = _32(G[6] + ((G[5] << 16) | urs(G[5], 16)) + ((G[4] << 16) | urs(G[4], 16)))
        X[7] = _32(G[7] + ((G[6] << 8) | urs(G[6], 24)) + G[5])

    def _doProcessBlock(self, M, offset):
        X = self._X
        self._nextState()

        S0 = X[0] ^ urs(X[5], 16) ^ _32(X[3] << 16)
        S1 = X[2] ^ urs(X[7], 16) ^ _32(X[5] << 16)
        S2 = X[4] ^ urs(X[1], 16) ^ _32(X[7] << 16)
        S3 = X[6] ^ urs(X[3], 16) ^ _32(X[1] << 16)

        S0 = swapEndian(S0)
        S1 = swapEndian(S1)
        S2 = swapEndian(S2)
        S3 = swapEndian(S3)

        M[offset] = _32(M[offset] ^ S0)
        M[offset + 1] = _32(M[offset + 1] ^ S1)
        M[offset + 2] = _32(M[offset + 2] ^ S2)
        M[offset + 3] = _32(M[offset + 3] ^ S3)


def swapEndian(word):
    return (
        (((word << 8) | (word >> 24)) & 0x00FF00FF) |
        (((word << 24) | (word >> 8)) & 0xFF00FF00)
    )
