"""
sha3.py — SHA-3 / Keccak hash algorithm (pure Python).
"""

import math
from CryptoPy.core import WordArray, Hasher, _32


RHO = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
RC24 = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]


def _swap32(w):
    return (
        ((_32(w << 8) | (w >> 24)) & 0x00FF00FF) |
        ((_32(w << 24) | (w >> 8)) & 0xFF00FF00)
    )


def _keccakf(st):
    for rnd in range(24):
        C = [st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20] for x in range(5)]
        D = [0] * 5
        for x in range(5):
            D[x] = C[(x+4)%5] ^ (((C[(x+1)%5] << 1) | (C[(x+1)%5] >> 63)) & 0xFFFFFFFFFFFFFFFF)
        for x in range(5):
            for y in range(5):
                st[x+5*y] ^= D[x]

        st_c = st[:]
        for x in range(5):
            for y in range(5):
                i = x + 5*y
                v = st_c[i]
                n = RHO[i]
                p = (y + ((2*x + 3*y) % 5) * 5) % 25
                st[p] = ((v << n) | (v >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

        st_c = st[:]
        for x in range(5):
            for y in range(5):
                i = x + 5*y
                st[i] = st_c[i] ^ ((~st_c[((x+1)%5)+5*y]) & st_c[((x+2)%5)+5*y])

        st[0] ^= RC24[rnd]


class SHA3(Hasher):
    blockSize = 512 // 32

    def init(self, cfg=None):
        if cfg is None:
            out_len = 512
        elif isinstance(cfg, dict):
            out_len = cfg.get('outputLength', 512)
        else:
            out_len = getattr(cfg, 'outputLength', 512)
        super().init(type('cfg', (), {'outputLength': out_len})())

    def _doReset(self):
        self._state = [0] * 25
        self.blockSize = (1600 - 2 * self.cfg.outputLength) // 32

    def _doProcessBlock(self, M, offset):
        n = self.blockSize // 2
        for i in range(n):
            w0 = M[offset + 2 * i]
            w1 = M[offset + 2 * i + 1]
            lo = (
                ((_32(w0 << 8) | (w0 >> 24)) & 0x00FF00FF) |
                ((_32(w0 << 24) | (w0 >> 8)) & 0xFF00FF00)
            )
            hi = (
                ((_32(w1 << 8) | (w1 >> 24)) & 0x00FF00FF) |
                ((_32(w1 << 24) | (w1 >> 8)) & 0xFF00FF00)
            )
            self._state[i] ^= (hi << 32) | lo
        _keccakf(self._state)

    def _doFinalize(self):
        data = self._data
        dataWords = data.words
        nBitsLeft = data.sigBytes * 8
        blockSizeBits = self.blockSize * 32

        while len(dataWords) <= (nBitsLeft >> 5):
            dataWords.append(0)
        dataWords[nBitsLeft >> 5] = _32(dataWords[nBitsLeft >> 5] | (0x1 << (24 - nBitsLeft % 32)))

        lastIdx = (int(math.ceil((nBitsLeft + 1) / blockSizeBits)) * blockSizeBits >> 5) - 1
        while len(dataWords) <= lastIdx:
            dataWords.append(0)
        dataWords[lastIdx] = _32(dataWords[lastIdx] | 0x80)
        data.sigBytes = len(dataWords) * 4

        self._process()

        out_bytes = self.cfg.outputLength // 8
        ws = []
        for i in range(25):
            if len(ws) * 4 >= out_bytes:
                break
            v = self._state[i]
            hi = _swap32(v >> 32)
            lo = _swap32(v & 0xFFFFFFFF)
            ws.append(lo)
            if len(ws) * 4 < out_bytes:
                ws.append(hi)
        return WordArray.create(ws, out_bytes)

    def clone(self):
        clone = Hasher.clone(self)
        clone._state = list(self._state)
        return clone
