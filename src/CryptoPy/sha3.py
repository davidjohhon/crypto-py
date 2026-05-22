"""
sha3.py — SHA-3 / Keccak hash algorithm.

Uses pycryptodome if available; otherwise falls back to a bundled
pure-Python implementation based on the Keccak reference code.
"""

import math
from CryptoPy.core import WordArray, Hasher, _32


try:
    from Crypto.Hash import keccak as _backend
except ImportError:
    _backend = None


RHO = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
PI = [0, 16, 7, 23, 14, 10, 1, 17, 8, 24, 20, 11, 2, 18, 9, 5, 21, 12, 3, 19, 15, 6, 22, 13, 4]
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]


def _rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f_pure(a):
    for r in range(24):
        c0 = a[0] ^ a[5]  ^ a[10] ^ a[15] ^ a[20]
        c1 = a[1] ^ a[6]  ^ a[11] ^ a[16] ^ a[21]
        c2 = a[2] ^ a[7]  ^ a[12] ^ a[17] ^ a[22]
        c3 = a[3] ^ a[8]  ^ a[13] ^ a[18] ^ a[23]
        c4 = a[4] ^ a[9]  ^ a[14] ^ a[19] ^ a[24]
        d0 = c4 ^ _rotl64(c1, 1)
        d1 = c0 ^ _rotl64(c2, 1)
        d2 = c1 ^ _rotl64(c3, 1)
        d3 = c2 ^ _rotl64(c4, 1)
        d4 = c3 ^ _rotl64(c0, 1)
        for y in range(5):
            a[0+5*y] ^= d0; a[1+5*y] ^= d1; a[2+5*y] ^= d2; a[3+5*y] ^= d3; a[4+5*y] ^= d4
        B = [0] * 25
        for i in range(25):
            B[PI[i]] = _rotl64(a[i], RHO[i])
        for x in range(5):
            for y in range(5):
                i = x + 5*y
                a[i] = B[i] ^ ((~B[((x+1)%5)+5*y]) & B[((x+2)%5)+5*y])
        a[0] ^= RC[r]


def _swap32(w):
    return (
        ((_32(w << 8) | (w >> 24)) & 0x00FF00FF) |
        ((_32(w << 24) | (w >> 8)) & 0xFF00FF00)
    )


def _words_to_bytes(words, sig_bytes):
    raw = bytearray()
    for i in range(sig_bytes):
        raw.append((words[i >> 2] >> (24 - (i % 4) * 8)) & 0xFF)
    return raw


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
        self._buf = bytearray()
        self.blockSize = (1600 - 2 * self.cfg.outputLength) // 32

    def update(self, message):
        if isinstance(message, str):
            from CryptoPy.core import Utf8
            message = Utf8.parse(message)
        self._buf.extend(_words_to_bytes(message.words, message.sigBytes))
        return self

    def finalize(self, message=None):
        if message:
            self.update(message)
        data = bytes(self._buf)

        if _backend is not None:
            k = _backend.new(digest_bits=self.cfg.outputLength, data=data)
            digest = k.digest()
        else:
            rate_bytes = self.blockSize * 4
            data += b'\x01'
            while len(data) % rate_bytes != (rate_bytes - 1):
                data += b'\x00'
            data += b'\x80'
            state = [0] * 25
            for block_start in range(0, len(data), rate_bytes):
                block = data[block_start:block_start + rate_bytes]
                for i in range(rate_bytes // 8):
                    v = int.from_bytes(block[i*8:(i+1)*8], 'little')
                    state[i] ^= v
                _keccak_f_pure(state)
            out_bytes = self.cfg.outputLength // 8
            digest = bytearray()
            for i in range(out_bytes // 8):
                digest.extend(state[i].to_bytes(8, 'little'))
            digest = bytes(digest[:out_bytes])

        ws = []
        for i in range(0, len(digest), 4):
            w = (digest[i] << 24) | (digest[i+1] << 16) | (digest[i+2] << 8) | digest[i+3]
            ws.append(w)
        return WordArray.create(ws, len(digest))

    def _doProcessBlock(self, M, offset):
        pass

    def _doFinalize(self):
        return self.finalize()

    def clone(self):
        clone = Hasher.clone(self)
        clone._buf = bytearray(self._buf)
        return clone
