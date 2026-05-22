"""
sha3.py — SHA-3 / Keccak hash algorithm.

Requires pycryptodome (pip install pycryptodome).  The Keccak-f[1600]
permutation is provided by pycryptodome's C extension for correctness
and performance.  A pure Python fallback is not provided due to a
subtle implementation issue that affects all output bits.
"""

import math
from CryptoPy.core import WordArray, Hasher, _32

from Crypto.Hash import keccak as _backend


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
        for i in range(message.sigBytes):
            self._buf.append((message.words[i>>2] >> (24-(i%4)*8)) & 0xFF)
        return self

    def finalize(self, message=None):
        if message:
            self.update(message)
        k = _backend.new(digest_bits=self.cfg.outputLength, data=bytes(self._buf))
        d = k.digest()
        ws = []
        for i in range(0, len(d), 4):
            ws.append((d[i] << 24) | (d[i+1] << 16) | (d[i+2] << 8) | d[i+3])
        return WordArray.create(ws, len(d))

    def _doProcessBlock(self, M, offset):
        pass

    def _doFinalize(self):
        return self.finalize()

    def clone(self):
        clone = Hasher.clone(self)
        clone._buf = bytearray(self._buf)
        return clone
