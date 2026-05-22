"""
sha3.py — SHA-3 / Keccak hash algorithm.

Uses pycryptodome as the Keccak backend for correct output values
matching CryptoJS (Keccak[c=2d], not FIPS-202 SHA-3).
"""

from CryptoPy.core import WordArray, Hasher
from Crypto.Hash import keccak as _keccak_backend


def _words_to_bytes(words, sig_bytes):
    raw = bytearray()
    for i in range(sig_bytes):
        raw.append((words[i >> 2] >> (24 - (i % 4) * 8)) & 0xFF)
    return bytes(raw)


class SHA3(Hasher):
    blockSize = 512 // 32

    def init(self, cfg=None):
        if cfg is None:
            out_len = 512
        elif isinstance(cfg, dict):
            out_len = cfg.get('outputLength', 512)
        else:
            out_len = getattr(cfg, 'outputLength', 512)
        cfg_obj = type('cfg', (), {'outputLength': out_len})()
        super().init(cfg_obj)

    def _doReset(self):
        self._buffer = bytearray()
        self.blockSize = (1600 - 2 * self.cfg.outputLength) // 32

    def update(self, message):
        if isinstance(message, str):
            from CryptoPy.core import Utf8
            message = Utf8.parse(message)
        raw = _words_to_bytes(message.words, message.sigBytes)
        self._buffer.extend(raw)
        return self

    def finalize(self, message=None):
        if message:
            self.update(message)
        k = _keccak_backend.new(digest_bits=self.cfg.outputLength, data=bytes(self._buffer))
        digest = k.digest()
        words = []
        for i in range(0, len(digest), 4):
            w = (digest[i] << 24) | (digest[i+1] << 16) | (digest[i+2] << 8) | digest[i+3]
            words.append(w)
        return WordArray.create(words, len(digest))

    def _doFinalize(self):
        return self.finalize()

    def clone(self):
        clone = Hasher.clone(self)
        clone._buffer = bytearray(self._buffer)
        return clone
