"""
pbkdf2.py — PBKDF2 key derivation function (RFC 2898).

PBKDF2 applies a pseudorandom function (HMAC by default) repeatedly
to derive key material from a password and salt.

The algorithm:
  For each block index (starting from 1):
    U_1 = PRF(password, salt || INT_32_BE(block_index))
    U_2 = PRF(password, U_1)
    ...
    U_c = PRF(password, U_{c-1})
    block = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
    derivedKey += block
"""

from Crypto.core import WordArray, Base
from Crypto.sha256 import SHA256
from Crypto.hmac import HMAC


class PBKDF2(Base):
    """
    PBKDF2 key derivation function.

    Configuration:
      - keySize: desired key size in 32-bit words (default 4 = 128 bits).
      - hasher: hash algorithm for HMAC (default SHA256).
      - iterations: iteration count (default 1).
    """

    def init(self, cfg=None):
        self.cfg = type('cfg', (), {'keySize': 128 // 32, 'hasher': SHA256, 'iterations': 250000})()
        if cfg:
            for k, v in cfg.items():
                setattr(self.cfg, k, v)

    def compute(self, password, salt):
        """
        Derive key material from password and salt.

        Returns a WordArray of keySize * 4 bytes.
        """
        cfg = self.cfg
        hmac = HMAC.create(cfg.hasher, password)
        derivedKey = WordArray.create()
        blockIndex = WordArray.create([0x00000001])

        while len(derivedKey.words) < cfg.keySize:
            block = hmac.update(salt).finalize(blockIndex)
            hmac.reset()

            blockWords = block.words[:]
            blockWordsLength = len(blockWords)

            intermediate = block
            for i in range(1, cfg.iterations):
                intermediate = hmac.finalize(intermediate)
                hmac.reset()
                intermediateWords = intermediate.words
                for j in range(blockWordsLength):
                    blockWords[j] = (blockWords[j] ^ intermediateWords[j]) & 0xFFFFFFFF

            derivedKey.concat(WordArray.create(blockWords, block.sigBytes))
            blockIndex.words[0] = (blockIndex.words[0] + 1) & 0xFFFFFFFF

        derivedKey.sigBytes = cfg.keySize * 4
        return derivedKey
