"""
evpkdf.py — OpenSSL EVP_BytesToKey key derivation.

This is the key derivation function used by OpenSSL's enc utility.
It repeatedly hashes the password and salt (MD5 by default) with
the previous block concatenated, accumulating enough key material.

The algorithm:
  block = ''
  while len(derivedKey) < keySize:
    block = MD5(block + password + salt)
    for i in range(iterations - 1):
      block = MD5(block)
    derivedKey += block
"""

from CryptoPy.core import WordArray, Base
from CryptoPy.md5 import MD5


class EvpKDF(Base):
    """
    EVP_BytesToKey key derivation function.

    Configuration:
      - keySize: desired key size in 32-bit words (default 4 = 128 bits).
      - hasher: hash algorithm class (default MD5).
      - iterations: number of iterations (default 1).
    """

    def init(self, cfg=None):
        self.cfg = type('cfg', (), {'keySize': 128 // 32, 'hasher': MD5, 'iterations': 1})()
        if cfg:
            for k, v in cfg.items():
                setattr(self.cfg, k, v)

    def compute(self, password, salt):
        """
        Derive key material from password and salt.

        Returns a WordArray of keySize * 4 bytes.
        """
        cfg = self.cfg
        hasher = cfg.hasher.create()
        derivedKey = WordArray.create()
        block = None

        while len(derivedKey.words) < cfg.keySize:
            if block is not None:
                hasher.update(block)
            block = hasher.update(password).finalize(salt)
            hasher.reset()

            for i in range(1, cfg.iterations):
                block = hasher.finalize(block)
                hasher.reset()

            derivedKey.concat(block)

        derivedKey.sigBytes = cfg.keySize * 4
        return derivedKey
