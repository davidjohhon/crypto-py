"""
sha224.py — SHA-224 hash algorithm (FIPS 180-4).

SHA-224 is identical to SHA-256 except for the initial hash values
and the output is truncated to 224 bits (7 words, dropping the
last 32-bit word).
"""

from CryptoPy.core import WordArray
from CryptoPy.sha256 import SHA256


class SHA224(SHA256):
    """
    SHA-224 hash algorithm.

    Digest size: 224 bits (7 words — last word of SHA-256 state is dropped).
    Block size: 512 bits (inherits from SHA256).
    Uses different initial values than SHA-256.
    """

    def _doReset(self):
        """
        Initialise with SHA-224-specific IV values.

        These are the fractional parts of the square roots of the
        9th through 16th primes (as specified in FIPS 180-4).
        """
        self._hash = WordArray.create([
            0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
            0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
        ])
        self.W = [0] * 64

    def _doFinalize(self):
        """
        Compute SHA-256 finalisation, then truncate to 224 bits.

        The last word (index 7) is simply excluded from sigBytes.
        """
        hash_result = SHA256._doFinalize(self)
        hash_result.sigBytes -= 4
        return hash_result
