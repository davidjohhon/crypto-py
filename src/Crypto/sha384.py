"""
sha384.py — SHA-384 hash algorithm (FIPS 180-4).

SHA-384 is identical to SHA-512 except for the initial hash values
and the output is truncated to 384 bits (six 64-bit words, i.e.
twelve 32-bit words, dropping the last two 64-bit words / four 32-bit
words from the SHA-512 state).
"""

from Crypto.x64core import X64Word, X64WordArray
from Crypto.sha512 import SHA512


class SHA384(SHA512):
    """
    SHA-384 hash algorithm.

    Digest size: 384 bits (6 X64Words → 12 × 32-bit words on output).
    Block size: 1024 bits (inherits from SHA512).
    Uses different initial values than SHA-512.
    """

    def _doReset(self):
        """
        Initialise with SHA-384-specific IV values.

        These are the fractional parts of the square roots of the
        9th through 16th primes (64-bit values, as specified in
        FIPS 180-4).
        """
        self._hash = X64WordArray.create([
            X64Word.create(0xcbbb9d5d, 0xc1059ed8), X64Word.create(0x629a292a, 0x367cd507),
            X64Word.create(0x9159015a, 0x3070dd17), X64Word.create(0x152fecd8, 0xf70e5939),
            X64Word.create(0x67332667, 0xffc00b31), X64Word.create(0x8eb44a87, 0x68581511),
            X64Word.create(0xdb0c2e0d, 0x64f98fa7), X64Word.create(0x47b5481d, 0xbefa4fa4)
        ])

    def _doFinalize(self):
        """
        Compute SHA-512 finalisation, then truncate to 384 bits.

        The last two 64-bit words (16 bytes) are dropped by
        subtracting from sigBytes.
        """
        hash_result = SHA512._doFinalize(self)
        hash_result.sigBytes -= 16
        return hash_result
