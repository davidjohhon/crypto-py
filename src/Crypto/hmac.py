"""
hmac.py — HMAC (Keyed-Hash Message Authentication Code, RFC 2104).

HMAC computes:
  HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))

Where:
  - K' is the key, zero-padded or hashed to the block size.
  - ipad = 0x363636... (block size bytes).
  - opad = 0x5C5C5C... (block size bytes).
"""

from Crypto.core import Base, Utf8


class HMAC(Base):
    """
    HMAC implementation using any Crypto hasher.

    Usage:
      hmac = HMAC.create(hasher_cls, key)
      hmac.update(message)
      result = hmac.finalize()
    """

    def init(self, hasher_cls, key):
        """Initialise HMAC with a hash algorithm class and key."""
        hasher = self._hasher = hasher_cls.create()
        if isinstance(key, str):
            key = Utf8.parse(key)

        hasherBlockSize = hasher.blockSize
        hasherBlockSizeBytes = hasherBlockSize * 4

        if key.sigBytes > hasherBlockSizeBytes:
            key = hasher.finalize(key)

        key.clamp()

        oKey = key.clone()
        iKey = key.clone()

        oKeyWords = oKey.words
        iKeyWords = iKey.words

        for i in range(hasherBlockSize):
            if i < len(oKeyWords):
                oKeyWords[i] ^= 0x5C5C5C5C
                iKeyWords[i] ^= 0x36363636
            else:
                while len(oKeyWords) <= i:
                    oKeyWords.append(0x5C5C5C5C)
                while len(iKeyWords) <= i:
                    iKeyWords.append(0x36363636)
                oKeyWords[i] = 0x5C5C5C5C
                iKeyWords[i] = 0x36363636

        oKey.sigBytes = hasherBlockSizeBytes
        iKey.sigBytes = hasherBlockSizeBytes

        self._oKey = oKey
        self._iKey = iKey

        self.reset()

    def reset(self):
        """Reset the HMAC state: re-initialise inner hash with iKey."""
        hasher = self._hasher
        hasher.reset()
        hasher.update(self._iKey)

    def update(self, messageUpdate):
        """Feed more data into the inner hash."""
        self._hasher.update(messageUpdate)
        return self

    def finalize(self, messageUpdate=None):
        """
        Compute and return the HMAC digest.

        1. Finalise the inner hash (iKey || message).
        2. Reset the hasher and compute outer hash (oKey || inner_digest).
        """
        hasher = self._hasher
        innerHash = hasher.finalize(messageUpdate)
        hasher.reset()
        hmac = hasher.finalize(self._oKey.clone().concat(innerHash))
        return hmac
