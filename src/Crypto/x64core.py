"""
x64core.py — 64-bit word support for SHA-512 / SHA-384.

CryptoJS emulates 64-bit arithmetic by combining two 32-bit words
(high and low halves).  X64Word represents a single 64-bit value,
and X64WordArray is an array of such words stored big-endian within
each 32-bit half.

These types are used exclusively by SHA-512 and SHA-384.
"""

from Crypto.core import Base


class X64Word(Base):
    """
    Pseudo-64-bit word stored as two 32-bit halves.

    The actual 64-bit value is (high << 32) | low.
    Bitwise and arithmetic operations on 64-bit values in SHA-512
    are decomposed into operations on high and low separately, with
    carry propagation handled explicitly.
    """

    def init(self, high=0, low=0):
        self.high = high & 0xFFFFFFFF
        self.low = low & 0xFFFFFFFF

    def clone(self):
        return X64Word.create(self.high, self.low)


class X64WordArray(Base):
    """
    Array of X64Word elements.

    The sigBytes field counts bytes (each word holds 8 bytes).
    """

    def init(self, words=None, sigBytes=None):
        words = words or []
        self.words = words
        if sigBytes is not None:
            self.sigBytes = sigBytes
        else:
            self.sigBytes = len(words) * 8

    def toX32(self):
        """
        Convert to a 32-bit WordArray by interleaving high and low halves.

        Each X64Word produces two 32-bit words (high first, then low).
        This is used by SHA-512._doFinalize() to produce the final digest.
        """
        x32Words = []
        for w in self.words:
            x32Words.append(w.high)
            x32Words.append(w.low)
        from Crypto.core import WordArray
        return WordArray.create(x32Words, self.sigBytes)

    def clone(self):
        cloned_words = [w.clone() for w in self.words]
        return X64WordArray.create(cloned_words, self.sigBytes)
