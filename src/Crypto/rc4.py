"""
rc4.py — RC4 and RC4Drop stream ciphers.

RC4 (Rivest Cipher 4) generates a keystream using a permutation
of all 256 possible bytes.  The Key Scheduling Algorithm (KSA)
initialises the permutation from the key, and the Pseudo-Random
Generation Algorithm (PRGA) produces the keystream bytes.

RC4Drop is a variant that discards the first N bytes of the
keystream to mitigate known biases in the initial output.
"""

from Crypto.cipher_core import StreamCipher, _32, _merge_cfg


def generateKeystreamWord(self):
    """
    PRGA: generate one 32-bit keystream word (4 bytes).

    For each byte:
      i = (i + 1) % 256
      j = (j + S[i]) % 256
      swap S[i], S[j]
      K = S[(S[i] + S[j]) % 256]
    """
    S = self._S
    i = self._i
    j = self._j

    keystreamWord = 0
    for n in range(4):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        t = S[i]
        S[i] = S[j]
        S[j] = t
        keystreamWord |= S[(S[i] + S[j]) % 256] << (24 - n * 8)

    self._i = i
    self._j = j
    return _32(keystreamWord)


class RC4(StreamCipher):
    """
    RC4 stream cipher.

    Key size: up to 256 bytes (default 32 bytes = 256 bits).
    IV size: 0 (no IV support).
    Block size: 1 word (operates byte-by-byte internally).
    """

    keySize = 256 // 32
    ivSize = 0

    def _doReset(self):
        """
        KSA: Key Scheduling Algorithm.

        Initialise S = [0, 1, 2, ..., 255].
        Mix S using the key bytes:
          j = (j + S[i] + key[i % keyLength]) % 256
          swap S[i], S[j]
        """
        key = self._key
        keyWords = key.words
        keySigBytes = key.sigBytes

        S = self._S = list(range(256))

        j = 0
        for i in range(256):
            keyByteIndex = i % keySigBytes
            keyByte = (keyWords[keyByteIndex >> 2] >> (24 - (keyByteIndex % 4) * 8)) & 0xFF
            j = (j + S[i] + keyByte) % 256
            t = S[i]
            S[i] = S[j]
            S[j] = t

        self._i = 0
        self._j = 0

    def _doProcessBlock(self, M, offset):
        """
        Encrypt/decrypt one word by XORing with a keystream word.

        Since RC4 is a stream cipher, encryption and decryption
        are identical (XOR-based).
        """
        M[offset] = _32(M[offset] ^ generateKeystreamWord(self))


class RC4Drop(RC4):
    """
    RC4Drop stream cipher — RC4 with initial keystream dropping.

    The first `drop` bytes (default 768 = 192 words) of the keystream
    are discarded to reduce statistical biases.

    Configuration:
      - drop: number of initial keystream bytes to skip (default 192 words).
    """

    def init(self, xformMode, key, cfg=None):
        default_cfg = type('cfg', (), {'drop': 192})()
        merged = _merge_cfg(default_cfg, cfg)
        super().init(xformMode, key, merged)

    def _doReset(self):
        """
        Run KSA, then discard the first `drop` keystream words.
        """
        RC4._doReset(self)
        for _ in range(self.cfg.drop):
            generateKeystreamWord(self)
