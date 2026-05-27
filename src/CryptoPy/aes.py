"""
aes.py — AES (Rijndael) block cipher implementation (FIPS 197).

AES processes 128-bit blocks with key sizes of 128, 192, or 256 bits.
The number of rounds depends on the key size:
  - 128-bit key: 10 rounds
  - 192-bit key: 12 rounds
  - 256-bit key: 14 rounds

This implementation uses precomputed lookup tables (SUB_MIX_0 through
SUB_MIX_3 for encryption, INV_SUB_MIX_0 through INV_SUB_MIX_3 for
decryption) that combine SubBytes + ShiftRows + MixColumns into a
single table lookup per byte (the "te0..te3" technique).

Key expansion generates keySchedule and invKeySchedule on demand.
The inverse key schedule uses InvMixColumns transform on round keys.
"""

from CryptoPy.cipher_core import BlockCipher, _32


SBOX = [0] * 256
INV_SBOX = [0] * 256
SUB_MIX_0 = [0] * 256
SUB_MIX_1 = [0] * 256
SUB_MIX_2 = [0] * 256
SUB_MIX_3 = [0] * 256
INV_SUB_MIX_0 = [0] * 256
INV_SUB_MIX_1 = [0] * 256
INV_SUB_MIX_2 = [0] * 256
INV_SUB_MIX_3 = [0] * 256

# Precompute the x2 (times 2) table in GF(2^8) for MixColumns
d = [0] * 256
for i in range(256):
    if i < 128:
        d[i] = i << 1
    else:
        d[i] = (i << 1) ^ 0x11B

# Generate the S-box, inverse S-box, and all lookup tables
x = 0
xi = 0
for i in range(256):
    sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4)
    sx = (sx >> 8) ^ (sx & 0xFF) ^ 0x63
    SBOX[x] = sx
    INV_SBOX[sx] = x

    x2 = d[x]
    x4 = d[x2]
    x8 = d[x4]

    t = (d[sx] * 0x101) ^ (sx * 0x1010100)
    SUB_MIX_0[x] = _32((t << 24) | (t >> 8))
    SUB_MIX_1[x] = _32((t << 16) | (t >> 16))
    SUB_MIX_2[x] = _32((t << 8) | (t >> 24))
    SUB_MIX_3[x] = _32(t)

    t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100)
    INV_SUB_MIX_0[sx] = _32((t << 24) | (t >> 8))
    INV_SUB_MIX_1[sx] = _32((t << 16) | (t >> 16))
    INV_SUB_MIX_2[sx] = _32((t << 8) | (t >> 24))
    INV_SUB_MIX_3[sx] = _32(t)

    if not x:
        x = xi = 1
    else:
        x = x2 ^ d[d[d[x8 ^ x2]]]
        xi ^= d[d[xi]]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


class AES(BlockCipher):
    """
    AES block cipher (Rijndael).

    Key size: 256 bits by default (configurable via key length).
    Block size: 128 bits (4 words).
    """

    keySize = 256 // 32
    blockSize = 128 // 32

    def _doReset(self):
        """
        Expand the key into round key schedules.

        The key schedule reuses previously computed values when the
        same key object is reused (detected by _keyPriorReset).
        """
        if getattr(self, '_nRounds', None) and getattr(self, '_keyPriorReset', None) is self._key:
            return

        key = self._keyPriorReset = self._key
        keyWords = key.words
        keySize = key.sigBytes // 4
        nRounds = self._nRounds = keySize + 6
        ksRows = (nRounds + 1) * 4

        keySchedule = self._keySchedule = []
        for ksRow in range(ksRows):
            if ksRow < keySize:
                keySchedule.append(keyWords[ksRow])
            else:
                t = keySchedule[ksRow - 1]
                if not (ksRow % keySize):
                    t = _32((t << 8) | (t >> 24))
                    t = (SBOX[t >> 24] << 24) | (SBOX[(t >> 16) & 0xFF] << 16) | (SBOX[(t >> 8) & 0xFF] << 8) | SBOX[t & 0xFF]
                    t ^= RCON[(ksRow // keySize)] << 24
                elif keySize > 6 and ksRow % keySize == 4:
                    t = (SBOX[t >> 24] << 24) | (SBOX[(t >> 16) & 0xFF] << 16) | (SBOX[(t >> 8) & 0xFF] << 8) | SBOX[t & 0xFF]
                keySchedule.append(_32(keySchedule[ksRow - keySize] ^ t))

        invKeySchedule = self._invKeySchedule = []
        for invKsRow in range(ksRows):
            ksRow = ksRows - invKsRow
            if invKsRow % 4:
                t = keySchedule[ksRow]
            else:
                t = keySchedule[ksRow - 4]
            if invKsRow < 4 or ksRow <= 4:
                invKeySchedule.append(t)
            else:
                invKeySchedule.append(_32(
                    INV_SUB_MIX_0[SBOX[t >> 24]] ^ INV_SUB_MIX_1[SBOX[(t >> 16) & 0xFF]] ^
                    INV_SUB_MIX_2[SBOX[(t >> 8) & 0xFF]] ^ INV_SUB_MIX_3[SBOX[t & 0xFF]]
                ))

    def encryptBlock(self, M, offset):
        """Encrypt one 128-bit (4-word) block starting at offset."""
        self._doCryptBlock(M, offset, self._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX)

    def decryptBlock(self, M, offset):
        """
        Decrypt one 128-bit (4-word) block starting at offset.

        AES decrypt requires swapping columns 1 and 3 before and
        after the core crypt operation due to the inverse ShiftRows
        and InvMixColumns interaction.
        """
        t = M[offset + 1]
        M[offset + 1] = M[offset + 3]
        M[offset + 3] = t

        self._doCryptBlock(M, offset, self._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX)

        t = M[offset + 1]
        M[offset + 1] = M[offset + 3]
        M[offset + 3] = t

    def _doCryptBlock(self, M, offset, keySchedule, SUB_0, SUB_1, SUB_2, SUB_3, SBOX):
        """
        Core AES encryption/decryption round transformation.

        For encryption (or decryption using inverse tables):
          - Initial round key XOR (AddRoundKey).
          - For rounds 1 .. nRounds-1: T-table substitution (SubBytes +
            ShiftRows + MixColumns + AddRoundKey in one step).
          - Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns).

        The state is four 32-bit words (s0..s3 = column-major order).
        """
        nRounds = self._nRounds

        s0 = _32(M[offset] ^ keySchedule[0])
        s1 = _32(M[offset + 1] ^ keySchedule[1])
        s2 = _32(M[offset + 2] ^ keySchedule[2])
        s3 = _32(M[offset + 3] ^ keySchedule[3])

        ksRow = 4
        for round in range(1, nRounds):
            t0 = _32(SUB_0[s0 >> 24] ^ SUB_1[(s1 >> 16) & 0xFF] ^ SUB_2[(s2 >> 8) & 0xFF] ^ SUB_3[s3 & 0xFF] ^ keySchedule[ksRow])
            t1 = _32(SUB_0[s1 >> 24] ^ SUB_1[(s2 >> 16) & 0xFF] ^ SUB_2[(s3 >> 8) & 0xFF] ^ SUB_3[s0 & 0xFF] ^ keySchedule[ksRow + 1])
            t2 = _32(SUB_0[s2 >> 24] ^ SUB_1[(s3 >> 16) & 0xFF] ^ SUB_2[(s0 >> 8) & 0xFF] ^ SUB_3[s1 & 0xFF] ^ keySchedule[ksRow + 2])
            t3 = _32(SUB_0[s3 >> 24] ^ SUB_1[(s0 >> 16) & 0xFF] ^ SUB_2[(s1 >> 8) & 0xFF] ^ SUB_3[s2 & 0xFF] ^ keySchedule[ksRow + 3])
            s0, s1, s2, s3 = t0, t1, t2, t3
            ksRow += 4

        t0 = _32(((SBOX[s0 >> 24] << 24) | (SBOX[(s1 >> 16) & 0xFF] << 16) | (SBOX[(s2 >> 8) & 0xFF] << 8) | SBOX[s3 & 0xFF]) ^ keySchedule[ksRow])
        t1 = _32(((SBOX[s1 >> 24] << 24) | (SBOX[(s2 >> 16) & 0xFF] << 16) | (SBOX[(s3 >> 8) & 0xFF] << 8) | SBOX[s0 & 0xFF]) ^ keySchedule[ksRow + 1])
        t2 = _32(((SBOX[s2 >> 24] << 24) | (SBOX[(s3 >> 16) & 0xFF] << 16) | (SBOX[(s0 >> 8) & 0xFF] << 8) | SBOX[s1 & 0xFF]) ^ keySchedule[ksRow + 2])
        t3 = _32(((SBOX[s3 >> 24] << 24) | (SBOX[(s0 >> 16) & 0xFF] << 16) | (SBOX[(s1 >> 8) & 0xFF] << 8) | SBOX[s2 & 0xFF]) ^ keySchedule[ksRow + 3])

        M[offset] = t0
        M[offset + 1] = t1
        M[offset + 2] = t2
        M[offset + 3] = t3
