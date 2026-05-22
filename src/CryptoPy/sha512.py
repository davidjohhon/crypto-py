"""
sha512.py — SHA-512 hash algorithm implementation (FIPS 180-4).

SHA-512 processes 1024-bit blocks and produces a 512-bit digest
(eight 64-bit words).  This implementation represents 64-bit values
as pairs of 32-bit words (high/low) using X64Word/X64WordArray.

The message schedule W[0..79] expands the 16 X64Word block to
80 X64Words.  Each 64-bit operation is decomposed into high and
low 32-bit halves with explicit carry propagation.

The carry detection pattern:
    sum_low = _64(a_low + b_low)
    sum_high = _64(a_high + b_high + (1 if sum_low < a_low else 0))
This emulates 64-bit addition using 32-bit arithmetic.
"""

import math
from CryptoPy.core import WordArray, Hasher, _32
from CryptoPy.x64core import X64Word, X64WordArray


def _64(x):
    """Truncate to unsigned 32 bits (helper for 64-bit emulation halves)."""
    return x & 0xFFFFFFFF


K = [
    X64Word.create(0x428a2f98, 0xd728ae22), X64Word.create(0x71374491, 0x23ef65cd),
    X64Word.create(0xb5c0fbcf, 0xec4d3b2f), X64Word.create(0xe9b5dba5, 0x8189dbbc),
    X64Word.create(0x3956c25b, 0xf348b538), X64Word.create(0x59f111f1, 0xb605d019),
    X64Word.create(0x923f82a4, 0xaf194f9b), X64Word.create(0xab1c5ed5, 0xda6d8118),
    X64Word.create(0xd807aa98, 0xa3030242), X64Word.create(0x12835b01, 0x45706fbe),
    X64Word.create(0x243185be, 0x4ee4b28c), X64Word.create(0x550c7dc3, 0xd5ffb4e2),
    X64Word.create(0x72be5d74, 0xf27b896f), X64Word.create(0x80deb1fe, 0x3b1696b1),
    X64Word.create(0x9bdc06a7, 0x25c71235), X64Word.create(0xc19bf174, 0xcf692694),
    X64Word.create(0xe49b69c1, 0x9ef14ad2), X64Word.create(0xefbe4786, 0x384f25e3),
    X64Word.create(0x0fc19dc6, 0x8b8cd5b5), X64Word.create(0x240ca1cc, 0x77ac9c65),
    X64Word.create(0x2de92c6f, 0x592b0275), X64Word.create(0x4a7484aa, 0x6ea6e483),
    X64Word.create(0x5cb0a9dc, 0xbd41fbd4), X64Word.create(0x76f988da, 0x831153b5),
    X64Word.create(0x983e5152, 0xee66dfab), X64Word.create(0xa831c66d, 0x2db43210),
    X64Word.create(0xb00327c8, 0x98fb213f), X64Word.create(0xbf597fc7, 0xbeef0ee4),
    X64Word.create(0xc6e00bf3, 0x3da88fc2), X64Word.create(0xd5a79147, 0x930aa725),
    X64Word.create(0x06ca6351, 0xe003826f), X64Word.create(0x14292967, 0x0a0e6e70),
    X64Word.create(0x27b70a85, 0x46d22ffc), X64Word.create(0x2e1b2138, 0x5c26c926),
    X64Word.create(0x4d2c6dfc, 0x5ac42aed), X64Word.create(0x53380d13, 0x9d95b3df),
    X64Word.create(0x650a7354, 0x8baf63de), X64Word.create(0x766a0abb, 0x3c77b2a8),
    X64Word.create(0x81c2c92e, 0x47edaee6), X64Word.create(0x92722c85, 0x1482353b),
    X64Word.create(0xa2bfe8a1, 0x4cf10364), X64Word.create(0xa81a664b, 0xbc423001),
    X64Word.create(0xc24b8b70, 0xd0f89791), X64Word.create(0xc76c51a3, 0x0654be30),
    X64Word.create(0xd192e819, 0xd6ef5218), X64Word.create(0xd6990624, 0x5565a910),
    X64Word.create(0xf40e3585, 0x5771202a), X64Word.create(0x106aa070, 0x32bbd1b8),
    X64Word.create(0x19a4c116, 0xb8d2d0c8), X64Word.create(0x1e376c08, 0x5141ab53),
    X64Word.create(0x2748774c, 0xdf8eeb99), X64Word.create(0x34b0bcb5, 0xe19b48a8),
    X64Word.create(0x391c0cb3, 0xc5c95a63), X64Word.create(0x4ed8aa4a, 0xe3418acb),
    X64Word.create(0x5b9cca4f, 0x7763e373), X64Word.create(0x682e6ff3, 0xd6b2b8a3),
    X64Word.create(0x748f82ee, 0x5defb2fc), X64Word.create(0x78a5636f, 0x43172f60),
    X64Word.create(0x84c87814, 0xa1f0ab72), X64Word.create(0x8cc70208, 0x1a6439ec),
    X64Word.create(0x90befffa, 0x23631e28), X64Word.create(0xa4506ceb, 0xde82bde9),
    X64Word.create(0xbef9a3f7, 0xb2c67915), X64Word.create(0xc67178f2, 0xe372532b),
    X64Word.create(0xca273ece, 0xea26619c), X64Word.create(0xd186b8c7, 0x21c0c207),
    X64Word.create(0xeada7dd6, 0xcde0eb1e), X64Word.create(0xf57d4f7f, 0xee6ed178),
    X64Word.create(0x06f067aa, 0x72176fba), X64Word.create(0x0a637dc5, 0xa2c898a6),
    X64Word.create(0x113f9804, 0xbef90dae), X64Word.create(0x1b710b35, 0x131c471b),
    X64Word.create(0x28db77f5, 0x23047d84), X64Word.create(0x32caab7b, 0x40c72493),
    X64Word.create(0x3c9ebe0a, 0x15c9bebc), X64Word.create(0x431d67c4, 0x9c100d4c),
    X64Word.create(0x4cc5d4be, 0xcb3e42b6), X64Word.create(0x597f299c, 0xfc657e2a),
    X64Word.create(0x5fcb6fab, 0x3ad6faec), X64Word.create(0x6c44198c, 0x4a475817)
]


class SHA512(Hasher):
    """
    SHA-512 hash algorithm.

    Digest size: 512 bits (8 X64Words → 16 × 32-bit words on output).
    Block size: 1024 bits (32 × 32-bit words).
    Uses 80 rounds of compression on a 64-bit state.
    """

    blockSize = 1024 // 32

    def init(self, cfg=None):
        """Initialise the message schedule W (80 X64Words)."""
        self.W = [X64Word.create() for _ in range(80)]
        super().init(cfg)

    def _doReset(self):
        """Initialise SHA-512 state with standard IV values (64-bit words)."""
        self._hash = X64WordArray.create([
            X64Word.create(0x6a09e667, 0xf3bcc908), X64Word.create(0xbb67ae85, 0x84caa73b),
            X64Word.create(0x3c6ef372, 0xfe94f82b), X64Word.create(0xa54ff53a, 0x5f1d36f1),
            X64Word.create(0x510e527f, 0xade682d1), X64Word.create(0x9b05688c, 0x2b3e6c1f),
            X64Word.create(0x1f83d9ab, 0xfb41bd6b), X64Word.create(0x5be0cd19, 0x137e2179)
        ])

    def _doProcessBlock(self, M, offset):
        """
        Process one 1024-bit (32-word) block through 80 rounds.

        Each X64Word from the message is formed from two consecutive
        32-bit big-endian words from M (high word first, then low word).

        64-bit operations are decomposed:
          - Rotations: each half is rotated independently with carry
            between halves (e.g. (high << n) | (low >> (32-n))).
          - Addition: low halves are added first, then high halves
            with carry from the low addition.

        The carry detection pattern:
            Wil = _64(gamma0l + Wi7l)
            Wih = _64(gamma0h + Wi7h + (1 if (Wil & 0xFFFFFFFF) < (gamma0l & 0xFFFFFFFF) else 0))
        """
        H = self._hash.words
        H0l, H0h = H[0].low, H[0].high
        H1l, H1h = H[1].low, H[1].high
        H2l, H2h = H[2].low, H[2].high
        H3l, H3h = H[3].low, H[3].high
        H4l, H4h = H[4].low, H[4].high
        H5l, H5h = H[5].low, H[5].high
        H6l, H6h = H[6].low, H[6].high
        H7l, H7h = H[7].low, H[7].high

        ah, al = H0h, H0l
        bh, bl = H1h, H1l
        ch, cl = H2h, H2l
        dh, dl = H3h, H3l
        eh, el = H4h, H4l
        fh, fl = H5h, H5l
        gh, gl = H6h, H6l
        hh, hl = H7h, H7l

        W = self.W
        for i in range(80):
            if i < 16:
                Wih = M[offset + i * 2] | 0
                Wil = M[offset + i * 2 + 1] | 0
                W[i].high = Wih
                W[i].low = Wil
            else:
                gamma0x = W[i - 15]
                gamma0xh = gamma0x.high
                gamma0xl = gamma0x.low
                gamma0h = ((gamma0xh >> 1) | (gamma0xl << 31)) ^ ((gamma0xh >> 8) | (gamma0xl << 24)) ^ (gamma0xh >> 7)
                gamma0l = ((gamma0xl >> 1) | (gamma0xh << 31)) ^ ((gamma0xl >> 8) | (gamma0xh << 24)) ^ ((gamma0xl >> 7) | (gamma0xh << 25))

                gamma1x = W[i - 2]
                gamma1xh = gamma1x.high
                gamma1xl = gamma1x.low
                gamma1h = ((gamma1xh >> 19) | (gamma1xl << 13)) ^ ((gamma1xh << 3) | (gamma1xl >> 29)) ^ (gamma1xh >> 6)
                gamma1l = ((gamma1xl >> 19) | (gamma1xh << 13)) ^ ((gamma1xl << 3) | (gamma1xh >> 29)) ^ ((gamma1xl >> 6) | (gamma1xh << 26))

                Wi7 = W[i - 7]
                Wi7h, Wi7l = Wi7.high, Wi7.low
                Wi16 = W[i - 16]
                Wi16h, Wi16l = Wi16.high, Wi16.low

                Wil = _64(gamma0l + Wi7l)
                Wih = _64(gamma0h + Wi7h + (1 if (Wil & 0xFFFFFFFF) < (gamma0l & 0xFFFFFFFF) else 0))
                Wil = _64(Wil + gamma1l)
                Wih = _64(Wih + gamma1h + (1 if (Wil & 0xFFFFFFFF) < (gamma1l & 0xFFFFFFFF) else 0))
                Wil = _64(Wil + Wi16l)
                Wih = _64(Wih + Wi16h + (1 if (Wil & 0xFFFFFFFF) < (Wi16l & 0xFFFFFFFF) else 0))

                W[i].high = Wih & 0xFFFFFFFF
                W[i].low = Wil & 0xFFFFFFFF

            chh = (eh & fh) ^ ((~eh & 0xFFFFFFFF) & gh)
            chl = (el & fl) ^ ((~el & 0xFFFFFFFF) & gl)
            majh = (ah & bh) ^ (ah & ch) ^ (bh & ch)
            majl = (al & bl) ^ (al & cl) ^ (bl & cl)

            sigma0h = ((ah >> 28) | (al << 4)) ^ ((ah << 30) | (al >> 2)) ^ ((ah << 25) | (al >> 7))
            sigma0l = ((al >> 28) | (ah << 4)) ^ ((al << 30) | (ah >> 2)) ^ ((al << 25) | (ah >> 7))
            sigma1h = ((eh >> 14) | (el << 18)) ^ ((eh >> 18) | (el << 14)) ^ ((eh << 23) | (el >> 9))
            sigma1l = ((el >> 14) | (eh << 18)) ^ ((el >> 18) | (eh << 14)) ^ ((el << 23) | (eh >> 9))

            Ki = K[i]
            Kih, Kil = Ki.high, Ki.low
            Wi = W[i]
            Wih, Wil = Wi.high, Wi.low

            t1l = _64(hl + sigma1l)
            t1h = _64(hh + sigma1h + (1 if (t1l & 0xFFFFFFFF) < (hl & 0xFFFFFFFF) else 0))
            t1l = _64(t1l + chl)
            t1h = _64(t1h + chh + (1 if (t1l & 0xFFFFFFFF) < (chl & 0xFFFFFFFF) else 0))
            t1l = _64(t1l + Kil)
            t1h = _64(t1h + Kih + (1 if (t1l & 0xFFFFFFFF) < (Kil & 0xFFFFFFFF) else 0))
            t1l = _64(t1l + Wil)
            t1h = _64(t1h + Wih + (1 if (t1l & 0xFFFFFFFF) < (Wil & 0xFFFFFFFF) else 0))

            t2l = _64(sigma0l + majl)
            t2h = _64(sigma0h + majh + (1 if (t2l & 0xFFFFFFFF) < (sigma0l & 0xFFFFFFFF) else 0))

            hh, hl = gh, gl
            gh, gl = fh, fl
            fh, fl = eh, el
            el = _64(dl + t1l)
            eh = _64(dh + t1h + (1 if (el & 0xFFFFFFFF) < (dl & 0xFFFFFFFF) else 0))
            dh, dl = ch, cl
            ch, cl = bh, bl
            bh, bl = ah, al
            al = _64(t1l + t2l)
            ah = _64(t1h + t2h + (1 if (al & 0xFFFFFFFF) < (t1l & 0xFFFFFFFF) else 0))

        H0l = _64(H0l + al)
        H[0].low = H0l & 0xFFFFFFFF
        H[0].high = _64(H0h + ah + (1 if (H0l & 0xFFFFFFFF) < (al & 0xFFFFFFFF) else 0)) & 0xFFFFFFFF
        H1l = _64(H1l + bl)
        H[1].low = H1l & 0xFFFFFFFF
        H[1].high = _64(H1h + bh + (1 if (H1l & 0xFFFFFFFF) < (bl & 0xFFFFFFFF) else 0)) & 0xFFFFFFFF
        H2l = _64(H2l + cl)
        H[2].low = H2l & 0xFFFFFFFF
        H[2].high = _64(H2h + ch + (1 if (H2l & 0xFFFFFFFF) < (cl & 0xFFFFFFFF) else 0)) & 0xFFFFFFFF
        H3l = _64(H3l + dl)
        H[3].low = H3l & 0xFFFFFFFF
        H[3].high = _64(H3h + dh + (1 if (H3l & 0xFFFFFFFF) < (dl & 0xFFFFFFFF) else 0)) & 0xFFFFFFFF
        H4l = _64(H4l + el)
        H[4].low = H4l & 0xFFFFFFFF
        H[4].high = _64(H4h + eh + (1 if (H4l & 0xFFFFFFFF) < (el & 0xFFFFFFFF) else 0)) & 0xFFFFFFFF
        H5l = _64(H5l + fl)
        H[5].low = H5l & 0xFFFFFFFF
        H[5].high = _64(H5h + fh + (1 if (H5l & 0xFFFFFFFF) < (fl & 0xFFFFFFFF) else 0)) & 0xFFFFFFFF
        H6l = _64(H6l + gl)
        H[6].low = H6l & 0xFFFFFFFF
        H[6].high = _64(H6h + gh + (1 if (H6l & 0xFFFFFFFF) < (gl & 0xFFFFFFFF) else 0)) & 0xFFFFFFFF
        H7l = _64(H7l + hl)
        H[7].low = H7l & 0xFFFFFFFF
        H[7].high = _64(H7h + hh + (1 if (H7l & 0xFFFFFFFF) < (hl & 0xFFFFFFFF) else 0)) & 0xFFFFFFFF

    def _doFinalize(self):
        """
        Finalise SHA-512 with Merkle-Damgard padding.

        Padding: append 0x80, then zeros, then 128-bit big-endian bit
        length (two 32-bit words representing the high and low 32 bits
        of the 64-bit length — SHA-512 uses 128 bits of length padding).

        The final hash is converted from X64WordArray to a 32-bit WordArray
        via toX32() for compatibility with the rest of the library.
        """
        data = self._data
        dataWords = data.words
        nBitsTotal = self._nDataBytes * 8
        nBitsLeft = data.sigBytes * 8

        while len(dataWords) <= (nBitsLeft >> 5):
            dataWords.append(0)
        dataWords[nBitsLeft >> 5] = _32(dataWords[nBitsLeft >> 5] | (0x80 << (24 - nBitsLeft % 32)))

        idx30 = (((nBitsLeft + 128) >> 10) << 5) + 30
        idx31 = idx30 + 1
        while len(dataWords) <= idx31:
            dataWords.append(0)

        dataWords[idx30] = nBitsTotal // 0x100000000
        dataWords[idx31] = nBitsTotal
        data.sigBytes = len(dataWords) * 4

        self._process()
        return self._hash.toX32()

    def clone(self):
        clone = Hasher.clone(self)
        clone._hash = self._hash.clone()
        return clone
