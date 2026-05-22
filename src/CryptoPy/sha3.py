"""
sha3.py — SHA-3 / Keccak hash algorithm (FIPS 202).

SHA-3 is based on the Keccak sponge construction, not the
Merkle-Damgard construction used by SHA-1/SHA-2.

Sponge construction:
  - The state is 1600 bits (25 × 64-bit lanes).
  - Absorbing: input blocks are XORed into the state.
  - Squeezing: output lanes are read from the state.
  - The output length determines the capacity (c = 2 * outputLength)
    and the rate (r = 1600 - c).

Each Keccak-f[1600] permutation consists of 24 rounds of five steps:
  θ (theta), ρ (rho), π (pi), χ (chi), ι (iota).

Constants RHO_OFFSETS, PI_INDEXES, and ROUND_CONSTANTS are precomputed
at module load time based on the Keccak specification.
"""

import math
from CryptoPy.core import WordArray, Hasher, _32
from CryptoPy.x64core import X64Word


RHO_OFFSETS = [0] * 25
PI_INDEXES = []
ROUND_CONSTANTS = []

x, y = 1, 0
for t in range(24):
    RHO_OFFSETS[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
    newX = y % 5
    newY = (2 * x + 3 * y) % 5
    x, y = newX, newY

for xi in range(5):
    for yi in range(5):
        PI_INDEXES.append(yi + ((2 * xi + 3 * yi) % 5) * 5)

LFSR = 0x01
for i in range(24):
    roundConstantMsw = 0
    roundConstantLsw = 0
    for j in range(7):
        if LFSR & 0x01:
            bitPosition = (1 << j) - 1
            if bitPosition < 32:
                roundConstantLsw ^= 1 << bitPosition
            else:
                roundConstantMsw ^= 1 << (bitPosition - 32)
        if LFSR & 0x80:
            LFSR = (LFSR << 1) ^ 0x71
        else:
            LFSR <<= 1
    ROUND_CONSTANTS.append(X64Word.create(roundConstantMsw, roundConstantLsw))


def swapEndian(word):
    return (
        (((word << 8) | (word >> 24)) & 0x00FF00FF) |
        (((word << 24) | (word >> 8)) & 0xFF00FF00)
    )


class SHA3(Hasher):
    """
    SHA-3 hash algorithm (Keccak-based).

    The output length defaults to 512 bits, but can be set to any
    supported value (224, 256, 384, 512) via cfg.outputLength.

    The block size (rate) is automatically computed as:
        blockSize = (1600 - 2 * outputLength) / 8 / 4   (in 32-bit words)
    """

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
        """Initialise the 25-lane Keccak state and temporary buffer T."""
        self._state = [X64Word.create() for _ in range(25)]
        self._T = [X64Word.create() for _ in range(25)]
        self.blockSize = (1600 - 2 * self.cfg.outputLength) // 32

    def _doProcessBlock(self, M, offset):
        """
        Absorb one block into the sponge and apply Keccak-f[1600].

        Absorption: XOR the block's lanes into the state (byte-swapped
        to convert between WordArray big-endian and Keccak little-endian
        lane representation).

        Keccak-f[1600] rounds:
          θ (theta): XOR columns, diffuse across rows.
          ρ (rho): rotate each lane by a fixed offset.
          π (pi): permute lane positions.
          χ (chi): nonlinear step (AND-NOT combos within rows).
          ι (iota): XOR a round constant into lane 0.
        """
        state = self._state
        T = self._T
        nBlockSizeLanes = self.blockSize // 2

        for i in range(nBlockSizeLanes):
            M2i = M[offset + 2 * i]
            M2i1 = M[offset + 2 * i + 1]
            M2i = swapEndian(M2i) & 0xFFFFFFFF
            M2i1 = swapEndian(M2i1) & 0xFFFFFFFF
            lane = state[i]
            lane.high = (lane.high ^ M2i1) & 0xFFFFFFFF
            lane.low = (lane.low ^ M2i) & 0xFFFFFFFF

        for round in range(24):
            # θ step: compute column parity (XOR of each column of 5 lanes)
            for xi in range(5):
                tMsw, tLsw = 0, 0
                for yj in range(5):
                    lane = state[xi + 5 * yj]
                    tMsw ^= lane.high
                    tLsw ^= lane.low
                Tx = T[xi]
                Tx.high = tMsw & 0xFFFFFFFF
                Tx.low = tLsw & 0xFFFFFFFF

            # θ step: diffuse column parity across the state
            for xi in range(5):
                Tx4 = T[(xi + 4) % 5]
                Tx1 = T[(xi + 1) % 5]
                Tx1Msw = Tx1.high
                Tx1Lsw = Tx1.low
                tMsw = Tx4.high ^ ((Tx1Msw << 1) | (Tx1Lsw >> 31))
                tLsw = Tx4.low ^ ((Tx1Lsw << 1) | (Tx1Msw >> 31))
                for yj in range(5):
                    lane = state[xi + 5 * yj]
                    lane.high = (lane.high ^ tMsw) & 0xFFFFFFFF
                    lane.low = (lane.low ^ tLsw) & 0xFFFFFFFF

            # ρ and π steps: rotate each lane and permute positions
            for laneIndex in range(1, 25):
                lane = state[laneIndex]
                laneMsw = lane.high
                laneLsw = lane.low
                rhoOffset = RHO_OFFSETS[laneIndex]
                if rhoOffset < 32:
                    tMsw = ((laneMsw << rhoOffset) | (laneLsw >> (32 - rhoOffset))) & 0xFFFFFFFF
                    tLsw = ((laneLsw << rhoOffset) | (laneMsw >> (32 - rhoOffset))) & 0xFFFFFFFF
                else:
                    tMsw = ((laneLsw << (rhoOffset - 32)) | (laneMsw >> (64 - rhoOffset))) & 0xFFFFFFFF
                    tLsw = ((laneMsw << (rhoOffset - 32)) | (laneLsw >> (64 - rhoOffset))) & 0xFFFFFFFF
                TPiLane = T[PI_INDEXES[laneIndex]]
                TPiLane.high = tMsw & 0xFFFFFFFF
                TPiLane.low = tLsw & 0xFFFFFFFF

            T0 = T[0]
            state0 = state[0]
            T0.high = state0.high
            T0.low = state0.low

            # χ step: nonlinear substitution (xi + NOT(xi+1) AND xi+2)
            for xi in range(5):
                for yj in range(5):
                    laneIndex = xi + 5 * yj
                    lane = state[laneIndex]
                    TLane = T[laneIndex]
                    Tx1Lane = T[((xi + 1) % 5) + 5 * yj]
                    Tx2Lane = T[((xi + 2) % 5) + 5 * yj]
                    lane.high = (TLane.high ^ (~Tx1Lane.high & Tx2Lane.high)) & 0xFFFFFFFF
                    lane.low = (TLane.low ^ (~Tx1Lane.low & Tx2Lane.low)) & 0xFFFFFFFF

            # ι step: XOR the round constant into lane 0
            lane = state[0]
            roundConstant = ROUND_CONSTANTS[round]
            lane.high = (lane.high ^ roundConstant.high) & 0xFFFFFFFF
            lane.low = (lane.low ^ roundConstant.low) & 0xFFFFFFFF

    def _doFinalize(self):
        """
        Finalise SHA-3 with Keccak-style padding.

        Padding: append 0x01, then zeros, then 0x80 at the end of
        the block (domain separation for SHA-3).  This differs from
        the Merkle-Damgard padding used by SHA-1/SHA-2.

        After final absorption, outputLengthBytes are squeezed from
        the state, with each lane byte-swapped back to big-endian.
        """
        data = self._data
        dataWords = data.words
        nBitsTotal = self._nDataBytes * 8
        nBitsLeft = data.sigBytes * 8
        blockSizeBits = self.blockSize * 32

        while len(dataWords) <= (nBitsLeft >> 5):
            dataWords.append(0)
        dataWords[nBitsLeft >> 5] = _32(dataWords[nBitsLeft >> 5] | (0x1 << (24 - nBitsLeft % 32)))

        lastIdx = (int(math.ceil((nBitsLeft + 1) / blockSizeBits)) * blockSizeBits >> 5) - 1
        while len(dataWords) <= lastIdx:
            dataWords.append(0)
        dataWords[lastIdx] = _32(dataWords[lastIdx] | 0x80)
        data.sigBytes = len(dataWords) * 4

        self._process()

        state = self._state
        outputLengthBytes = self.cfg.outputLength // 8
        outputLengthLanes = outputLengthBytes // 8

        hashWords = []
        for i in range(outputLengthLanes):
            lane = state[i]
            laneMsw = lane.high
            laneLsw = lane.low
            laneMsw = swapEndian(laneMsw) & 0xFFFFFFFF
            laneLsw = swapEndian(laneLsw) & 0xFFFFFFFF
            hashWords.append(laneLsw)
            hashWords.append(laneMsw)

        return WordArray.create(hashWords, outputLengthBytes)

    def clone(self):
        clone = Hasher.clone(self)
        clone._state = [w.clone() for w in self._state]
        clone._T = [w.clone() for w in self._T]
        return clone
