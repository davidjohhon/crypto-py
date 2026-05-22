"""
_keccak.py — Pure Python Keccak-f[1600] permutation.

Port of the Keccak Code Package reference implementation.
"""


PlSn = [
    [0, 1, 2, 3, 4],
    [5, 6, 7, 8, 9],
    [10, 11, 12, 13, 14],
    [15, 16, 17, 18, 19],
    [20, 21, 22, 23, 24],
]

R = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]


def _rot64(x, n):
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def KeccakF1600(state):
    for rnd in range(24):
        C0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20]
        C1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21]
        C2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22]
        C3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23]
        C4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24]

        D0 = C4 ^ _rot64(C1, 1)
        D1 = C0 ^ _rot64(C2, 1)
        D2 = C1 ^ _rot64(C3, 1)
        D3 = C2 ^ _rot64(C4, 1)
        D4 = C3 ^ _rot64(C0, 1)

        state[0] ^= D0; state[5] ^= D0; state[10] ^= D0; state[15] ^= D0; state[20] ^= D0
        state[1] ^= D1; state[6] ^= D1; state[11] ^= D1; state[16] ^= D1; state[21] ^= D1
        state[2] ^= D2; state[7] ^= D2; state[12] ^= D2; state[17] ^= D2; state[22] ^= D2
        state[3] ^= D3; state[8] ^= D3; state[13] ^= D3; state[18] ^= D3; state[23] ^= D3
        state[4] ^= D4; state[9] ^= D4; state[14] ^= D4; state[19] ^= D4; state[24] ^= D4

        B = state[:]
        for x in range(5):
            for y in range(5):
                state[PlSn[x][y]] = _rot64(B[x + 5 * ((x + y) % 5) - x], R[x + 5 * y])

        M = [0] * 25
        for x in range(5):
            for y in range(5):
                i = x + 5 * y
                M[i] = state[i] ^ ((~state[PlSn[(x + 1) % 5][y]]) & state[PlSn[(x + 2) % 5][y]])

        state[:] = M
        state[0] ^= RC[rnd]
