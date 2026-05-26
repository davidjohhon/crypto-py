"""
sm2.py — SM2 public key cryptography (GM/T 0003-2012).

Elliptic curve over Fp (256-bit SM2 curve).
"""

import os
from Crypto.core import WordArray
from Crypto.sm3 import SM3 as _SM3


SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class _Point:
    def __init__(self, x, y):
        self.x, self.y = x % SM2_P, y % SM2_P

    def is_zero(self):
        return self.x == 0 and self.y == 0

    def __eq__(self, o):
        return self.x == o.x and self.y == o.y


_ZERO = _Point(0, 0)
_G = _Point(SM2_GX, SM2_GY)


def _mod_inv(a, m):
    return pow(a, m - 2, m)


def _int_from(b):
    return int.from_bytes(b, 'big')


def _int_to(x, n=32):
    return x.to_bytes(n, 'big')


def _add(p, q):
    if p.is_zero(): return q
    if q.is_zero(): return p
    if p == q:
        return _double(p)
    if p.x == q.x:
        return _ZERO
    s = _mod_inv(q.x - p.x, SM2_P)
    lam = (q.y - p.y) * s % SM2_P
    x3 = (lam * lam - p.x - q.x) % SM2_P
    y3 = (lam * (p.x - x3) - p.y) % SM2_P
    return _Point(x3, y3)


def _double(p):
    if p.is_zero(): return p
    lam = (3 * p.x * p.x + SM2_A) * _mod_inv(2 * p.y, SM2_P) % SM2_P
    x3 = (lam * lam - 2 * p.x) % SM2_P
    y3 = (lam * (p.x - x3) - p.y) % SM2_P
    return _Point(x3, y3)


def _mul(k, p):
    r, q = _ZERO, _Point(p.x, p.y)
    while k > 0:
        if k & 1:
            r = _add(r, q)
        q, k = _double(q), k >> 1
    return r


def _sha256(data):
    h = _SM3.create()
    wa = WordArray.create(list(data), len(data))
    h.update(wa)
    return int(h.finalize().toString(), 16)


def _kdf(z, klen):
    d, ct = bytearray(), 1
    while len(d) * 8 < klen:
        h = _sha256(z + ct.to_bytes(4, 'big'))
        d.extend(h.to_bytes(32, 'big'))
        ct += 1
    return bytes(d)[:klen // 8]


def generate_keypair():
    """Generate SM2 key pair. Returns (private_key_bytes, public_key_bytes)."""
    d = _int_from(os.urandom(32)) % (SM2_N - 1) + 1
    Q = _mul(d, _G)
    return _int_to(d), _int_to(Q.x) + _int_to(Q.y)


def sign(private_key, message):
    """Sign a message with SM2 private key. Returns 64-byte signature."""
    if isinstance(message, str):
        message = message.encode()
    d = _int_from(private_key)
    e = _sha256(message)
    while True:
        k = _int_from(os.urandom(32)) % (SM2_N - 1) + 1
        p = _mul(k, _G)
        r = (e + p.x) % SM2_N
        if r == 0 or r + k == SM2_N:
            continue
        s = _mod_inv(1 + d, SM2_N) * (k - r * d) % SM2_N
        if s == 0:
            continue
        return _int_to(r) + _int_to(s)


def verify(public_key, message, signature):
    """Verify an SM2 signature. Returns True/False."""
    if isinstance(message, str):
        message = message.encode()
    r, s = _int_from(signature[:32]), _int_from(signature[32:])
    if not (1 <= r < SM2_N and 1 <= s < SM2_N):
        return False
    t = (r + s) % SM2_N
    if t == 0:
        return False
    P = _Point(_int_from(public_key[:32]), _int_from(public_key[32:]))
    e = _sha256(message)
    gs = _mul(s, _G)
    tp = _mul(t, P)
    p = _add(gs, tp)
    return (e + p.x) % SM2_N == r


def encrypt(public_key, message):
    """Encrypt a message with SM2 public key."""
    if isinstance(message, str):
        message = message.encode()
    P = _Point(_int_from(public_key[:32]), _int_from(public_key[32:]))
    while True:
        k = _int_from(os.urandom(32)) % (SM2_N - 1) + 1
        c1 = _mul(k, _G)
        p = _mul(k, P)
        x2, y2 = _int_to(p.x), _int_to(p.y)
        t = _kdf(x2 + y2, len(message) * 8)
        if any(t):
            break
    c2 = bytes(a ^ b for a, b in zip(message, t))
    c3 = _int_to(_sha256(x2 + message + y2), 32)
    return _int_to(c1.x) + _int_to(c1.y) + c3 + c2


def decrypt(private_key, ciphertext):
    """Decrypt a ciphertext with SM2 private key."""
    d = _int_from(private_key)
    cx = _int_from(ciphertext[:32])
    cy = _int_from(ciphertext[32:64])
    c3 = ciphertext[64:96]
    c2 = ciphertext[96:]
    p = _mul(d, _Point(cx, cy))
    x2, y2 = _int_to(p.x), _int_to(p.y)
    t = _kdf(x2 + y2, len(c2) * 8)
    m = bytes(a ^ b for a, b in zip(c2, t))
    u = _int_to(_sha256(x2 + m + y2), 32)
    if u != c3:
        raise ValueError("SM2 decrypt: invalid ciphertext")
    return m
