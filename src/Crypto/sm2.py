"""
sm2.py — SM2 public key cryptography (GM/T 0003-2012).

Elliptic curve over Fp (256-bit SM2 curve).
Supports: key generation, signing, verification, encryption.
"""

import os
from Crypto.core import WordArray, _32
from Crypto.sm3 import SM3 as _SM3


SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


def _mod_inv(a, m):
    return pow(a, m - 2, m)


def _mod_add(a, b, m):
    return (a + b) % m


def _mod_sub(a, b, m):
    return (a - b) % m


def _mod_mul(a, b, m):
    return (a * b) % m


def _bytes_to_int(b):
    return int.from_bytes(b, 'big')


def _int_to_bytes(x, n=32):
    return x.to_bytes(n, 'big')


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_zero(self):
        return self.x == 0 and self.y == 0

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        return f"Point(0x{self.x:064x}, 0x{self.y:064x})"


POINT_ZERO = Point(0, 0)
G = Point(SM2_GX, SM2_GY)


def _point_add(p1, p2):
    if p1.is_zero():
        return p2
    if p2.is_zero():
        return p1
    if p1 == p2:
        return _point_double(p1)
    if p1.x == p2.x:
        return POINT_ZERO
    s = _mod_mul(_mod_sub(p2.y, p1.y, SM2_P), _mod_inv(_mod_sub(p2.x, p1.x, SM2_P), SM2_P), SM2_P)
    x3 = _mod_sub(_mod_sub(_mod_mul(s, s, SM2_P), p1.x, SM2_P), p2.x, SM2_P)
    y3 = _mod_sub(_mod_mul(s, _mod_sub(p1.x, x3, SM2_P), SM2_P), p1.y, SM2_P)
    return Point(x3, y3)


def _point_double(p):
    if p.is_zero():
        return p
    s = _mod_mul(_mod_mul(p.x, p.x, SM2_P) * 3 + SM2_A, _mod_inv(p.y * 2, SM2_P), SM2_P)
    x3 = _mod_sub(_mod_mul(s, s, SM2_P), p.x * 2, SM2_P)
    y3 = _mod_sub(_mod_mul(s, _mod_sub(p.x, x3, SM2_P), SM2_P), p.y, SM2_P)
    return Point(x3, y3)


def _point_mul(k, p):
    if k == 0 or p.is_zero():
        return POINT_ZERO
    if k == 1:
        return p
    if k % 2 == 0:
        return _point_mul(k // 2, _point_double(p))
    return _point_add(p, _point_mul(k - 1, p))


def _point_mul_fast(k, p):
    r = POINT_ZERO
    q = Point(p.x, p.y)
    while k > 0:
        if k & 1:
            r = _point_add(r, q)
        q = _point_double(q)
        k >>= 1
    return r


def _sm3_hash(data):
    sm3 = _SM3.create()
    wa = WordArray.create(list(data), len(data))
    sm3.update(wa)
    return sm3.finalize()


def _wordarray_to_bytes(wa):
    result = bytearray()
    for i in range(wa.sigBytes):
        result.append((wa.words[i >> 2] >> (24 - (i % 4) * 8)) & 0xFF)
    return bytes(result)


def _KDF(Z, klen):
    d = bytearray()
    ct = 0x00000001
    while len(d) * 8 < klen:
        h = _sm3_hash(Z + ct.to_bytes(4, 'big'))
        d.extend(_wordarray_to_bytes(h))
        ct += 1
    return bytes(d)[:klen // 8]


def generate_keypair():
    d = _bytes_to_int(os.urandom(32)) % (SM2_N - 1) + 1
    P = _point_mul_fast(d, G)
    return d, P


def sign(priv_key, msg):
    h = _sm3_hash(msg)
    e = int(h.toString(), 16)
    k = _bytes_to_int(os.urandom(32)) % (SM2_N - 1) + 1
    p1 = _point_mul_fast(k, G)
    r = _mod_add(e, p1.x, SM2_N)
    s = _mod_mul(_mod_inv(1 + priv_key, SM2_N), _mod_sub(k, _mod_mul(r, priv_key, SM2_N), SM2_N), SM2_N)
    return r, s


def verify(pub_key, msg, r, s):
    if r < 1 or r > SM2_N - 1 or s < 1 or s > SM2_N - 1:
        return False
    e = int(_sm3_hash(msg).toString(), 16)
    t = _mod_add(r, s, SM2_N)
    if t == 0:
        return False
    p1 = _point_mul_fast(s, G)
    p2 = _point_mul_fast(t, pub_key)
    p = _point_add(p1, p2)
    R = _mod_add(e, p.x, SM2_N)
    return R == r


class SM2:
    def __init__(self):
        self._priv_key = None
        self._pub_key = None

    def generate_key(self):
        self._priv_key, self._pub_key = generate_keypair()
        return self

    def set_private_key(self, priv_bytes):
        self._priv_key = _bytes_to_int(priv_bytes)
        self._pub_key = _point_mul_fast(self._priv_key, G)
        return self

    def set_public_key(self, pub_x, pub_y):
        self._pub_key = Point(pub_x, pub_y)
        return self

    def sign(self, message):
        if self._priv_key is None:
            raise ValueError("Private key not set")
        if isinstance(message, str):
            message = message.encode()
        r, s = sign(self._priv_key, message)
        return _int_to_bytes(r) + _int_to_bytes(s)

    def verify(self, message, signature):
        if self._pub_key is None:
            raise ValueError("Public key not set")
        if isinstance(message, str):
            message = message.encode()
        r = _bytes_to_int(signature[:32])
        s = _bytes_to_int(signature[32:])
        return verify(self._pub_key, message, r, s)

    def encrypt(self, message):
        if self._pub_key is None:
            raise ValueError("Public key not set")
        if isinstance(message, str):
            message = message.encode()
        k = _bytes_to_int(os.urandom(32)) % (SM2_N - 1) + 1
        c1 = _point_mul_fast(k, G)
        p = _point_mul_fast(k, self._pub_key)
        x2 = _int_to_bytes(p.x)
        y2 = _int_to_bytes(p.y)
        t = _KDF(x2 + y2, len(message) * 8)
        c2 = bytes(a ^ b for a, b in zip(message, t))
        c3 = _wordarray_to_bytes(_sm3_hash(x2 + message + y2))
        return _int_to_bytes(c1.x) + _int_to_bytes(c1.y) + c3 + c2

    def decrypt(self, ciphertext):
        if self._priv_key is None:
            raise ValueError("Private key not set")
        cx = _bytes_to_int(ciphertext[:32])
        cy = _bytes_to_int(ciphertext[32:64])
        c3 = ciphertext[64:96]
        c2 = ciphertext[96:]
        p = _point_mul_fast(self._priv_key, Point(cx, cy))
        x2 = _int_to_bytes(p.x)
        y2 = _int_to_bytes(p.y)
        t = _KDF(x2 + y2, len(c2) * 8)
        m = bytes(a ^ b for a, b in zip(c2, t))
        u = _wordarray_to_bytes(_sm3_hash(x2 + m + y2))
        if u != c3:
            raise ValueError("Decryption failed: invalid ciphertext")
        return m
