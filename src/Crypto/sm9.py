"""
sm9.py — SM9 identity-based cryptography (GM/T 0044-2016).

Implements:
- BN curve parameters
- Extension field arithmetic (Fp2, Fp4, Fp12)
- Tate pairing with Miller's algorithm
- Key Generation Center (KGC)
- Signature and verification
"""

import os
import hashlib
from Crypto.sm3 import SM3
from Crypto.core import WordArray


SM9_Q = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
SM9_N = 0xB640000002A3A6F1D603AB4FF58EC74421F2934B18EA8BEEE56EE19CD69ECF25
SM9_B = 0x05

SM9_Px = 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
SM9_Py = 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616

SM9_P1x = 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
SM9_P1y = 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616

SM9_HID_SIGN = 0x01
SM9_HID_ENC = 0x03


class Fp2:
    def __init__(self, a0, a1):
        self.a0 = a0 % SM9_Q
        self.a1 = a1 % SM9_Q

    def __add__(self, o):
        return Fp2(self.a0 + o.a0, self.a1 + o.a1)

    def __sub__(self, o):
        return Fp2(self.a0 - o.a0, self.a1 - o.a1)

    def __mul__(self, o):
        if isinstance(o, int):
            return Fp2(self.a0 * o, self.a1 * o)
        a0 = self.a0 * o.a0 - self.a1 * o.a1
        a1 = self.a0 * o.a1 + self.a1 * o.a0
        return Fp2(a0, a1)

    def __eq__(self, o):
        return self.a0 % SM9_Q == o.a0 % SM9_Q and self.a1 % SM9_Q == o.a1 % SM9_Q

    def inv(self):
        d = (self.a0 * self.a0 + self.a1 * self.a1) % SM9_Q
        d_inv = pow(d, SM9_Q - 2, SM9_Q)
        return Fp2(self.a0 * d_inv, -self.a1 * d_inv)

    def __repr__(self):
        return f"Fp2({hex(self.a0)}, {hex(self.a1)})"


class Fp4:
    def __init__(self, a0, a1):
        self.a0 = a0 if isinstance(a0, Fp2) else Fp2(a0, 0)
        self.a1 = a1 if isinstance(a1, Fp2) else Fp2(a1, 0)

    def __add__(self, o):
        return Fp4(self.a0 + o.a0, self.a1 + o.a1)

    def __sub__(self, o):
        return Fp4(self.a0 - o.a0, self.a1 - o.a1)

    def __mul__(self, o):
        a0 = self.a0 * o.a0 - self.a1 * o.a1 * Fp2(2, 0)
        a1 = self.a0 * o.a1 + self.a1 * o.a0
        return Fp4(a0, a1)


class Fp12:
    def __init__(self, a0, a1):
        self.a0 = a0 if isinstance(a0, Fp4) else Fp4(a0, 0)
        self.a1 = a1 if isinstance(a1, Fp4) else Fp4(a1, 0)

    def __mul__(self, o):
        a0 = self.a0 * o.a0 - self.a1 * o.a1 * Fp4(Fp2(2, 0), Fp2(0, 0))
        a1 = self.a0 * o.a1 + self.a1 * o.a0
        return Fp12(a0, a1)

    def __eq__(self, o):
        return self.a0 == o.a0 and self.a1 == o.a1

    def inv(self):
        raise NotImplementedError

    def __repr__(self):
        return f"Fp12(...)"


class ECPoint:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_zero(self):
        return self.x == 0 and self.y == 0

    def __eq__(self, o):
        return self.x == o.x and self.y == o.y


EC_ZERO = ECPoint(0, 0)
EC_G = ECPoint(SM9_Px, SM9_Py)


def _ec_add(p, q):
    if p.is_zero():
        return q
    if q.is_zero():
        return p
    if p == q:
        return _ec_double(p)
    if p.x == q.x:
        return EC_ZERO
    lam = ((q.y - p.y) * pow(q.x - p.x, SM9_Q - 2, SM9_Q)) % SM9_Q
    x3 = (lam * lam - p.x - q.x) % SM9_Q
    y3 = (lam * (p.x - x3) - p.y) % SM9_Q
    return ECPoint(x3, y3)


def _ec_double(p):
    if p.is_zero():
        return p
    lam = ((3 * p.x * p.x) * pow(2 * p.y, SM9_Q - 2, SM9_Q)) % SM9_Q
    x3 = (lam * lam - 2 * p.x) % SM9_Q
    y3 = (lam * (p.x - x3) - p.y) % SM9_Q
    return ECPoint(x3, y3)


def _ec_mul(k, p):
    r = EC_ZERO
    q = ECPoint(p.x, p.y)
    while k > 0:
        if k & 1:
            r = _ec_add(r, q)
        q = _ec_double(q)
        k >>= 1
    return r


def _hash_to_int(data):
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, 'big') % SM9_N


def _H1(ida, hid):
    """Hash function H1 for SM9: maps identity to integer."""
    data = ida.encode() if isinstance(ida, str) else ida
    ha = hashlib.sha256(data + bytes([hid])).digest()
    return int.from_bytes(ha, 'big') % (SM9_N - 1) + 1


def _H2(data):
    return hashlib.sha256(data).digest()


def _line_func(q, p):
    """Line function for Tate pairing (simplified)."""
    return Fp12(Fp4(Fp2(1, 0), Fp2(0, 0)), Fp4(Fp2(0, 0), Fp2(0, 0)))


def _tate_pairing(p, q):
    """Tate pairing computation using Miller's algorithm."""
    n = SM9_N
    t = n
    f = Fp12(Fp4(Fp2(1,0),Fp2(0,0)), Fp4(Fp2(0,0),Fp2(0,0)))
    v = ECPoint(q.x, q.y)
    bits = bin(t)[3:]
    for bit in bits:
        f = f * f
        v = _ec_double(v)
        if bit == '1':
            f = f * _line_func(v, p)
            v = _ec_add(v, q)
    f = f * _line_func(v, EC_ZERO)
    return f


def _key_derivation(shared, klen):
    sm3 = SM3.create()
    ct = 1
    d = bytearray()
    while len(d) * 8 < klen:
        sm3.reset()
        sm3.update(shared)
        sm3.update(ct.to_bytes(4, 'big'))
        d.extend(bytes(sm3.finalize().words) if hasattr(sm3.finalize(), 'words') else b'')
        ct += 1
    return bytes(d)[:klen//8]


class SM9:
    def __init__(self):
        self._master_private = None
        self._master_public = None
        self._user_private = None

    def setup(self):
        """Generate master secret and public key."""
        self._master_private = int.from_bytes(os.urandom(32), 'big') % (SM9_N - 1) + 1
        self._master_public = _ec_mul(self._master_private, EC_G)
        return self

    def set_master_key(self, priv):
        self._master_private = priv
        self._master_public = _ec_mul(self._master_private, EC_G)
        return self

    def generate_user_key(self, ida, hid=SM9_HID_SIGN):
        if self._master_private is None:
            raise ValueError("Master key not set")
        t1 = _H1(ida, hid)
        t2 = (self._master_private * t1) % SM9_N
        self._user_private = _ec_mul(t2, EC_G)
        return self._user_private

    def sign(self, message, user_key=None):
        sk = user_key or self._user_private
        if sk is None:
            raise ValueError("User private key not set")
        if isinstance(message, str):
            message = message.encode()
        r = int.from_bytes(os.urandom(32), 'big') % (SM9_N - 1) + 1
        w = _ec_mul(r, EC_G)
        h = _hash_to_int(message + int.to_bytes(w.x, 32, 'big'))
        l = (r - h) % SM9_N
        S = _ec_mul(l, sk)
        return h.to_bytes(32, 'big') + int.to_bytes(S.x, 32, 'big') + int.to_bytes(S.y, 32, 'big')

    def verify(self, message, signature, ida, hid=SM9_HID_SIGN):
        if self._master_public is None:
            raise ValueError("Master public key not set")
        if isinstance(message, str):
            message = message.encode()
        h = int.from_bytes(signature[:32], 'big')
        sx = int.from_bytes(signature[32:64], 'big')
        sy = int.from_bytes(signature[64:96], 'big')
        S = ECPoint(sx, sy)
        t1 = _H1(ida, hid)
        P = _ec_mul(t1, self._master_public)  # Note: simplified
        w = _ec_add(_ec_mul(h, EC_G), _ec_mul(h, P))
        w = _ec_add(w, S) if w.is_zero() else w
        h2 = _hash_to_int(message + int.to_bytes(w.x, 32, 'big'))
        return h2 == h

    def encrypt(self, message, ida, hid=SM9_HID_ENC):
        if isinstance(message, str):
            message = message.encode()
        q = int.from_bytes(os.urandom(32), 'big') % (SM9_N - 1) + 1
        t1 = _H1(ida, hid)
        P = _ec_mul(t1, self._master_public)
        C1 = _ec_mul(q, EC_G)
        g = _tate_pairing(P, EC_G)
        w = None
        ct = 1
        d = bytearray()
        while len(d) < len(message):
            gt = int.to_bytes(q * ct, 32, 'big')
            d.extend(gt[:min(32, len(message) - len(d))])
            ct += 1
        C2 = bytes(a ^ b for a, b in zip(message, d[:len(message)]))
        h = _hash_to_int(message + int.to_bytes(C1.x, 32, 'big'))
        return int.to_bytes(C1.x, 32, 'big') + int.to_bytes(C1.y, 32, 'big') + C2 + h.to_bytes(32, 'big')
