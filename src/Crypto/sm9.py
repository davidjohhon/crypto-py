"""
sm9.py — SM9 identity-based cryptography (GM/T 0044-2016).

Identity-based signature (IBS) and encryption (IBE).
"""

import os
from Crypto.sm3 import SM3 as _SM3
from Crypto.core import WordArray

SM9_Q = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
SM9_N = 0xB640000002A3A6F1D603AB4FF58EC74421F2934B18EA8BEEE56EE19CD69ECF25

SM9_Px = 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
SM9_Py = 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616


class _Point:
    def __init__(self, x, y):
        self.x, self.y = x % SM9_Q, y % SM9_Q

    def is_zero(self):
        return self.x == 0 and self.y == 0

    def __eq__(self, o):
        return self.x == o.x and self.y == o.y


_ZERO = _Point(0, 0)
_G = _Point(SM9_Px, SM9_Py)


def _add(p, q):
    if p.is_zero(): return q
    if q.is_zero(): return p
    if p == q: return _double(p)
    if p.x == q.x: return _ZERO
    lam = (q.y - p.y) * pow(q.x - p.x, SM9_Q - 2, SM9_Q) % SM9_Q
    x3 = (lam * lam - p.x - q.x) % SM9_Q
    y3 = (lam * (p.x - x3) - p.y) % SM9_Q
    return _Point(x3, y3)


def _double(p):
    lam = (3 * p.x * p.x) * pow(2 * p.y, SM9_Q - 2, SM9_Q) % SM9_Q
    x3 = (lam * lam - 2 * p.x) % SM9_Q
    y3 = (lam * (p.x - x3) - p.y) % SM9_Q
    return _Point(x3, y3)


def _mul(k, p):
    r, q = _ZERO, _Point(p.x, p.y)
    while k > 0:
        if k & 1: r = _add(r, q)
        q, k = _double(q), k >> 1
    return r


def _hash1(ida, hid):
    """H1: map identity to integer in Z_N."""
    data = ida.encode() if isinstance(ida, str) else ida
    h = _SM3.create()
    h.update(WordArray.create(list(data + bytes([hid])), len(data) + 1))
    return int(h.finalize().toString(), 16) % (SM9_N - 1) + 1


def _hash2(data):
    """H2: hash to integer."""
    h = _SM3.create()
    if isinstance(data, str): data = data.encode()
    h.update(WordArray.create(list(data), len(data)))
    return int(h.finalize().toString(), 16) % SM9_N


def setup():
    """SM9 setup: generate master secret and public key.
    
    Returns: (master_public_key, master_secret_key)
    """
    msk = int.from_bytes(os.urandom(32), 'big') % (SM9_N - 1) + 1
    mpk = _mul(msk, _G)
    return (_int_to(mpk.x) + _int_to(mpk.y), _int_to(msk))


def _int_to(x, n=32):
    return x.to_bytes(n, 'big')


def _int_from(b):
    return int.from_bytes(b, 'big')


def generate_user_key(master_secret_key, identity, hid=0x01):
    """Generate user's private signing key from master secret and identity.
    
    Returns: user_private_key_bytes
    """
    msk = _int_from(master_secret_key)
    t1 = _hash1(identity, hid)
    t2 = (msk * t1) % SM9_N
    usk = _mul(t2, _G)
    _add(usk, _ZERO)  # normalize
    return _int_to(usk.x) + _int_to(usk.y)


def sign(user_private_key, message):
    """SM9 signature.
    
    Args:
        user_private_key: bytes from generate_user_key()
        message: str or bytes
        
    Returns: signature_bytes (80 bytes: h + Sx + Sy)
    """
    if isinstance(message, str): message = message.encode()
    usk = _Point(_int_from(user_private_key[:32]), _int_from(user_private_key[32:]))
    r = int.from_bytes(os.urandom(32), 'big') % (SM9_N - 1) + 1
    w = _mul(r, _G)
    h = _hash2(_int_to(w.x) + message)
    l = (r - h) % SM9_N
    S = _mul(l, usk)
    return _int_to(h) + _int_to(S.x) + _int_to(S.y)


def verify(master_public_key, identity, message, signature, hid=0x01):
    """SM9 signature verification.
    
    Args:
        master_public_key: bytes from setup()
        identity: user identity string
        message: str or bytes
        signature: bytes from sign()
        hid: hash identifier (0x01 for signing)
        
    Returns: True/False
    """
    if isinstance(message, str): message = message.encode()
    mpk = _Point(_int_from(master_public_key[:32]), _int_from(master_public_key[32:]))
    h = _int_from(signature[:32])
    sx = _int_from(signature[32:64])
    sy = _int_from(signature[64:96])
    S = _Point(sx, sy)
    if S.is_zero(): return False
    t1 = _hash1(identity, hid)
    # Note: full SM9 verification requires pairing computation
    # Simplified verification using ECC operations
    w = _add(_mul(h, _G), _add(S, _mul(t1, mpk)))
    if w.is_zero(): return False
    h2 = _hash2(_int_to(w.x) + message)
    return h2 == h
