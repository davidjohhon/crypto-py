"""
sm9.py — SM9 identity-based cryptography (GM/T 0044-2016).

Full implementation of SM9 identity-based signature scheme with
R-ate pairing over BN curves, ported from GmSSL.

References:
  - GmSSL: https://github.com/guanzhi/GmSSL (sm9_z256.c)
  - GM/T 0044-2016: Identity-Based Cryptographic Algorithms SM9

Tower extension:
  Fp² = Fp[u] / (u² + 2)
  Fp⁴ = Fp²[v] / (v² - u)
  Fp¹² = Fp⁴[w] / (w³ - v)
"""

import os
import struct

from CryptoPy.core import WordArray
from CryptoPy.sm3 import SM3 as _SM3


# ─── BN curve parameters (SM9 standard curve) ───────────────

SM9_P = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
SM9_N = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
SM9_B = 5  # Weierstrass coefficient for E/Fp: y² = x³ + b


# ─── Integer helpers ────────────────────────────────────────

def _mod_inv(a, m=SM9_P):
    """Modular inverse using Fermat's little theorem."""
    return pow(a, m - 2, m)


def _int_to(x, n=32):
    """Encode integer as big-endian bytes."""
    return x.to_bytes(n, 'big')


def _int_from(b):
    """Decode big-endian bytes as integer."""
    return int.from_bytes(b, 'big')


def _to_wa(data):
    """Convert bytes to WordArray."""
    words = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        if len(chunk) < 4:
            chunk += b'\x00' * (4 - len(chunk))
        words.append(int.from_bytes(chunk, 'big'))
    return WordArray.create(words, len(data))


def _wa_key(data):
    """Accept WordArray or bytes/str, return bytes."""
    if isinstance(data, WordArray):
        result = bytearray()
        for i in range(data.sigBytes):
            word_idx = i // 4
            byte_idx = 3 - (i % 4)
            if word_idx < len(data.words):
                result.append((data.words[word_idx] >> (byte_idx * 8)) & 0xff)
        return bytes(result)
    if isinstance(data, str):
        return bytes.fromhex(data)
    return data


# ═══════════════════════════════════════════════════════════════
# Extension field tower: Fp² → Fp⁴ → Fp¹²
# ═══════════════════════════════════════════════════════════════

# ─── Fp² = Fp[u] / (u² + 2) ─────────────────────────────────

class Fp2:
    """Quadratic extension Fp[u]/(u² + 2).  u² = -2."""

    def __init__(self, a0=0, a1=0):
        self.a0 = a0 % SM9_P
        self.a1 = a1 % SM9_P

    def __add__(self, o):
        if isinstance(o, int): o = Fp2(o, 0)
        return Fp2(self.a0 + o.a0, self.a1 + o.a1)

    def __sub__(self, o):
        if isinstance(o, int): o = Fp2(o, 0)
        return Fp2(self.a0 - o.a0, self.a1 - o.a1)

    def __mul__(self, o):
        if isinstance(o, int):
            return Fp2(self.a0 * o, self.a1 * o)
        # (a0 + a1·u)(b0 + b1·u) = (a0·b0 - 2·a1·b1) + (a0·b1 + a1·b0)·u
        return Fp2(self.a0 * o.a0 - 2 * self.a1 * o.a1,
                    self.a0 * o.a1 + self.a1 * o.a0)

    def __neg__(self):
        return Fp2(-self.a0, -self.a1)

    def __eq__(self, o):
        return self.a0 % SM9_P == o.a0 % SM9_P and self.a1 % SM9_P == o.a1 % SM9_P

    def inv(self):
        """(a0 + a1·u)⁻¹ = (a0 - a1·u) / (a0² + 2·a1²)"""
        d = _mod_inv(self.a0 * self.a0 + 2 * self.a1 * self.a1)
        return Fp2(self.a0 * d, -self.a1 * d)

    def is_zero(self):
        return self.a0 % SM9_P == 0 and self.a1 % SM9_P == 0


# ─── Fp² helper functions ────────────────────────────────────

def _fp2_conj(a):
    """Conjugate in Fp²: a0 + a1·u → a0 - a1·u."""
    return Fp2(a.a0, -a.a1)


def _fp2_mul_u(a, b):
    """(a · b) · u  over Fp², used in MulV / SqrV."""
    a0b0 = a.a0 * b.a0
    a1b1 = a.a1 * b.a1
    cross = a.a0 * b.a1 + a.a1 * b.a0
    return Fp2(-2 * cross, a0b0 - 2 * a1b1)


def _fp2_sqr_u(a):
    """a² · u  over Fp², used in SqrV."""
    t0 = a.a0 * a.a1
    t1 = a.a0 - a.a1 - a.a1
    t2 = (a.a0 + a.a1) * t1
    return Fp2(-4 * t0, t2 + t0)


def _fp2_a_mul_u(a):
    """a · u  over Fp² (single-argument variant)."""
    return Fp2(-2 * a.a1, a.a0)


def _fp2_mul_fp(a, k):
    """Multiply Fp² element by a base field scalar (component-wise)."""
    return Fp2(a.a0 * k, a.a1 * k)


# ─── Fp⁴ = Fp²[v] / (v² - u) ─────────────────────────────────

class Fp4:
    """Quadratic extension Fp²[v]/(v² - u).  v² = u."""

    def __init__(self, a0=None, a1=None):
        self.a0 = a0 if isinstance(a0, Fp2) else Fp2(a0, 0)
        self.a1 = a1 if isinstance(a1, Fp2) else Fp2(a1, 0)

    def __add__(self, o):
        return Fp4(self.a0 + o.a0, self.a1 + o.a1)

    def __sub__(self, o):
        return Fp4(self.a0 - o.a0, self.a1 - o.a1)

    def __mul__(self, o):
        if isinstance(o, int):
            return Fp4(self.a0 * o, self.a1 * o)
        # (a0 + a1·v)(b0 + b1·v) = (a0·b0 + a1·b1·u) + (a0·b1 + a1·b0)·v
        a0 = self.a0 * o.a0 + self.a1 * o.a1 * Fp2(0, 1)
        a1 = self.a0 * o.a1 + self.a1 * o.a0
        return Fp4(a0, a1)

    def __neg__(self):
        return Fp4(-self.a0, -self.a1)

    def __eq__(self, o):
        return self.a0 == o.a0 and self.a1 == o.a1

    def is_zero(self):
        return self.a0.is_zero() and self.a1.is_zero()

    def inv(self):
        """(a + b·v)⁻¹ = (a - b·v) / (a² - b²·u)"""
        a, b = self.a0, self.a1
        t = (a * a - b * b * Fp2(0, 1)).inv()
        return Fp4(a * t, -b * t)


# ─── Fp⁴ helper functions ────────────────────────────────────

def _fp4_conj(a):
    """Conjugate in Fp⁴: a0 + a1·v → a0 - a1·v."""
    return Fp4(a.a0, -a.a1)


def _fp4_frobenius(a, beta):
    """Frobenius on Fp⁴: (a0 + a1·v)^p = a0̄ + β·a1̄·v."""
    return Fp4(_fp2_conj(a.a0), _fp2_mul_fp(_fp2_conj(a.a1), beta.a0))


def _fp4_mul_v(a, b):
    """(a · b) · v  over Fp⁴, used in Fp¹² multiplication."""
    r0 = _fp2_mul_u(a.a0, b.a1) + _fp2_mul_u(a.a1, b.a0)
    r1 = a.a0 * b.a0 + _fp2_mul_u(a.a1, b.a1)
    return Fp4(r0, r1)


def _fp4_sqr_v(a):
    """a² · v  over Fp⁴, used in Fp¹² squaring."""
    t0 = _fp2_mul_u(a.a0, a.a1)
    t0 = t0 + t0
    t1 = a.a0 * a.a0 + _fp2_sqr_u(a.a1)
    return Fp4(t0, t1)


def _fp4_a_mul_v(a):
    """a · v  over Fp⁴ (single-argument)."""
    return Fp4(_fp2_a_mul_u(a.a1), a.a0)


def _fp4_mul_fp(a, k):
    """Multiply Fp⁴ by a base field scalar."""
    return Fp4(_fp2_mul_fp(a.a0, k), _fp2_mul_fp(a.a1, k))


# ─── Fp¹² = Fp⁴[w] / (w³ - v) ────────────────────────────────

def _get_v():
    """The constant v ∈ Fp⁴, used in Fp¹² operations."""
    return Fp4(Fp2(0, 0), Fp2(1, 0))


class Fp12:
    """Cubic extension Fp⁴[w]/(w³ - v).  w³ = v."""

    def __init__(self, a0=None, a1=None, a2=None):
        self.a0 = a0 if isinstance(a0, Fp4) else Fp4(a0, 0)
        self.a1 = a1 if isinstance(a1, Fp4) else Fp4(a1, 0)
        self.a2 = a2 if isinstance(a2, Fp4) else Fp4(a2, 0)

    def __add__(self, o):
        return Fp12(self.a0 + o.a0, self.a1 + o.a1, self.a2 + o.a2)

    def __sub__(self, o):
        return Fp12(self.a0 - o.a0, self.a1 - o.a1, self.a2 - o.a2)

    def __mul__(self, o):
        if isinstance(o, int):
            return Fp12(self.a0 * o, self.a1 * o, self.a2 * o)
        a0, a1, a2 = self.a0, self.a1, self.a2
        b0, b1, b2 = o.a0, o.a1, o.a2
        v = _get_v()
        # (a0 + a1·w + a2·w²)(b0 + b1·w + b2·w²), with w³ = v, w⁴ = v·w
        t0 = a0 * b0 + (a1 * b2 + a2 * b1) * v
        t1 = a0 * b1 + a1 * b0 + (a2 * b2) * v
        t2 = a0 * b2 + a1 * b1 + a2 * b0
        return Fp12(t0, t1, t2)

    def __eq__(self, o):
        return self.a0 == o.a0 and self.a1 == o.a1 and self.a2 == o.a2

    def is_one(self):
        return (self.a0 == Fp4(Fp2(1, 0), Fp2(0, 0)) and
                self.a1.is_zero() and self.a2.is_zero())

    def inv(self):
        """Fp¹² multiplicative inverse (GmSSL formula)."""
        if self.a2.is_zero():
            # Specialised formula when a2 = 0 (fewer operations)
            k = self.a0 * self.a0 * self.a0
            t2 = _fp4_sqr_v(self.a1) * self.a1
            k = k + t2
            k = k.inv()
            r0 = self.a0 * self.a0 * k
            r1 = self.a0 * self.a1 * k
            r1 = -r1
            r2 = self.a1 * self.a1 * k
            return Fp12(r0, r1, r2)
        # General case
        a0, a1, a2 = self.a0, self.a1, self.a2
        v = _get_v()
        t0 = a1 * a1 - a0 * a2
        t1 = a0 * a1 - _fp4_sqr_v(a2)
        t2 = a0 * a0 - a1 * a2 * v
        t3 = a2 * (t1 * t1 - t0 * t2).inv()
        return Fp12(t2 * t3, -(t1 * t3), t0 * t3)

    def sqr(self):
        """Fp¹² squaring (GmSSL formula)."""
        a0, a1, a2 = self.a0, self.a1, self.a2
        v = _get_v()
        r0 = a0 * a0 + (a1 * a2 + a1 * a2) * v
        r1 = a0 * a1 + a0 * a1 + a2 * a2 * v
        r2 = a0 * a2 + a0 * a2 + a1 * a1
        return Fp12(r0, r1, r2)

    def conjugate(self):
        """Fp¹² conjugate mapping to satisfy the pairing final-exponentiation."""
        a0 = _fp4_conj(self.a0)
        a1 = -self.a1 if self.a1.is_zero() else Fp4(-self.a1.a0, -self.a1.a1)
        a2 = -self.a2 if self.a2.is_zero() else Fp4(-self.a2.a0, -self.a2.a1)
        return Fp12(a0, a1, a2)


def _fp12_pow(x, e):
    """Modular exponentiation in Fp¹² by square-and-multiply."""
    r = Fp12(Fp4(Fp2(1, 0), Fp2(0, 0)),
             Fp4(Fp2(0, 0), Fp2(0, 0)),
             Fp4(Fp2(0, 0), Fp2(0, 0)))
    while e > 0:
        if e & 1:
            r = r * x
        x = x.sqr()
        e >>= 1
    return r


# ─── Frobenius endomorphism ──────────────────────────────────
#
# For the BN curve with embedding degree k = 12,
# Frobenius constants αᵢ = w^{(i·(p-1))/k} satisfy:
#   πⁱ(f) = (a⁰ + βⁱ·a¹·w + α₂ⁱ·a²·w²) for i ∈ {1,2,3,6,12}
#
# These are the regular-form values from GmSSL.

_beta_val = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
_FP2_BETA = Fp2(_beta_val, 0)

_ALPHA1 = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b
_ALPHA2 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
_ALPHA3 = _beta_val
_ALPHA4 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333
_ALPHA5 = 0x2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686


def _fp12_frobenius(f, k=1):
    """Frobenius endomorphism π^k on Fp¹² (k ∈ {1,2,3,6,12})."""
    if k == 0:
        return f

    # k ≡ 0 mod 6: relies on conjugate / negation (cheap)
    if k % 6 == 0:
        a0 = _fp4_conj(f.a0)
        a1 = -_fp4_conj(f.a1)
        a2 = _fp4_conj(f.a2)
        if k % 12 == 0:
            a0 = _fp4_conj(a0)
            a1 = -_fp4_conj(a1)
            a2 = _fp4_conj(a2)
        return Fp12(a0, a1, a2)

    if k == 1:
        xa0, xa1 = f.a0.a0, f.a0.a1
        xb0, xb1 = f.a1.a0, f.a1.a1
        xc0, xc1 = f.a2.a0, f.a2.a1
        ra = Fp4(_fp2_conj(xa0),
                 _fp2_mul_fp(_fp2_conj(xa1), _ALPHA3))
        rb = Fp4(_fp2_mul_fp(_fp2_conj(xb0), _ALPHA1),
                 _fp2_mul_fp(_fp2_conj(xb1), _ALPHA4))
        rc = Fp4(_fp2_mul_fp(_fp2_conj(xc0), _ALPHA2),
                 _fp2_mul_fp(_fp2_conj(xc1), _ALPHA5))
        return Fp12(ra, rb, rc)

    if k == 2:
        a = _fp4_conj(f.a0)
        b = _fp4_mul_fp(_fp4_conj(f.a1), _ALPHA2)
        c = _fp4_mul_fp(_fp4_conj(f.a2), _ALPHA4)
        return Fp12(a, b, c)

    if k == 3:
        xa0, xa1 = f.a0.a0, f.a0.a1
        xb0, xb1 = f.a1.a0, f.a1.a1
        xc0, xc1 = f.a2.a0, f.a2.a1
        ra = Fp4(_fp2_conj(xa0),
                 _fp2_conj(xa1) * _FP2_BETA * Fp2(-1, 0))
        rb = Fp4(_fp2_conj(xb0) * _FP2_BETA,
                 _fp2_conj(xb1))
        rc = Fp4(-_fp2_conj(xc0),
                 _fp2_conj(xc1) * _FP2_BETA)
        return Fp12(ra, rb, rc)

    # Fallback: compose from π¹
    return _fp12_frobenius(_fp12_frobenius(f, k - 1), 1)


# ─── Sparse line multiplication ──────────────────────────────
#
# A line function L = lw[0] + lw[1]·w² + lw[2]·w³ (with w³ = v)
# is represented in Fp¹² as (Fp4(lw[0],lw[2]), 0, Fp4(lw[1],0)).
# This multiplies it into an existing Fp¹² accumulator without
# full Fp¹² multiply, exploiting the zero Fp⁴ component.

def _fp12_line_mul(r, lw):
    """Sparse multiply: r × (lw[0] + lw[1]·w² + lw[2]·v)."""
    a0, a1, a2 = r.a0, r.a1, r.a2
    lw4 = Fp4(lw[0], lw[2])
    r0 = a0 * lw4
    r1 = a1 * lw4
    r2 = a2 * lw4
    # lw[1]·w² contribution
    t = a0.a0 * lw[1]; r2 = Fp4(r2.a0 + t, r2.a1)          # → r2.a0
    t = a0.a1 * lw[1]; r2 = Fp4(r2.a0, r2.a1 + t)          # → r2.a1
    t = a1.a0 * lw[1]; r0 = Fp4(r0.a0, r0.a1 + t)          # → r0.a1
    t = _fp2_a_mul_u(a1.a1 * lw[1]); r0 = Fp4(r0.a0 + t, r0.a1)  # → r0.a0
    t = a2.a0 * lw[1]; r1 = Fp4(r1.a0, r1.a1 + t)          # → r1.a1
    t = _fp2_a_mul_u(a2.a1 * lw[1]); r1 = Fp4(r1.a0 + t, r1.a1)  # → r1.a0
    return Fp12(r0, r1, r2)


# ═══════════════════════════════════════════════════════════════
# Elliptic curve groups
# ═══════════════════════════════════════════════════════════════

# ─── G₁: curve over Fp ─────────────────────────────────────

class _Point:
    """Affine point on E/Fp: y² = x³ + b."""

    def __init__(self, x, y):
        self.x = x % SM9_P
        self.y = y % SM9_P

    def is_zero(self):
        return self.x == 0 and self.y == 0

    def __eq__(self, o):
        return self.x == o.x and self.y == o.y


_ZERO = _Point(0, 0)

# Generator P₁ of G₁ (regular form, from GmSSL)
_G = _Point(
    0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD,
    0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616,
)


def _ec_add(p, q):
    """Point addition on E/Fp (affine)."""
    if p.is_zero(): return q
    if q.is_zero(): return p
    if p == q:      return _ec_dbl(p)
    if p.x == q.x:  return _ZERO
    lam = (q.y - p.y) * _mod_inv(q.x - p.x) % SM9_P
    x3 = (lam * lam - p.x - q.x) % SM9_P
    y3 = (lam * (p.x - x3) - p.y) % SM9_P
    return _Point(x3, y3)


def _ec_dbl(p):
    """Point doubling on E/Fp (affine)."""
    if p.is_zero(): return p
    lam = (3 * p.x * p.x) * _mod_inv(2 * p.y) % SM9_P
    x3 = (lam * lam - 2 * p.x) % SM9_P
    y3 = (lam * (p.x - x3) - p.y) % SM9_P
    return _Point(x3, y3)


def _ec_mul(k, p):
    """Scalar multiplication on E/Fp (double-and-add)."""
    r, q = _ZERO, _Point(p.x, p.y)
    while k > 0:
        if k & 1: r = _ec_add(r, q)
        q, k = _ec_dbl(q), k >> 1
    return r


# ─── G₂: twisted curve over Fp² ───────────────────────────

class _Point2:
    """Projective point on the sextic twist E'/Fp²: y² = x³ + b'."""

    def __init__(self, x=None, y=None, z=None):
        self.x = x if isinstance(x, Fp2) else Fp2(x, 0)
        self.y = y if isinstance(y, Fp2) else Fp2(y, 0)
        self.z = z if isinstance(z, Fp2) else Fp2(1, 0) if z is None else Fp2(z, 0)

    def is_zero(self):
        return self.x.is_zero() and self.y.is_zero() and self.z.is_zero()

    def is_infinity(self):
        return self.z.is_zero()

    def __eq__(self, o):
        return self.x == o.x and self.y == o.y and self.z == o.z


# Point at infinity for G₂
_2ZERO = _Point2(Fp2(0, 0), Fp2(1, 0), Fp2(0, 0))

# Generator P₂ of G₂ (regular form, from GmSSL)
_G2 = _Point2(
    Fp2(0x3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B,
        0x85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141),
    Fp2(0xA7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7,
        0x17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96),
    Fp2(1, 0),
)


def _ec2_dbl(p):
    """Point doubling on E'/Fp² (projective, GmSSL formula)."""
    if p.is_infinity(): return p
    X1, Y1, Z1 = p.x, p.y, p.z
    T2 = X1 * X1
    T2 = T2 + T2 + T2
    Y3 = Y1 + Y1
    Z3 = Y3 * Z1
    Y3 = Y3 * Y3
    T3 = Y3 * X1
    Y3 = Y3 * Y3
    # Halving  (Y3/2) in regular form: ensure even before integer divide
    h0, h1 = Y3.a0, Y3.a1
    if h0 & 1: h0 += SM9_P
    if h1 & 1: h1 += SM9_P
    Y3 = Fp2(h0 // 2, h1 // 2)
    T1 = T3 + T3
    X3 = T2 * T2
    X3 = X3 - T1
    T1 = T3 - X3
    T1 = T1 * T2
    Y3 = T1 - Y3
    return _Point2(X3, Y3, Z3)


def _ec2_add(p, q):
    """Point addition on E'/Fp² (projective, GmSSL formula)."""
    if p.is_infinity(): return q
    if q.is_infinity(): return p
    X1, Y1, Z1 = p.x, p.y, p.z
    X2, Y2, Z2 = q.x, q.y, q.z
    if X1 == X2 and Y1 == Y2 and Z1 == Z2:
        return _ec2_dbl(p)
    T1 = Z1 * Z1
    T2 = Z2 * Z2
    U1 = X1 * T2
    U2 = X2 * T1
    S1 = Y1 * T2 * Z2
    S2 = Y2 * T1 * Z1
    H = U2 - U1
    I = H + H
    I = I * I
    J = H * I
    r = S2 - S1
    r = r + r
    V = U1 * I
    X3 = r * r - J - V - V
    Y3 = r * (V - X3) - S1 * J - S1 * J
    Z3 = ((Z1 + Z2) * (Z1 + Z2) - T1 - T2) * H
    return _Point2(X3, Y3, Z3)


def _ec2_neg(p):
    """Point negation on E'/Fp²."""
    return _Point2(p.x, -p.y, p.z)


def _ec2_mul(k, p):
    """Scalar multiplication on E'/Fp² (double-and-add)."""
    r, q = _2ZERO, _Point2(p.x, p.y, p.z)
    while k > 0:
        if k & 1: r = _ec2_add(r, q)
        q, k = _ec2_dbl(q), k >> 1
    return r


def _ec2_to_affine(p):
    """Convert projective point to affine on E'/Fp²."""
    if p.is_infinity():
        return _Point2(Fp2(0, 0), Fp2(0, 0), Fp2(0, 0))
    z_inv = p.z.inv()
    x = p.x * z_inv * z_inv       # X / Z²
    y = p.y * z_inv * z_inv * z_inv  # Y / Z³
    return _Point2(x, y, Fp2(1, 0))


# ─── Twist Frobenius operations ─────────────────────────────
#
# π(P) = (conj(x), conj(y), α₁·conj(z))  where α₁ = u^((p-1)/2)
# π²(P) = (x, y, α₂·z)

def _twist_pi1(p):
    """Twist Frobenius π¹ for the R-ate pairing final steps."""
    c = 0x3F23EA58E5720BDB843C6CFA9C08674947C5C86E0DDD04EDA91D8354377B698B
    return _Point2(_fp2_conj(p.x), _fp2_conj(p.y),
                   _fp2_mul_fp(_fp2_conj(p.z), c))


def _twist_pi2(p):
    """Twist Frobenius π²."""
    c = 0xF300000002A3A6F2780272354F8B78F4D5FC11967BE65334
    return _Point2(p.x, p.y, _fp2_mul_fp(p.z, c))


def _twist_neg_pi2(p):
    """Twist Frobenius π² with y-negation."""
    c = 0xF300000002A3A6F2780272354F8B78F4D5FC11967BE65334
    return _Point2(p.x, -p.y, _fp2_mul_fp(p.z, c))


# ═══════════════════════════════════════════════════════════════
# Miller loop line functions
# ═══════════════════════════════════════════════════════════════
#
# The line value L = lw[0] + lw[1]·w² + lw[2]·w³ is the divisor
# function l_{T,Q}(P₁) evaluated at the G₁ affine point.
# The tangent/line functions return both the line coefficients and
# the updated point R.

def _eval_g_tangent(P, Q):
    """Tangent line at P on E'/Fp², evaluated at Q ∈ G₁.  Returns (R=2P, lw0, lw1, lw2)."""
    X1, Y1, Z1 = P.x, P.y, P.z
    T1 = Z1 * Z1                      # Z1²
    A = X1 * X1                       # X1²
    B = Y1 * Y1                       # Y1²
    C = B * B                         # Y1⁴
    D = X1 + B
    D = D * D - A - C                  # 2·X1·Y1²
    D = D + D                         # 4·X1·Y1²
    Z3 = Y1 + Z1
    Z3 = Z3 * Z3 - B - T1             # 2·Y1·Z1
    lw0 = B + B + B + B + A           # 4·Y1² + X1²
    A = A + A + A                     # 3·X1²
    B = A * A                         # 9·X1⁴
    X3 = D + D                        # 8·X1·Y1²
    X3 = B - X3                       # 9·X1⁴ - 8·X1·Y1²
    lw0 = lw0 + B                     # 4·Y1² + X1² + 9·X1⁴
    Y3 = D - X3                       # 4·X1·Y1² - X3
    Y3 = Y3 * A                       # (4·X1·Y1² - X3)·3·X1²
    C = C * 8                         # 8·Y1⁴
    Y3 = Y3 - C
    lw2 = Z3 * T1                     # 2·Y1·Z1³
    lw2 = lw2 + lw2                   # 4·Y1·Z1³
    lw1 = A * T1                      # 3·X1²·Z1²
    lw1 = lw1 + lw1                   # 6·X1²·Z1²
    lw1 = -lw1                        # -6·X1²·Z1²
    A = X1 + A
    A = A * A - lw0                   # 6·X1³ - 4·Y1²
    lw0 = A
    lw1 = lw1 * Q.x
    lw2 = lw2 * Q.y
    return _Point2(X3, Y3, Z3), lw0, lw1, lw2


def _eval_g_line(P, T, Q, pre=None):
    """Line through P and T on E'/Fp², evaluated at Q ∈ G₁.
    Returns (R=P+T, lw0, lw1, lw2)."""
    if pre is None:
        # Auto-compute pre when not provided (e.g. for pi-Q points)
        pre = [T.y * T.y,
               T.z * T.z * T.z,
               T.z * T.z * T.z * Q.y * Fp2(2, 0),
               T.z * T.z * T.z * Q.x * Fp2(-2, 0),
               T.x * T.z * Fp2(2, 0)]
    X1, Y1, Z1 = P.x, P.y, P.z
    X2, Y2, Z2 = T.x, T.y, T.z
    T1 = Z1 * Z1                                  # Z1²
    T2 = Z2 * Z2                                  # Z2²
    Z3 = Z1 + Z2
    Z3 = Z3 * Z3 - T1 - T2                        # 2·Z1·Z2
    A = X1 * T2                                   # X1·Z2²
    B = X2 * T1                                   # X2·Z1²
    C = Y1 * pre[1]
    C = C + C                                     # 2·Y1·Z_T³
    D = Y2 + Z1
    D = D * D - pre[0] - T1
    D = D * T1                                    # 2·Y2·Z1³
    B = B - A                                     # H = X2·Z1² - X1·Z2²
    Z3 = Z3 * B                                   # new Z = 2·Z1·Z2·H
    T1 = B + B
    T1 = T1 * T1                                  # 4·H²
    X3 = B * T1                                   # 4·H³
    Y3 = C * X3                                   # 8·Y1·Z_T³·H³
    A = A * T1                                    # 4·X1·Z2²·H²
    T2 = A + A                                    # 8·X1·Z2²·H²
    B = D - C                                     # r = 2·Y2·Z1³ - 2·Y1·Z_T³
    T1 = B * B                                    # r²
    X3 = T1 - X3 - T2                             # r² - 4·H³ - 8·X1·Z2²·H²
    T2 = A - X3
    T2 = T2 * B                                   # (4·X1·Z2²·H² - X3)·r
    Y3 = T2 - Y3
    lw2 = Z3 * pre[2]
    lw1 = B * pre[3]
    B = B * pre[4]
    lw0 = Y2 * Z3 + Y2 * Z3
    lw0 = B - lw0
    return _Point2(X3, Y3, Z3), lw0, lw1, lw2


# ═══════════════════════════════════════════════════════════════
# R-ate pairing
# ═══════════════════════════════════════════════════════════════
#
# e(P₁, Q₂) = f_{6t+2, Q₂}(P₁)^{(p¹²-1)/N}
#
# The Miller loop iterates over the non-adjacent-form (NAF) bits
# of 6t+2, where t is the BN curve parameter.  Digit '1' adds Q₂,
# digit '2' adds -Q₂ (subtracts).
#
# abits = NAF(6x+2) for BN parameter x = -0x600000000058F98A

def _rate_pairing(P, Q):
    """R-ate pairing e(P, Q): G₁ × G₂ → G_T."""
    if P.is_zero() or Q.is_zero() or Q.is_infinity():
        return Fp12(Fp4(Fp2(1, 0), Fp2(0, 0)),
                     Fp4(Fp2(0, 0), Fp2(0, 0)),
                     Fp4(Fp2(0, 0), Fp2(0, 0)))
    abits = "00100000000000000000000000000000000000010000101100020200101000020"

    T = _Point2(Q.x, Q.y, Q.z)
    Q_neg = _ec2_neg(Q)

    # Embed G₁ affine point into Fp²
    P_affine = _ec2_to_affine(_Point2(Fp2(P.x, 0), Fp2(P.y, 0)))

    # Precomputed values from fixed Q for line evaluation
    Qz3 = Q.z * Q.z * Q.z
    pre = [
        Q.y * Q.y,                                                               # pre[0]: Y_Q²
        Qz3,                                                                     # pre[1]: Z_Q³
        Fp2(Qz3.a0 * 2 * P_affine.y.a0 % SM9_P, Qz3.a1 * 2 * P_affine.y.a0 % SM9_P),  # pre[2]: 2·Z_Q³·y_P
        Fp2(Qz3.a0 * -2 * P_affine.x.a0 % SM9_P, Qz3.a1 * -2 * P_affine.x.a0 % SM9_P), # pre[3]: -2·Z_Q³·x_P
        Q.x * Q.z * Fp2(2, 0),                                                   # pre[4]: 2·X_Q·Z_Q
    ]

    r = Fp12(Fp4(Fp2(1, 0), Fp2(0, 0)),
             Fp4(Fp2(0, 0), Fp2(0, 0)),
             Fp4(Fp2(0, 0), Fp2(0, 0)))

    for c in abits:
        r = r.sqr()
        T, lw0, lw1, lw2 = _eval_g_tangent(T, P_affine)
        r = _fp12_line_mul(r, (lw0, lw1, lw2))

        if c == '1':
            T, lw0, lw1, lw2 = _eval_g_line(T, Q, P_affine, pre)
            r = _fp12_line_mul(r, (lw0, lw1, lw2))
        elif c == '2':
            T, lw0, lw1, lw2 = _eval_g_line(T, Q_neg, P_affine, pre)
            r = _fp12_line_mul(r, (lw0, lw1, lw2))

    # Final two line evaluations with Frobenius-twisted Q
    Q1 = _twist_pi1(Q)
    Q2 = _twist_neg_pi2(Q)

    T, lw0, lw1, lw2 = _eval_g_line(T, Q1, P_affine)
    r = _fp12_line_mul(r, (lw0, lw1, lw2))
    T, lw0, lw1, lw2 = _eval_g_line(T, Q2, P_affine)
    r = _fp12_line_mul(r, (lw0, lw1, lw2))

    return _final_exponent(r)


# ─── Final exponentiation ────────────────────────────────────
#
# f → f^{(p¹²-1)/N}  to map the Miller-loop output into G_T.
#
# Decomposed as: (p⁶-1)·(p²+1)·(p⁴-p²+1)/N
#   = "easy part" · "hard part"
#
# BN parameter x yields exponents:
#   a2 = (6x+2)³ / (6x+2)₃  = 0xD8000000019062ED0000B98B0CB27659
#   a3 = 6x+2                = 0x2400000000215D941

def _final_exponent(f):
    """Final exponentiation: f → f^{(p¹²-1)/N}."""
    # Easy part
    t0 = _fp12_frobenius(f, 6)     # f^{p⁶}
    t1 = f.inv()
    t0 = t0 * t1                   # f^{p⁶-1}
    t1 = _fp12_frobenius(t0, 2)    # f^{(p⁶-1)·p²}
    t0 = t0 * t1                   # f^{(p⁶-1)·(p²+1)}
    # Hard part
    return _hard_part(t0)


def _hard_part(f):
    """Hard part of final exponentiation: f^{(p⁴-p²+1)/N}."""
    # BN curve parameter decomposition
    a2 = 0xD8000000019062ED0000B98B0CB27659
    a3 = 0x2400000000215D941

    t0 = _fp12_pow(f, a3)
    t0 = t0.inv()
    t1 = _fp12_frobenius(t0)
    t1 = t0 * t1
    t0 = t0 * t1
    t2 = _fp12_frobenius(f)
    t3 = t2 * f
    t3 = _fp12_pow(t3, 9)
    t0 = t0 * t3
    t3 = f.sqr()
    t3 = t3.sqr()
    t0 = t0 * t3
    t2 = t2.sqr()
    t2 = t2 * t1
    t1 = _fp12_frobenius(f, 2)
    t1 = t1 * t2
    t2 = _fp12_pow(t1, a2)
    t0 = t2 * t0
    t1 = _fp12_frobenius(f, 3)
    t1 = t1 * t0
    return t1


# ═══════════════════════════════════════════════════════════════
# SM9 helper functions
# ═══════════════════════════════════════════════════════════════

def _sm3_words(data):
    """Convert bytes to CryptoPy.WordArray for SM3 hashing."""
    words = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        if len(chunk) < 4:
            chunk = chunk + b'\x00' * (4 - len(chunk))
        words.append(int.from_bytes(chunk, 'big'))
    return WordArray.create(words, len(data))


def _sm3_hash(data):
    """Compute SM3 hash of bytes, return WordArray."""
    h = _SM3.create()
    h.update(data)
    return h.finalize()


def _hash1(ida, hid):
    """H1 per GM/T 0044-2016 §5.4.2.2.

    ha = SM3(0x01 || IDA || hid || 0x00000001) ||
         SM3(0x01 || IDA || hid || 0x00000002)
    h1 = (ha mod (N-1)) + 1
    """
    if isinstance(ida, str):
        ida = ida.encode()

    msg1 = bytes([0x01]) + ida + bytes([hid]) + struct.pack('>I', 1)
    msg2 = bytes([0x01]) + ida + bytes([hid]) + struct.pack('>I', 2)

    ha1 = _sm3_hash(_sm3_words(msg1))
    ha2 = _sm3_hash(_sm3_words(msg2))
    ha_bytes = (b''.join(w.to_bytes(4, 'big') for w in ha1.words[:8]) +
                b''.join(w.to_bytes(4, 'big') for w in ha2.words[:8]))
    ha40 = int.from_bytes(ha_bytes[:40], 'big')
    return (ha40 % (SM9_N - 1)) + 1


def _hash2(msg, w_bytes):
    """H2 per GM/T 0044-2016 §5.4.2.3.

    ha = SM3(msg || w || 0x00000001) ||
         SM3(msg || w || 0x00000002)
    h2 = (ha mod (N-1)) + 1
    """
    if isinstance(msg, str):
        msg = msg.encode()

    z = msg + w_bytes
    ha1 = _sm3_hash(_sm3_words(z + struct.pack('>I', 1)))
    ha2 = _sm3_hash(_sm3_words(z + struct.pack('>I', 2)))
    ha_bytes = (b''.join(w.to_bytes(4, 'big') for w in ha1.words[:8]) +
                b''.join(w.to_bytes(4, 'big') for w in ha2.words[:8]))
    ha40 = int.from_bytes(ha_bytes[:40], 'big')
    return (ha40 % (SM9_N - 1)) + 1


def _fp12_to_bytes(f):
    """Serialize Fp¹² element to 384 bytes (GmSSL order)."""
    parts = [f.a2.a1.a1, f.a2.a1.a0, f.a2.a0.a1, f.a2.a0.a0,
             f.a1.a1.a1, f.a1.a1.a0, f.a1.a0.a1, f.a1.a0.a0,
             f.a0.a1.a1, f.a0.a1.a0, f.a0.a0.a1, f.a0.a0.a0]
    return b''.join(_int_to(v) for v in parts)


# ═══════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════

def setup():
    """Generate master secret key and master public key.

    msk ← random ∈ [1, N-1]
    mpk = [msk]·P₂  (on G₂)

    Returns:
        (mpk_wa, msk_wa) as WordArrays.
        mpk is 128 bytes (affine G₂), msk is 32 bytes (scalar).
        Use .toString() for hex.
    """
    msk = _int_from(os.urandom(32)) % (SM9_N - 1) + 1
    mpk = _ec2_to_affine(_ec2_mul(msk, _G2))
    mpk_bytes = (_int_to(mpk.x.a0) + _int_to(mpk.x.a1) +
                 _int_to(mpk.y.a0) + _int_to(mpk.y.a1))
    return (_to_wa(mpk_bytes), _to_wa(_int_to(msk)))


def generate_user_key(master_secret_key, identity, hid=0x01):
    """Generate user signing key d_s on G₁.

    t₁ = H1(IDA || hid)
    t₂ = msk · (msk + t₁)⁻¹  mod N
    usk = [t₂]·P₁  (on G₁)

    Returns WordArray (192 bytes):
        usk.x || usk.y || mpk.x.a0 || mpk.x.a1 || mpk.y.a0 || mpk.y.a1.
    """
    msk = _int_from(_wa_key(master_secret_key))
    t1 = _hash1(identity, hid)
    if (msk + t1) % SM9_N == 0:
        raise ValueError("Master key + H1(ID) == 0 mod N, regenerate master key")
    t2 = msk * pow((msk + t1) % SM9_N, -1, SM9_N) % SM9_N
    usk = _ec_mul(t2, _G)
    mpk = _ec2_to_affine(_ec2_mul(msk, _G2))
    mpk_bytes = (_int_to(mpk.x.a0) + _int_to(mpk.x.a1) +
                 _int_to(mpk.y.a0) + _int_to(mpk.y.a1))
    return _to_wa(_int_to(usk.x) + _int_to(usk.y) + mpk_bytes)


def sign(message, user_key):
    """SM9 digital signature generation.

    Returns WordArray (96 bytes: h || S.x || S.y).
    Use .toString() for hex.

    user_key: WordArray or bytes (192 bytes: usk || mpk from generate_user_key).

    g = e(P₁, mpk)
    r ← random ∈ [1, N-1]
    w = gʳ
    h = H2(M || w)
    l = (r - h) mod N
    S = [l]·usk

    Returns 96-byte signature: h || S.x || S.y.
    """
    if isinstance(message, str):
        message = message.encode()
    user_key = _wa_key(user_key)

    usk = _Point(_int_from(user_key[:32]),
                  _int_from(user_key[32:64]))

    mpk = _Point2(
        Fp2(_int_from(user_key[64:96]),
            _int_from(user_key[96:128])),
        Fp2(_int_from(user_key[128:160]),
            _int_from(user_key[160:192])))

    g = _rate_pairing(_G, mpk)

    r = _int_from(os.urandom(32)) % (SM9_N - 1) + 1
    w = _fp12_pow(g, r)

    h = _hash2(message, _fp12_to_bytes(w))

    l = (r - h) % SM9_N
    S = _ec_mul(l, usk)
    return _to_wa(_int_to(h) + _int_to(S.x) + _int_to(S.y))


def verify(message, signature, master_public_key, identity, hid=0x01):
    """SM9 signature verification.

    signature: WordArray or bytes (96 bytes: h || S.x || S.y).
    Master public key: WordArray or bytes (128 bytes, affine G₂ from setup).

    h₁ = H1(IDA || hid)
    g  = e(P₁, mpk)
    t  = gʰ
    Q  = [h₁]·P₂ + mpk
    w' = t · e(S, Q)
    h₂ = H2(M || w')

    Returns True iff h₂ == h (the h extracted from signature).
    """
    if isinstance(message, str):
        message = message.encode()

    signature = _wa_key(signature)
    mpk_bytes = _wa_key(master_public_key)

    mpk = _Point2(
        Fp2(_int_from(mpk_bytes[0:32]),
            _int_from(mpk_bytes[32:64])),
        Fp2(_int_from(mpk_bytes[64:96]),
            _int_from(mpk_bytes[96:128])))

    h = _int_from(signature[:32])
    sx, sy = _int_from(signature[32:64]), _int_from(signature[64:96])
    S = _Point(sx, sy)

    if S.is_zero() or (S.y * S.y - (S.x * S.x * S.x + SM9_B)) % SM9_P != 0:
        return False

    h1 = _hash1(identity, hid)

    g = _rate_pairing(_G, mpk)
    t = _fp12_pow(g, h)

    P2_h1 = _ec2_mul(h1, _G2)
    Q = _ec2_add(P2_h1, mpk)

    e_S_Q = _rate_pairing(S, Q)

    w = t * e_S_Q

    h2 = _hash2(message, _fp12_to_bytes(w))
    return h2 == h
