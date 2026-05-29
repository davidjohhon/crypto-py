"""
sm2.py — SM2 public key cryptography (GM/T 0003-2012).

Elliptic curve over Fp (256-bit SM2 curve).
"""

import os
from CryptoPy.core import WordArray
from CryptoPy.sm3 import SM3 as _SM3


SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
_DEFAULT_ID = b"1234567812345678"


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


def _to_wa(data):
    """Convert bytes to WordArray (4 bytes per 32-bit word)."""
    words = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        if len(chunk) < 4:
            chunk += b'\x00' * (4 - len(chunk))
        words.append(int.from_bytes(chunk, 'big'))
    return WordArray.create(words, len(data))

def _wa_to_bytes(wa):
    """Convert WordArray to bytes."""
    result = bytearray()
    for i in range(wa.sigBytes):
        word_idx = i // 4
        byte_idx = 3 - (i % 4)
        if word_idx < len(wa.words):
            result.append((wa.words[word_idx] >> (byte_idx * 8)) & 0xff)
    return bytes(result)


def _to_key(data):
    """Accept WordArray or bytes, return bytes."""
    if isinstance(data, WordArray):
        return _wa_to_bytes(data)
    if isinstance(data, str):
        return bytes.fromhex(data)
    return data


def _hash(data):
    """SM3 hash of bytes -> int."""
    h = _SM3.create()
    h.update(_to_wa(data))
    return int(h.finalize().toString(), 16)


def _za(ida, pub_x, pub_y):
    """Compute ZA per GM/T 0003-2012 §5.3.
    ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
    """
    entla = len(ida) * 8
    return _hash(
        entla.to_bytes(2, 'big') +
        ida +
        _int_to(SM2_A) +
        _int_to(SM2_B) +
        _int_to(SM2_GX) +
        _int_to(SM2_GY) +
        _int_to(pub_x) +
        _int_to(pub_y)
    )


def _hash_msg(msg, xa=None, ya=None, ida=None):
    """SM3(ZA || M) for SM2 sign/verify, SM3(M) otherwise."""
    if xa is not None and ya is not None:
        if ida is None:
            ida = _DEFAULT_ID
        return _hash(_int_to(_za(ida, xa, ya)) + msg)
    return _hash(msg)


def _kdf(z, klen):
    d, ct = bytearray(), 1
    while len(d) * 8 < klen:
        h = _hash(z + ct.to_bytes(4, 'big'))
        d.extend(h.to_bytes(32, 'big'))
        ct += 1
    return bytes(d)[:klen // 8]


def generate_keypair():
    """Generate SM2 key pair.
    
    Returns (private_key_wa, public_key_wa) as WordArrays.
    Use .toString() for hex.
    """
    d = _int_from(os.urandom(32)) % (SM2_N - 1) + 1
    Q = _mul(d, _G)
    return _to_wa(_int_to(d)), _to_wa(_int_to(Q.x) + _int_to(Q.y))


def sign(message, private_key, ida=None):
    """SM2 digital signature (GM/T 0003-2012 §6.1).
    
    Returns WordArray (64 bytes: r || s).
    Use .toString() for hex, .toString(enc.Base64) for base64.
    """
    if isinstance(message, str):
        message = message.encode()
    private_key = _to_key(private_key)
    d = _int_from(private_key)
    
    # Compute ZA
    pk = _mul(d, _Point(SM2_GX, SM2_GY))
    za = _za(ida or _DEFAULT_ID, pk.x, pk.y)
    
    e = _hash_msg(message, pk.x, pk.y, ida or _DEFAULT_ID)
    
    while True:
        k = _int_from(os.urandom(32)) % (SM2_N - 1) + 1
        p = _mul(k, _Point(SM2_GX, SM2_GY))
        r = (e + p.x) % SM2_N
        if r == 0 or r + k == SM2_N:
            continue
        s = _mod_inv(1 + d, SM2_N) * (k - r * d) % SM2_N
        if s != 0:
            break
    return _to_wa(_int_to(r) + _int_to(s))


def verify(message, signature, public_key, ida=None):
    """Verify an SM2 signature. Returns True/False.
    
    signature: WordArray or bytes (64-byte r || s).
    public_key: WordArray or bytes (64 bytes: Q.x || Q.y).
    ida: optional user identity bytes (default: b'1234567812345678').
    """
    if isinstance(message, str):
        message = message.encode()
    signature = _to_key(signature)
    public_key = _to_key(public_key)
    r, s = _int_from(signature[:32]), _int_from(signature[32:])
    if not (1 <= r < SM2_N and 1 <= s < SM2_N):
        return False
    t = (r + s) % SM2_N
    if t == 0:
        return False
    P = _Point(_int_from(public_key[:32]), _int_from(public_key[32:]))
    e = _hash_msg(message, P.x, P.y, ida)
    gs = _mul(s, _G)
    tp = _mul(t, P)
    p = _add(gs, tp)
    return (e + p.x) % SM2_N == r


def encrypt(message, public_key):
    """Encrypt a message with SM2 public key.
    
    Returns WordArray (ciphertext).
    """
    if isinstance(message, str):
        message = message.encode()
    public_key = _to_key(public_key)
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
    c3 = _int_to(_hash(x2 + message + y2), 32)
    # gmssl-compatible: C1 || C2 || C3 ordering (gm.decrypt reads C1||C2||C3)
    return _to_wa(_int_to(c1.x) + _int_to(c1.y) + c2 + c3)


def decrypt(ciphertext, private_key):
    """Decrypt a ciphertext with SM2 private key.
    
    ciphertext: WordArray or bytes.
    Returns bytes (decrypted message).
    """
    ciphertext = _to_key(ciphertext)
    private_key = _to_key(private_key)
    d = _int_from(private_key)
    cx = _int_from(ciphertext[:32])
    cy = _int_from(ciphertext[32:64])
    c2 = ciphertext[64:-32]
    c3 = ciphertext[-32:]
    p = _mul(d, _Point(cx, cy))
    x2, y2 = _int_to(p.x), _int_to(p.y)
    t = _kdf(x2 + y2, len(c2) * 8)
    m = bytes(a ^ b for a, b in zip(c2, t))
    u = _int_to(_hash(x2 + m + y2), 32)
    if u != c3:
        raise ValueError("SM2 decrypt: invalid ciphertext")
    return m
