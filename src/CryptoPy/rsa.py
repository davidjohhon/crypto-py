"""
rsa.py — RSA public key cryptography (PKCS#1 v1.5).

Pure Python implementation with zero external dependencies.
Ported from python-rsa (https://github.com/sybrenstuvel/python-rsa).

Supports:
  - Key generation (Miller-Rabin primality testing)
  - Encryption / decryption (PKCS#1 v1.5)
  - Digital signature / verification (PKCS#1 v1.5)
  - Chinese Remainder Theorem for fast decryption
"""

import os, struct

from CryptoPy.core import WordArray
from CryptoPy.md5 import MD5 as _MD5
from CryptoPy.sha1 import SHA1 as _SHA1
from CryptoPy.sha256 import SHA256 as _SHA256
from CryptoPy.sha384 import SHA384 as _SHA384
from CryptoPy.sha512 import SHA512 as _SHA512

DEFAULT_EXPONENT = 65537

# ASN.1 DigestInfo prefixes for hash algorithms
_HASH_ASN1 = {
    "MD5":     b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
    "SHA-1":   b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
    "SHA-256": b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    "SHA-384": b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    "SHA-512": b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

_HASH_FUNCS = {
    "MD5": lambda d: str(_MD5.create().finalize(_to_wa(d))),
    "SHA-1": lambda d: str(_SHA1.create().finalize(_to_wa(d))),
    "SHA-256": lambda d: str(_SHA256.create().finalize(_to_wa(d))),
    "SHA-384": lambda d: str(_SHA384.create().finalize(_to_wa(d))),
    "SHA-512": lambda d: str(_SHA512.create().finalize(_to_wa(d))),
}


def _to_wa(data):
    words = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        if len(chunk) < 4:
            chunk += b'\x00' * (4 - len(chunk))
        words.append(int.from_bytes(chunk, 'big'))
    return WordArray.create(words, len(data))


# ─── Integer helpers ───────────────────────────────────────

def _int_from(b):
    return int.from_bytes(b, 'big')


def _wa_key(data):
    """Accept WordArray, bytes, or str(hex); return bytes."""
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


def _int_to(x, n=None):
    if n is None:
        n = (x.bit_length() + 7) // 8
    return x.to_bytes(max(n, 1), 'big')


def _byte_size(n):
    if n == 0:
        return 1
    return (n.bit_length() + 7) // 8


def _mod_inverse(a, m):
    """Extended Euclidean algorithm for modular inverse."""
    x0, x1 = 0, 1
    orig_m = m
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += orig_m
    return x1


# ─── Miller-Rabin primality ───────────────────────────────

def _miller_rabin(n, k):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = _int_from(os.urandom((n.bit_length() + 7) // 8)) % (n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False
    return True


def _is_prime(n):
    if n < 10:
        return n in (2, 3, 5, 7)
    if n % 2 == 0:
        return False
    b = n.bit_length()
    if b >= 1536:  rounds = 3
    elif b >= 1024: rounds = 4
    elif b >= 512:  rounds = 7
    else:           rounds = 10
    return _miller_rabin(n, rounds + 1)


def _get_prime(nbits):
    while True:
        p = _int_from(os.urandom((nbits + 7) // 8)) | (1 << (nbits - 1)) | 1
        if _is_prime(p):
            return p


# ─── Key generation ───────────────────────────────────────

def generate_keypair(nbits=2048):
    """Generate an RSA key pair.

    Returns (private_key_wa, public_key_wa) as WordArrays.
    Use .toString() for hex.
    """
    if nbits < 512:
        raise ValueError("Key size must be at least 512 bits")

    e = DEFAULT_EXPONENT
    key_bytes = (nbits + 7) // 8

    while True:
        shift = nbits // 16
        p = _get_prime(nbits // 2 + shift)
        q = _get_prime(nbits // 2 - shift)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        n = p * q
        if n.bit_length() != nbits:
            p = _get_prime(nbits // 2 + shift)
            continue
        phi = (p - 1) * (q - 1)
        try:
            d = _mod_inverse(e, phi)
        except Exception:
            continue
        if (e * d) % phi == 1:
            break

    exp1 = d % (p - 1)
    exp2 = d % (q - 1)
    coef = _mod_inverse(q, p)

    half = max(_byte_size(p), _byte_size(q))
    pub = struct.pack('>H', nbits) + _int_to(n, key_bytes) + _int_to(e, key_bytes)
    priv = (struct.pack('>H', nbits) + _int_to(n, key_bytes) + _int_to(e, key_bytes) +
            _int_to(d, key_bytes) + _int_to(p, half) + _int_to(q, half) +
            _int_to(exp1, half) + _int_to(exp2, half) + _int_to(coef, half))
    return _to_wa(priv), _to_wa(pub)


def _key_from(pub_bytes):
    """Parse public key bytes → (n, e)."""
    nbits = struct.unpack('>H', pub_bytes[:2])[0]
    ks = (nbits + 7) // 8
    n = _int_from(pub_bytes[2:2 + ks])
    e = _int_from(pub_bytes[2 + ks:2 + ks * 2])
    return n, e


def _privkey_from(priv_bytes):
    """Parse private key bytes → (n, e, d, p, q, exp1, exp2, coef)."""
    nbits = struct.unpack('>H', priv_bytes[:2])[0]
    ks = (nbits + 7) // 8
    off = 2
    n = _int_from(priv_bytes[off:off + ks]); off += ks
    e = _int_from(priv_bytes[off:off + ks]); off += ks
    d = _int_from(priv_bytes[off:off + ks]); off += ks
    half = (len(priv_bytes) - off) // 5
    p = _int_from(priv_bytes[off:off + half]); off += half
    q = _int_from(priv_bytes[off:off + half]); off += half
    exp1 = _int_from(priv_bytes[off:off + half]); off += half
    exp2 = _int_from(priv_bytes[off:off + half]); off += half
    coef = _int_from(priv_bytes[off:off + half])
    return n, e, d, p, q, exp1, exp2, coef


# ─── PKCS#1 v1.5 padding ──────────────────────────────────

def _pad_encrypt(message, target_length):
    ml = len(message)
    if ml > target_length - 11:
        raise OverflowError("Message too long (%d > %d)" % (ml, target_length - 11))
    pl = target_length - ml - 3
    padding = b''
    while len(padding) < pl:
        pad = os.urandom(pl - len(padding) + 5)
        pad = pad.replace(b'\x00', b'')
        padding += pad[:pl - len(padding)]
    return b'\x00\x02' + padding + b'\x00' + message


def _pad_sign(message, target_length):
    ml = len(message)
    if ml > target_length - 11:
        raise OverflowError("DigestInfo too long")
    pl = target_length - ml - 3
    return b'\x00\x01' + (b'\xff' * pl) + b'\x00' + message


# ─── Core RSA operations ──────────────────────────────────

def _encrypt_int(m, e, n):
    return pow(m, e, n)


def _decrypt_int_fast(c, p, q, exp1, exp2, coef):
    m1 = pow(c, exp1, p)  # m mod p
    m2 = pow(c, exp2, q)  # m mod q
    h = ((m1 - m2) * coef) % p
    return m2 + h * q


# ─── Public API ───────────────────────────────────────────

def encrypt(message, public_key):
    """RSA PKCS#1 v1.5 encryption.
    
    message: str, bytes, or WordArray.
    Returns WordArray (ciphertext).
    """
    if isinstance(message, str):
        message = message.encode()
    elif isinstance(message, WordArray):
        message = _wa_key(message)
    n, e = _key_from(_wa_key(public_key))
    keylength = _byte_size(n)
    padded = _pad_encrypt(message, keylength)
    m = _int_from(padded)
    c = _encrypt_int(m, e, n)
    return _to_wa(_int_to(c, keylength))


def decrypt(ciphertext, private_key):
    """RSA PKCS#1 v1.5 decryption with CRT.
    
    Returns bytes (decrypted message).
    """
    ciphertext = _wa_key(ciphertext)
    n, e, d, p, q, exp1, exp2, coef = _privkey_from(_wa_key(private_key))
    keylength = _byte_size(n)
    if len(ciphertext) > keylength:
        raise ValueError("Ciphertext too long")
    c = _int_from(ciphertext)
    m = _decrypt_int_fast(c, p, q, exp1, exp2, coef)
    cleartext = _int_to(m, keylength)
    if cleartext[:2] != b'\x00\x02':
        raise ValueError("Decryption failed")
    sep = cleartext.find(b'\x00', 2)
    if sep < 10:
        raise ValueError("Decryption failed")
    return cleartext[sep + 1:]


def _compute_hash(message, method_name):
    if method_name not in _HASH_ASN1:
        raise ValueError("Unknown hash method: %s" % method_name)
    data = message if isinstance(message, bytes) else message.encode()
    return bytes.fromhex(_HASH_FUNCS[method_name](data))


def sign(message, private_key, hash_method="SHA-256"):
    """RSA PKCS#1 v1.5 detached signature.
    
    Returns WordArray (signature).
    hash_method: CryptoPy.hash.SHA256, "SHA-256", "SHA-1", "MD5", etc.
    """
    if isinstance(message, str):
        message = message.encode()
    n, e, d, p, q, exp1, exp2, coef = _privkey_from(_wa_key(private_key))
    keylength = _byte_size(n)
    msg_hash = _compute_hash(message, hash_method)
    asn1code = _HASH_ASN1[hash_method]
    digest_info = asn1code + msg_hash
    padded = _pad_sign(digest_info, keylength)
    m = _int_from(padded)
    s = _decrypt_int_fast(m, p, q, exp1, exp2, coef)
    return _to_wa(_int_to(s, keylength))


def verify(message, signature, public_key):
    """RSA PKCS#1 v1.5 signature verification.
    
    Returns True if valid, raises ValueError otherwise.
    """
    if isinstance(message, str):
        message = message.encode()
    signature = _wa_key(signature)
    n, e = _key_from(_wa_key(public_key))
    keylength = _byte_size(n)
    if len(signature) != keylength:
        raise ValueError("Verification failed: wrong signature length")
    s = _int_from(signature)
    m = _encrypt_int(s, e, n)
    clearsig = _int_to(m, keylength)
    method_name = None
    for name, prefix in _HASH_ASN1.items():
        if prefix in clearsig:
            method_name = name
            break
    if method_name is None:
        raise ValueError("Verification failed: unknown hash")
    msg_hash = _compute_hash(message, method_name)
    expected = _pad_sign(_HASH_ASN1[method_name] + msg_hash, keylength)
    if expected != clearsig:
        raise ValueError("Verification failed: signature mismatch")
    return True
