"""Verified RSA helpers for hard CTF artifacts.

The ordinary RSA ladder covers small-e, Wiener, Fermat and factoring.  Hard
challenges often leak a CRT component instead (``dp``/``dq``/``qinv``), use a
multi-prime modulus, or ship a signature rather than a ciphertext.  This
module keeps those paths small and deterministic: every recovered key is
checked against the supplied RSA equations before it is returned.
"""
import hashlib
import math

from .common import iroot, long_to_bytes, strip_zeros


def _int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip().replace("_", "")
        try:
            return int(value, 0)
        except ValueError:
            try:
                return int(value, 16) if value and all(
                    c in "0123456789abcdefABCDEF" for c in value) else None
            except ValueError:
                return None
    return None


def _valid_factor(p, n):
    return p is not None and 1 < p < n and n % p == 0


def recover_factor_from_crt_exponent(n, e, dp, *, bases=(2, 3, 5, 7, 11, 13)):
    """Recover ``p`` when the CRT exponent ``dp = d mod (p-1)`` leaked.

    Since ``g**(e*dp) == g (mod p)``, ``gcd(g**(e*dp)-g, n)`` reveals p for
    almost any small g.  The result is returned only when both factors are
    non-trivial and their RSA relation is consistent.
    """
    try:
        n, e, dp = int(n), int(e), int(dp)
    except (TypeError, ValueError):
        return None
    if n <= 3 or e <= 1 or dp <= 0:
        return None
    exponent = e * dp
    for base in bases:
        try:
            factor = math.gcd(pow(int(base), exponent, n) - int(base), n)
        except (ValueError, ZeroDivisionError):
            continue
        if not _valid_factor(factor, n):
            continue
        q = n // factor
        # A CRT exponent must satisfy e*dp == 1 mod p-1.
        if (e * dp - 1) % (factor - 1) == 0:
            return min(factor, q), max(factor, q)
    return None


def recover_private_from_crt(n, e, *, dp=None, dq=None, p=None, q=None,
                             qinv=None):
    """Recover ``(d, p, q)`` from leaked CRT RSA values.

    ``dp``/``dq`` can factor the modulus independently.  If p and q are
    already supplied, the function also accepts qinv and verifies all values.
    """
    n, e = _int(n), _int(e)
    dp, dq, p, q, qinv = map(_int, (dp, dq, p, q, qinv))
    if not n or not e or n <= 3 or e <= 1:
        return None
    if p and q and p * q != n:
        return None
    if not p and dp:
        pair = recover_factor_from_crt_exponent(n, e, dp)
        if pair:
            p, q = pair
    if not p and dq:
        pair = recover_factor_from_crt_exponent(n, e, dq)
        if pair:
            p, q = pair
    if not p or not q or p * q != n:
        return None
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError:
        return None
    if dp is not None and d % (p - 1) != dp % (p - 1):
        return None
    if dq is not None and d % (q - 1) != dq % (q - 1):
        return None
    if qinv is not None and (qinv * q) % p != 1:
        # Some libraries call p^-1 mod q qinv.  Accept the alternate naming
        # only when the canonical relation is absent.
        if (qinv * p) % q != 1:
            return None
    return d, p, q


def decrypt_multi_prime(n, e, c, primes):
    """Decrypt an RSA ciphertext when all prime factors are supplied."""
    try:
        n, e, c = int(n), int(e), int(c)
        factors = [int(x) for x in primes]
    except (TypeError, ValueError):
        return None
    if len(factors) < 2 or any(x <= 1 for x in factors):
        return None
    product = 1
    phi = 1
    for factor in factors:
        product *= factor
        phi *= factor - 1
    if product != n or math.gcd(e, phi) != 1:
        return None
    try:
        d = pow(e, -1, phi)
        message = pow(c, d, n)
    except ValueError:
        return None
    if pow(message, e, n) != c % n:
        return None
    return strip_zeros(long_to_bytes(message))


_DIGEST_INFO = {
    "md5": bytes.fromhex("3020300c06082a864886f70d020505000410"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha224": bytes.fromhex("302d300d06096086480165030402040500041c"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def verify_pkcs1_v15_signature(message, signature, n, e, hash_name="sha256"):
    """Verify a strict RSA PKCS#1 v1.5 signature and return bool."""
    if isinstance(message, str):
        message = message.encode()
    if isinstance(signature, str):
        try:
            raw_signature = signature.strip()
            if raw_signature.lower().startswith("0x"):
                raw_signature = raw_signature[2:]
            signature = bytes.fromhex(raw_signature)
        except ValueError:
            return False
    try:
        n, e = int(n), int(e)
        sig = int.from_bytes(bytes(signature), "big")
        size = (n.bit_length() + 7) // 8
        encoded = pow(sig, e, n).to_bytes(size, "big")
    except (TypeError, ValueError, OverflowError):
        return False
    digest_info = _DIGEST_INFO.get(str(hash_name).lower())
    if digest_info is None:
        return False
    expected = digest_info + hashlib.new(str(hash_name).lower(), message).digest()
    return encoded == b"\x00\x01" + b"\xff" * (size - len(expected) - 3) + \
        b"\x00" + expected


def forge_pkcs1_v15_e3(message, n, hash_name="sha256"):
    """Return a *candidate* e=3 lax-PKCS#1 signature.

    This is useful for CTF verifiers that check only the prefix of the
    encoded message.  It deliberately returns ``None`` for strict verifiers;
    callers must use ``verify_pkcs1_v15_signature`` before reporting success.
    """
    if isinstance(message, str):
        message = message.encode()
    digest_info = _DIGEST_INFO.get(str(hash_name).lower())
    if digest_info is None:
        return None
    digest = digest_info + hashlib.new(str(hash_name).lower(), message).digest()
    size = (int(n).bit_length() + 7) // 8
    if size < len(digest) + 11:
        return None
    # Prefix-only verifiers accept a short FF run followed by the digest.  We
    # search the smallest cube whose bytes begin with that verifier prefix.
    prefix = int.from_bytes(b"\x00\x01\xff\xff\x00" + digest, "big")
    shift = 8 * max(0, size - len(b"\x00\x01\xff\xff\x00") - len(digest))
    target = prefix << shift
    root = iroot(target, 3)
    for candidate in range(max(0, root - 2), root + 4):
        encoded = pow(candidate, 3, int(n)).to_bytes(size, "big")
        if encoded.startswith(b"\x00\x01\xff\xff\x00" + digest):
            return candidate.to_bytes(size, "big")
    return None
