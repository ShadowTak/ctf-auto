"""Small, deterministic verification helpers for crypto findings.

These helpers never label heuristic plaintext as a flag. They validate
mathematical relationships or exact byte transformations so callers can attach
strong evidence to a result.
"""
import hashlib
import math


def rsa_roundtrip(message, e, d, n):
    """Verify RSA private exponent by encrypting/decrypting an integer."""
    m = int(message)
    if min(int(e), int(d), int(n)) < 0 or not 0 <= m < int(n):
        return False
    c = pow(m, int(e), int(n))
    return pow(c, int(d), int(n)) == m


def rsa_factorization(n, p, q):
    """Verify p*q == n and return a normalized evidence record."""
    n, p, q = int(n), int(p), int(q)
    valid = p > 1 and q > 1 and p * q == n
    return {"verified": valid, "n": n, "p": p, "q": q,
            "product": p * q if p > 0 and q > 0 else None}


def crt_recombine(residues, moduli):
    """Return CRT recombination only when moduli are pairwise coprime."""
    residues = [int(x) for x in residues]
    moduli = [int(x) for x in moduli]
    if len(residues) != len(moduli) or not residues:
        return None
    if any(m <= 1 for m in moduli):
        return None
    for i, left in enumerate(moduli):
        for right in moduli[i + 1:]:
            if math.gcd(left, right) != 1:
                return None
    total = math.prod(moduli)
    value = 0
    for residue, modulus in zip(residues, moduli):
        part = total // modulus
        value += residue * part * pow(part, -1, modulus)
    return value % total


def xor_roundtrip(ciphertext, key, plaintext):
    """Verify a repeating XOR candidate exactly."""
    ciphertext = bytes(ciphertext)
    key = bytes(key)
    plaintext = bytes(plaintext)
    if not key or len(ciphertext) != len(plaintext):
        return False
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext)) == plaintext


def digest_matches(value, digest, algorithm="sha256"):
    """Constant-time comparison of a candidate value to a hex digest."""
    try:
        actual = hashlib.new(algorithm, bytes(value)).hexdigest()
    except (ValueError, TypeError):
        return False
    return actual.lower() == str(digest).strip().lower()
