"""Additional bounded crypto primitives used by competition triage."""
import base64
import hashlib
import math
import re

from .common import iroot, long_to_bytes, invmod


def crt(pairs):
    total = 0
    modulus = math.prod(int(n) for _, n in pairs)
    for value, part in pairs:
        part = int(part)
        total += int(value) * (modulus // part) * pow(modulus // part, -1, part)
    return total % modulus


def rsa_broadcast(pairs, exponent=None):
    """Håstad broadcast for coprime moduli and identical small exponent."""
    if not pairs:
        return None
    e = int(exponent or pairs[0][1])
    chosen = [(int(n), int(c)) for n, pe, c in pairs if int(pe) == e]
    if len(chosen) < e:
        return None
    for start in range(len(chosen) - e + 1):
        subset = chosen[start:start + e]
        if any(math.gcd(subset[i][0], subset[j][0]) != 1
               for i in range(e) for j in range(i)):
            continue
        value = crt([(c, n) for n, c in subset])
        root = iroot(value, e)
        if root ** e == value:
            return root
    return None


def rsa_common_modulus(c1, c2, e1, e2, n):
    """Recover same RSA plaintext under coprime exponents."""
    e1, e2, n = int(e1), int(e2), int(n)
    g, a, b = _xgcd(e1, e2)
    if g != 1:
        return None
    try:
        left = pow(invmod(int(c1), n), -a, n) if a < 0 else pow(int(c1), a, n)
        right = pow(invmod(int(c2), n), -b, n) if b < 0 else pow(int(c2), b, n)
    except (ValueError, TypeError):
        return None
    return (left * right) % n


def _xgcd(a, b):
    if not b:
        return a, 1, 0
    g, x, y = _xgcd(b, a % b)
    return g, y, x - (a // b) * y


def detect_hash_candidates(value):
    """Return likely digest algorithms without claiming ambiguous formats."""
    value = str(value).strip()
    size = len(value.lstrip("*"))
    candidates = []
    by_size = {8: ("crc32",), 16: ("md5-half", "mysql323"),
               32: ("md5", "md4", "ntlm"), 40: ("sha1", "ripemd160"),
               56: ("sha224",), 64: ("sha256", "sha3-256"),
               96: ("sha384",), 128: ("sha512", "sha3-512")}
    if re.fullmatch(r"\*?[0-9a-fA-F]+", value):
        candidates.extend(by_size.get(size, ()))
    return candidates


def hash_word_candidates(word):
    """Small deterministic mutation set for fast local hash triage."""
    base = str(word)
    values = {base, base.lower(), base.upper(), base.capitalize(), base[::-1]}
    values.update(base + suffix for suffix in ("1", "123", "!", "2024", "2025", "2026"))
    values.add(base.replace("a", "4").replace("e", "3").replace("i", "1").replace("o", "0"))
    return sorted(values)


def digest_matches(password, digest):
    raw = str(password).encode("utf-8", "replace")
    target = str(digest).lower().lstrip("*")
    functions = {
        32: (hashlib.md5,),
        40: (hashlib.sha1,),
        56: (hashlib.sha224,),
        64: (hashlib.sha256, hashlib.sha3_256),
        96: (hashlib.sha384,),
        128: (hashlib.sha512, hashlib.sha3_512),
    }.get(len(target), ())
    for fn in functions:
        if fn(raw).hexdigest() == target:
            return fn.__name__
    return None
