"""Finite-field math and Diffie-Hellman helpers for CTF artifacts.

All recovered discrete logs are verified before being returned. The module
uses SymPy when available for large composite-order groups and keeps bounded
BSGS/Pohlig-Hellman fallbacks for the stdlib-only path.
"""
import hashlib
import math


def crt(congruences):
    """Combine ``[(remainder, modulus), ...]``; reject inconsistent input."""
    x, modulus = 0, 1
    for remainder, part in congruences:
        remainder, part = int(remainder), int(part)
        if part <= 0:
            raise ValueError("CRT modulus must be positive")
        g = math.gcd(modulus, part)
        if (remainder - x) % g:
            raise ValueError("inconsistent CRT congruences")
        left, right = modulus // g, part // g
        step = ((remainder - x) // g * pow(left, -1, right)) % right
        x += modulus * step
        modulus *= right
        x %= modulus
    return x, modulus


def legendre_symbol(a, p):
    return 0 if a % p == 0 else (1 if pow(a, (p - 1) // 2, p) == 1 else -1)


def tonelli_shanks(a, p):
    """Return one square root of ``a mod p`` for odd prime p, or None."""
    a %= p
    if a == 0:
        return 0
    if p == 2:
        return a
    if legendre_symbol(a, p) != 1:
        return None
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, probe = 1, (t * t) % p
        while probe != 1:
            probe = probe * probe % p
            i += 1
            if i >= m:
                return None
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, b * b % p, t * b * b % p, r * b % p
    return r


def _factorint(n):
    try:
        from sympy import factorint
        return {int(k): int(v) for k, v in factorint(int(n)).items()}
    except Exception:
        factors = {}
        value, prime = int(n), 2
        while prime * prime <= value and prime <= 1_000_000:
            while value % prime == 0:
                factors[prime] = factors.get(prime, 0) + 1
                value //= prime
            prime = 3 if prime == 2 else prime + 2
        if value > 1:
            factors[value] = factors.get(value, 0) + 1
        return factors


def _normal_factors(factors):
    if factors is None:
        return None
    if isinstance(factors, dict):
        return {int(k): int(v) for k, v in factors.items()}
    out = {}
    for item in factors:
        if isinstance(item, (list, tuple)):
            prime, power = item[0], item[1]
        else:
            prime, power = item, 1
        out[int(prime)] = int(power)
    return out


def bsgs(g, h, p, order=None):
    """Solve ``g**x == h (mod p)`` with bounded baby-step giant-step."""
    g, h, p = int(g) % p, int(h) % p, int(p)
    order = int(order or (p - 1))
    if order <= 0 or order > 100_000_000:
        return None
    m = math.isqrt(order) + 1
    table, value = {}, 1
    for j in range(m):
        table.setdefault(value, j)
        value = value * g % p
    try:
        factor = pow(pow(g, m, p), -1, p)
    except ValueError:
        return None
    gamma = h
    for i in range(m + 1):
        j = table.get(gamma)
        if j is not None:
            x = i * m + j
            if x < order and pow(g, x, p) == h:
                return x
        gamma = gamma * factor % p
    return None


def pohlig_hellman(g, h, p, factors=None, order=None):
    """Solve a prime-field DLP when the subgroup order is smooth."""
    order = int(order or (p - 1))
    factors = _normal_factors(factors) or _factorint(order)
    if not factors or math.prod(q ** e for q, e in factors.items()) != order:
        return None
    congruences = []
    for q, exponent in factors.items():
        modulus = q ** exponent
        base = pow(g, order // q, p)
        x_q = 0
        for digit in range(exponent):
            correction = (h * pow(pow(g, x_q, p), -1, p)) % p
            target = pow(correction, order // (q ** (digit + 1)), p)
            value = bsgs(base, target, p, q)
            if value is None:
                return None
            x_q += value * (q ** digit)
        if pow(g, x_q, p) != pow(h, order // modulus, p):
            return None
        congruences.append((x_q, modulus))
    x, _ = crt(congruences)
    x %= order
    return x if pow(g, x, p) == h % p else None


def discrete_log(g, h, p, order=None, factors=None):
    """Select PH, SymPy, or bounded BSGS and verify the result."""
    order = int(order or (p - 1))
    result = None
    normal = _normal_factors(factors)
    if normal or order <= 10_000_000:
        result = pohlig_hellman(g, h, p, normal, order)
    if result is None and order <= 100_000_000:
        result = bsgs(g, h, p, order)
    if result is None:
        try:
            from sympy.ntheory import discrete_log as sympy_dlog
            result = int(sympy_dlog(int(p), int(h), int(g), order=int(order)))
        except Exception:
            return None
    return result if pow(g, result, p) == h % p else None


def derive_key_candidates(shared):
    """Common CTF KDF conventions, ordered from explicit to hashed."""
    shared = int(shared)
    raw = shared.to_bytes((shared.bit_length() + 7) // 8 or 1, "big")
    fixed = shared.to_bytes(32, "big")
    return [
        ("shared-int-be", raw),
        ("sha256(shared-int)", hashlib.sha256(str(shared).encode()).digest()),
        ("sha256(shared-be)", hashlib.sha256(raw).digest()),
        ("sha256(shared-be32)", hashlib.sha256(fixed).digest()),
        ("md5(shared-be)", hashlib.md5(raw).digest()),
        ("sha1(shared-be)", hashlib.sha1(raw).digest()),
    ]


def recover_dh_private(public, p, g, factors=None, order=None):
    return discrete_log(g, public, p, order=order, factors=factors)

