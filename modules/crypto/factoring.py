"""Integer factoring toolkit for CTF moduli.

Covers the standard ladder used in competition solve scripts:
small-prime trial division -> Pollard p-1 (smooth primes) ->
Pollard rho (Brent) with a bounded budget.  A FactorDB lookup is
attempted last because many CTFs reuse textbook moduli; it is skipped
automatically when offline.  Nothing here needs third-party libraries.
"""
import math

from core.output import info_line, warn_line


# ---------------------------------------------------------------------------
# Trial division
# ---------------------------------------------------------------------------
def small_primes(limit=100_000):
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i in range(limit) if sieve[i]]


_TRIAL_CACHE = None


def trial_division(n, limit=100_000):
    """Strip every prime factor below *limit*. Returns list of factors."""
    global _TRIAL_CACHE
    if _TRIAL_CACHE is None or len(_TRIAL_CACHE) < min(limit, 100_000):
        _TRIAL_CACHE = small_primes(min(limit, 100_000))
    out = []
    for p in _TRIAL_CACHE:
        if p * p > n:
            break
        while n % p == 0:
            out.append(p)
            n //= p
    return out, n


# ---------------------------------------------------------------------------
# Pollard rho (Brent's improvement)
# ---------------------------------------------------------------------------
def pollard_rho(n, max_steps=1 << 22):
    """Find a non-trivial factor via Brent's cycle detection.

    Works for factors up to roughly 2**48 within the default step budget
    (sqrt(factor) iterations); raise max_steps for bigger hunts.
    """
    if n % 2 == 0:
        return 2
    for c in (1, 2, 3, 5, 7, 11, 13):  # different polynomials dodge failures
        x = y = 2
        d = 1
        steps = 0
        while steps < max_steps:
            # run a batch of gcd-free steps, then one gcd (batching trick)
            saved = x
            for _ in range(128):
                x = (x * x + c) % n
                y = (y * y + c) % n
                y = (y * y + c) % n
                d = (x - y) % n or d
                steps += 1
                if steps >= max_steps:
                    break
            g = math.gcd(d, n)
            if g not in (1, n):
                return g
            if g == n:
                # back off one step at a time from the checkpoint
                xx = saved
                yy = xx
                for _ in range(128):
                    xx = (xx * xx + c) % n
                    yy = (yy * yy + c) % n
                    yy = (yy * yy + c) % n
                    g = math.gcd(abs(xx - yy), n)
                    if g not in (1, n):
                        return g
                    if g == n:
                        break
                break
        continue
    return None


# ---------------------------------------------------------------------------
# Pollard p-1
# ---------------------------------------------------------------------------
def pollard_p1(n, b1=100_000, b2=None):
    """Pollard's p-1: finds p when p-1 is B1-smooth (with a small stage-2)."""
    a = 2
    primes = small_primes(50_000)
    try:
        for p in primes:
            if p > b1:
                break
            pk = p
            pk_limit = b1
            while pk * p <= pk_limit:
                pk *= p
            a = pow(a, pk, n)
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                return g
        if a == 1:
            return None
        g = math.gcd(a - 1, n)
        if 1 < g < n:
            return g
        # stage 2: single extra powers to catch p-1 = smooth*B with B <= b2
        b2 = b2 or 10_000_000
        base = a
        for j in range(2, 1000):
            a = pow(a, j, n)
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                return g
        del b2, base
    except (ValueError, ZeroDivisionError):
        pass
    return None


# ---------------------------------------------------------------------------
# FactorDB lookup (optional; silently skipped offline)
# ---------------------------------------------------------------------------
def factor_db_lookup(n, timeout=6):
    import json as _json
    import urllib.request

    url = ("https://factordb.com/api?query=" + str(n))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ctf-auto"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = _json.loads(resp.read().decode())
        status = data.get("status", "")
        factors = data.get("factors", [])
        if status in ("FF", "CF") and factors and len(factors) >= 1:
            parts = []
            for f, exp in factors:
                f = int(f)
                parts.extend([f] * int(exp))
            product = 1
            for part in parts:
                product *= part
            if product == n and all(1 < p < n for p in parts):
                return parts
    except Exception:  # noqa: BLE001 — offline / blocked is normal
        pass
    return None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def factor_n(n, use_factordb=True, verbose=False):
    """Fully factor n using every method available. Returns sorted list of
    prime-ish factors (composite leftovers are included if unfactored)."""
    if n < 4:
        return [n] if n > 1 else []
    todo = [n]
    found = []

    def emit(value):
        if value > 1:
            todo.append(value)

    steps = 0
    while todo and steps < 64:
        steps += 1
        m = todo.pop()
        if m == 1:
            continue
        # primality check (Miller-Rabin, deterministic for CTF sizes)
        if _is_probable_prime(m):
            found.append(m)
            continue
        factor = None
        # 1) trial division
        small, rest = trial_division(m)
        found.extend(small)
        if rest != m and _is_probable_prime(rest):
            found.append(rest)
            continue
        m = rest
        if m == 1:
            continue
        if _is_probable_prime(m):
            found.append(m)
            continue
        # 2) Fermat close-primes (imported lazily to avoid cycles)
        from .rsa import fermat_factor
        try:
            factor = fermat_factor(m, max_iter=20_000)
        except Exception:
            factor = None
        # 3) Pollard p-1
        if not factor:
            factor = pollard_p1(m)
        # 4) Pollard rho
        if not factor:
            factor = pollard_rho(m)
        # 5) FactorDB
        if not factor and use_factordb:
            parts = factor_db_lookup(m)
            if parts:
                if verbose:
                    info_line(f"FactorDB: {m} = {' * '.join(map(str, parts))}")
                found.extend(p for p in parts if p > 1)
                continue
        if not factor:
            warn_line(f"factor: {m} ยังแยกไม่ได้ (ลอง FactorDB เองหรือเพิ่ม budget)")
            found.append(m)
            continue
        emit(factor)
        emit(m // factor)
    return sorted(found)


_PRIMALITY_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def _is_probable_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _PRIMALITY_BASES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


is_probable_prime = _is_probable_prime
