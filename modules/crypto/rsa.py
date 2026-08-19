"""RSA attacks: small-e, Wiener (continued fractions), Fermat factorization,
common modulus, Hastad broadcast. Includes a minimal DER/PEM parser so no
third-party ASN.1 library is required."""
import base64
import math
import re

from .common import (
    bytes_to_long,
    invmod,
    iroot,
    long_to_bytes,
    strip_zeros,
)


# ---------------------------------------------------------------------------
# Minimal DER / PEM parsing
# ---------------------------------------------------------------------------
def _der_len(data, off):
    l = data[off]
    off += 1
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(data[off:off + n], "big")
        off += n
    return l, off


def _der_items(data, off=0):
    """Parse the SEQUENCE whose header starts at off; return its children
    as a list of (tag, value_bytes). Skips the container's own header."""
    tag = data[off]
    off += 1
    length, off = _der_len(data, off)
    end = off + length
    children = []
    while off < end:
        ctag = data[off]
        off += 1
        clen, off = _der_len(data, off)
        children.append((ctag, data[off:off + clen]))
        off += clen
    return children


def _der_int(b):
    return int.from_bytes(b, "big")


def parse_pem(data):
    """Extract RSA params from a PEM string/bytes.

    Returns dict with any of: n, e, d, p, q.
    """
    if isinstance(data, str):
        data = data.encode()
    text = data.decode("latin-1")
    out = {}

    def from_pkcs1(der):
        fields = [b for tag, b in _der_items(der) if tag == 0x02]
        if len(fields) >= 3:
            out["n"] = _der_int(fields[1])
            out["e"] = _der_int(fields[2])
        if len(fields) >= 8:
            out["d"] = _der_int(fields[3])
            out["p"] = _der_int(fields[4])
            out["q"] = _der_int(fields[5])

    def from_spki(der):
        # SubjectPublicKeyInfo: SEQUENCE{ alg, BIT STRING{ SEQUENCE{n,e} } }
        # _der_items already skips the SEQUENCE header, so the BIT STRING
        # content parses straight into the two INTEGERs.
        for tag, b in _der_items(der):
            if tag == 0x03:  # BIT STRING
                inner = b[1:]  # skip unused-bits byte
                fields = [x for t3, x in _der_items(inner) if t3 == 0x02]
                if len(fields) >= 2:
                    out["n"] = _der_int(fields[0])
                    out["e"] = _der_int(fields[1])

    def from_pkcs8(der):
        # SEQUENCE{ INTEGER, alg, OCTET STRING{ PKCS#1 } }
        for tag, b in _der_items(der):
            if tag == 0x04:  # OCTET STRING
                from_pkcs1(b)

    blocks = re.findall(
        r"-----BEGIN ([A-Z ]+)-----([A-Za-z0-9+/=\s]+)-----END \1-----",
        text,
    )
    for label, body in blocks:
        der = base64.b64decode("".join(body.split()))
        try:
            if "RSA PRIVATE" in label:
                from_pkcs1(der)
            elif "PRIVATE KEY" in label:
                from_pkcs8(der)
            elif "RSA PUBLIC" in label:
                fields = [b for t, b in _der_items(der) if t == 0x02]
                if len(fields) >= 2:
                    out["n"] = _der_int(fields[0])
                    out["e"] = _der_int(fields[1])
            else:  # PUBLIC KEY
                from_spki(der)
        except Exception:
            continue
    return out


# ---------------------------------------------------------------------------
# Attack primitives
# ---------------------------------------------------------------------------
def small_e_attack(c, e, n):
    """If m^e < n we can just take the integer root. Only tries when e is
    actually small (<= 65537) — a large e means the message is padded and
    small-e is hopeless anyway."""
    if e > 65537:
        return None
    k = iroot(c, e)
    if k ** e == c:
        return k
    return None


def fermat_factor(n, max_iter=50_000):
    """Factor n when p and q are close. For large n (>100 digits), caps the
    search window to 1000 iterations since real Fermat factors have tiny gaps.
    For small n, uses the full max_iter."""
    if n % 2 == 0:
        return 2, n // 2
    a0 = math.isqrt(n)
    a = a0 if a0 * a0 >= n else a0 + 1
    # For large n, the gap between p and q is tiny in practice
    limit = min(max_iter, 1000) if n.bit_length() > 200 else max_iter
    for _ in range(limit):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def wiener_attack(e, n):
    """Recover d when d is small (d < n^0.25 / 3)."""
    a, b = e, n
    cf = []
    while b:
        cf.append(a // b)
        a, b = b, a % b
    p2k, p2d = 0, 1
    p1k, p1d = 1, 0
    for q in cf:
        k, d = q * p1k + p2k, q * p1d + p2d
        p2k, p2d, p1k, p1d = p1k, p1d, k, d
        if k == 0 or d == 0 or (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1  # p + q
        disc = s * s - 4 * n
        if disc < 0:
            continue
        root = math.isqrt(disc)
        if root * root != disc:
            continue
        p = (s + root) // 2
        q = (s - root) // 2
        if p * q == n:
            return d, p, q
    return None


def common_modulus(c1, c2, e1, e2, n):
    """Given two ciphertexts of the same message under coprime e1,e2."""
    g, a, b = _xgcd(e1, e2)
    if g != 1:
        return None
    if a < 0:
        c1 = invmod(c1, n)
        a = -a
    if b < 0:
        c2 = invmod(c2, n)
        b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n


def _xgcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _xgcd(b % a, a)
    return g, y - (b // a) * x, x


def hastad_broadcast(pairs):
    """pairs: list of (n, e, c) all same e (default 3). CRT + iroot."""
    if not pairs:
        return None
    e = pairs[0][1]
    if any(pe != e for _, pe, _ in pairs):
        return None
    N = 1
    for n, _, _ in pairs:
        N *= n
    total = 0
    for n, _, c in pairs:
        Ni = N // n
        total += c * Ni * invmod(Ni, n)
    m = total % N
    k = iroot(m, e)
    if k ** e == m:
        return k
    return None


def shared_prime_attack(n1, n2, e, c):
    """Two moduli sharing a prime factor (broken RNG). Compute gcd(n1,n2)."""
    shared = math.gcd(n1, n2)
    if shared <= 1 or shared == n1 or shared == n2:
        return []
    results = []
    # Try decrypting with n1's factorization
    for label, n_val in [("n1", n1), ("n2", n2)]:
        p = shared
        q = n_val // p
        if p * q != n_val:
            continue
        phi = (p - 1) * (q - 1)
        try:
            dd = invmod(e, phi)
            pt = strip_zeros(long_to_bytes(pow(c, dd, n_val)))
            results.append((f"shared-prime({label})", pt))
        except Exception:
            pass
    return results


def crack_rsa(n=None, e=None, c=None, d=None, p=None, q=None, pem=None, n2=None):
    """Try every attack and return a list of found plaintexts (bytes)."""
    found = []

    if pem:
        params = parse_pem(pem)
        n = n or params.get("n")
        e = e or params.get("e")
        d = d or params.get("d")
        p = p or params.get("p")
        q = q or params.get("q")

    if p and q and n is None:
        n = p * q
    if p and q and e is not None and d is None:
        phi = (p - 1) * (q - 1)
        try:
            d = invmod(e, phi)
        except ValueError:
            pass

    if n is None or e is None:
        return found

    if c is None:
        return found

    # 1) direct with known d
    if d is not None:
        try:
            found.append(("d known", strip_zeros(long_to_bytes(pow(c, d, n)))))
        except Exception:
            pass

    # 2) small e
    try:
        m = small_e_attack(c, e, n)
        if m is not None:
            found.append(("small e", strip_zeros(long_to_bytes(m))))
    except Exception:
        pass

    # 3) fermat
    try:
        f = fermat_factor(n)
        if f:
            p_, q_ = f
            phi = (p_ - 1) * (q_ - 1)
            dd = invmod(e, phi)
            found.append(("fermat", strip_zeros(long_to_bytes(pow(c, dd, n)))))
    except Exception:
        pass

    # 4) wiener
    try:
        w = wiener_attack(e, n)
        if w:
            dd, p_, q_ = w
            found.append(("wiener", strip_zeros(long_to_bytes(pow(c, dd, n)))))
    except Exception:
        pass

    # 5) shared prime (two moduli with gcd > 1)
    if n2 is not None:
        try:
            found.extend(shared_prime_attack(n, n2, e, c))
        except Exception:
            pass

    return found
