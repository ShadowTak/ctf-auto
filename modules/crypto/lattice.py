"""Small, verified univariate Coppersmith helpers.

This is deliberately a bounded adapter around fpylll/SymPy. It refuses large
or malformed inputs and verifies every returned root modulo N. It is useful
for common CTF cases such as a known RSA prefix with a short unknown suffix;
general multivariate/Boneh-Durfee instances still need challenge-specific
parameter selection.
"""
import math


def _mul(left, right, modulus=None):
    out = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            out[i + j] += a * b
            if modulus:
                out[i + j] %= modulus
    return out


def _pow(poly, exponent, modulus):
    result, base = [1], poly[:]
    while exponent:
        if exponent & 1:
            result = _mul(result, base, modulus)
        base = _mul(base, base, modulus)
        exponent >>= 1
    return result


def _trim(poly):
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def evaluate(poly, x, modulus=None):
    result = 0
    for coefficient in reversed(poly):
        result = result * x + coefficient
        if modulus:
            result %= modulus
    return result


def coppersmith_univariate(poly, modulus, bound, m=None):
    """Return verified small integer roots of a monic polynomial modulo N."""
    try:
        from fpylll import IntegerMatrix, LLL
        from sympy import Poly, symbols
    except ImportError:
        return []
    modulus, bound = int(modulus), int(bound)
    poly = _trim([int(x) % modulus for x in poly])
    degree = len(poly) - 1
    if modulus <= 1 or degree < 1 or degree > 8 or bound <= 0 or bound > modulus:
        return []
    try:
        inv_lead = pow(poly[-1], -1, modulus)
    except ValueError:
        return []
    poly = [(x * inv_lead) % modulus for x in poly]
    # Small m often gives the cleanest short polynomial; callers can raise it
    # for harder instances, but the default is deliberately conservative.
    m = int(m or 2)
    if not 1 <= m <= 8 or degree * m > 64:
        return []
    rows = []
    for i in range(m):
        base = _pow(poly, i, modulus)
        scale = modulus ** (m - 1 - i)
        for j in range(degree):
            row = [0] * (degree * m)
            for k, coefficient in enumerate(base):
                index = k + j
                if index < len(row):
                    row[index] = coefficient * scale * (bound ** index)
            rows.append(row)
    try:
        matrix = IntegerMatrix.from_matrix(rows)
        LLL.reduction(matrix)
    except Exception:
        return []
    x = symbols("x")
    roots = set()
    for row in matrix:
        coefficients = []
        for index, value in enumerate(row):
            divisor = bound ** index
            coefficients.append(int(round(int(value) / divisor)))
        coefficients = _trim(coefficients)
        if len(coefficients) <= 1:
            continue
        try:
            for root in Poly(sum(c * x ** i for i, c in enumerate(coefficients)), x).ground_roots():
                if getattr(root, "q", 1) == 1:
                    candidate = int(root)
                    if abs(candidate) < bound and evaluate(poly, candidate, modulus) == 0:
                        roots.add(candidate)
        except Exception:
            continue
    return sorted(roots)


def rsa_known_prefix_roots(ciphertext, modulus, exponent, prefix,
                           unknown_bytes, suffix=b""):
    """Find a short unknown suffix in ``(prefix || x || suffix)^e mod N``."""
    prefix = prefix if isinstance(prefix, bytes) else str(prefix).encode()
    suffix = suffix if isinstance(suffix, bytes) else str(suffix).encode()
    unknown_bytes = int(unknown_bytes)
    if not 0 <= unknown_bytes <= 8:
        return []
    shift = 8 * (unknown_bytes + len(suffix))
    base = int.from_bytes(prefix, "big") << shift
    suffix_value = int.from_bytes(suffix, "big")
    # Expand (base + 2^(8*len(suffix))*x + suffix)^e modulo N.
    factor = 1 << (8 * len(suffix))
    constant = base + suffix_value
    polynomial = [0] * (int(exponent) + 1)
    for power in range(int(exponent) + 1):
        # binomial coefficient without importing a heavy CAS.
        coefficient = math.comb(int(exponent), power)
        polynomial[power] = coefficient * pow(constant, int(exponent) - power,
                                              int(modulus)) * factor ** power
    polynomial[0] = (polynomial[0] - int(ciphertext)) % int(modulus)
    roots = coppersmith_univariate(polynomial, modulus, 1 << (8 * unknown_bytes))
    return [root.to_bytes(unknown_bytes, "big") for root in roots
            if root >= 0]
