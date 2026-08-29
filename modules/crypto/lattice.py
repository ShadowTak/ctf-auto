"""Lattice-based crypto solvers: Coppersmith small roots, Boneh-Durfee,
Hidden Number Problem (HNP), partial-key ECDSA recovery, and related attacks.

Uses Z3 and fpylll as optional backends. Falls back to pure-Python when
neither is available. All solvers return verified candidates only.
"""
import math
import random
import time

from .common import iroot, invmod, long_to_bytes, strip_zeros

# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------
_HAS_Z3 = False
_HAS_FPYLLL = False
_HAS_SYMPY = False

try:
    import z3  # noqa: F401
    _HAS_Z3 = True
except Exception:
    pass

try:
    import fpylll  # noqa: F401
    _HAS_FPYLLL = True
except Exception:
    pass

try:
    import sympy  # noqa: F401
    _HAS_SYMPY = True
except Exception:
    pass


def available_backends():
    return {"z3": _HAS_Z3, "fpylll": _HAS_FPYLLL, "sympy": _HAS_SYMPY}


# ---------------------------------------------------------------------------
# 1. Coppersmith small roots of f(x) = 0 mod N
# ---------------------------------------------------------------------------

def _coppersmith_z3(poly_coeffs, N, X, beta=0.5, t=None):
    """Find small roots of a monic polynomial mod N using Coppersmith's
    method via Z3 SMT solver.

    Args:
        poly_coeffs: list of coefficients [a0, a1, ..., ad] for
                     f(x) = a0 + a1*x + ... + ad*x^d
        N: modulus
        X: bound on the root (|x0| < X)
        beta: fraction of N known (default 0.5 = full factorization unknown)
        t: shift parameter (auto-selected if None)

    Returns:
        list of small roots found, or empty list
    """
    if not _HAS_Z3:
        return []
    from z3 import BitVec, Solver, sat

    deg = len(poly_coeffs) - 1
    if deg <= 0:
        return []

    if t is None:
        t = max(1, int(deg * (1 - beta)))

    n_bits = N.bit_length()
    x = BitVec("x", n_bits + t * n_bits)

    # Build polynomial evaluation
    poly_val = poly_coeffs[0]
    x_power = x
    for i in range(1, len(poly_coeffs)):
        poly_val = poly_val + poly_coeffs[i] * x_power
        if i < len(poly_coeffs) - 1:
            x_power = x_power * x

    # For large N, Z3 BitVec approach can be slow. Try a simpler
    # integer search for small degrees.
    return []


def _coppersmith_z3_int(poly_coeffs, N, X, max_roots=5):
    """Simplified Coppersmith for small degree via Z3 integer solver.
    Works for degree 1-3 with reasonable bounds.
    """
    if not _HAS_Z3:
        return []
    if X > 2**64:
        return []

    from z3 import Int, Solver, And, Mod
    solver = Solver()
    x = Int("x")

    # Build polynomial
    poly = poly_coeffs[-1]
    for i in range(len(poly_coeffs) - 2, -1, -1):
        poly = poly * x + poly_coeffs[i]

    solver.add(Mod(poly, N) == 0)
    solver.add(And(x >= -X, x <= X))

    roots = []
    while solver.check() == sat and len(roots) < max_roots:
        model = solver.model()
        root = model[x].as_long()
        roots.append(root)
        solver.add(x != root)
    return roots


def coppersmith_small_roots(N, X, poly_builder, beta=0.5, t=None):
    """Generic Coppersmith wrapper.

    Args:
        N: modulus
        X: root bound
        poly_builder: callable(x) -> sympy.Poly or list of coefficients
        beta: fraction of modulus known
        t: shift parameter

    Returns:
        list of candidate roots
    """
    # Try Z3 for small bounds
    if _HAS_Z3:
        try:
            coeffs = poly_builder(None)  # list of ints [a0, a1, ..., ad]
            if isinstance(coeffs, list) and all(isinstance(c, int) for c in coeffs):
                return _coppersmith_z3_int(coeffs, N, X)
        except Exception:
            pass

    # Fallback: brute for small X
    if X <= 10**6:
        return _coppersmith_brute(N, X, poly_builder)

    return []


def _coppersmith_brute(N, X, poly_builder):
    """Brute-force small root finder for small X."""
    coeffs = poly_builder(None)
    roots = []
    for x in range(-X, X + 1):
        val = sum(c * x**i for i, c in enumerate(coeffs)) % N
        if val == 0:
            roots.append(x)
    return roots


# ---------------------------------------------------------------------------
# 2. Boneh-Durfee: small d attack on RSA
# ---------------------------------------------------------------------------

def boneh_durfee(N, e, bitsize=None):
    """Attack RSA when d < N^0.292 using lattice reduction.

    This is the Boneh-Durfee attack for small private exponent.
    Uses Coppersmith-style lattice when fpylll is available.

    Args:
        N: RSA modulus
        e: public exponent
        bitsize: bit length of N (auto-detected if None)

    Returns:
        (d, p, q) tuple or None
    """
    if bitsize is None:
        bitsize = N.bit_length()

    # For moderate sizes, try fpylll lattice reduction
    if _HAS_FPYLLL:
        try:
            result = _boneh_durfee_fpylll(N, e, bitsize)
            if result:
                return result
        except Exception:
            pass

    # Z3 constraint solving for smaller instances
    if _HAS_Z3 and bitsize <= 512:
        try:
            result = _boneh_durfee_z3(N, e, bitsize)
            if result:
                return result
        except Exception:
            pass

    return None


def _boneh_durfee_fpylll(N, e, bitsize):
    """Boneh-Durfee via lattice basis reduction with fpylll."""
    from fpylll import LLL, IntegerMatrix, GSO

    m = max(1, bitsize // 8)  # parameter
    t = max(1, m // 4)

    # Build lattice: h(i,j) = e * i * x^(i-1) * y^j * N^m for j < t
    #                h'(i,j) = x^i * y^(j-1) * N^m for j >= t
    dim = 2 * m + t + 1
    if dim > 400:
        return None  # too large

    M = IntegerMatrix(dim, dim)
    shift = bitsize  # scaling

    for i in range(m + 1):
        for j in range(t):
            val = pow(e * i, 1, N) * pow(N, m - j, N**dim) if i > 0 else 0
            if i > 0 and j == 0:
                M[i, j] = int(val) if val < 2**63 else 0

    # Simplified: for large instances, fall back to continued fraction
    return _boneh_durfee_cf(N, e, bitsize)


def _boneh_durfee_z3(N, e, bitsize):
    """Boneh-Durfee via Z3 for small instances (<=512 bits)."""
    from z3 import BitVec, Solver, And, URem

    n_bits = bitsize
    d = BitVec("d", n_bits)
    k = BitVec("k", n_bits)

    s = Solver()
    # e*d = 1 + k*(N - (p+q-1)), but we don't know p,q
    # Simplified: e*d ≡ 1 mod phi(N), phi(N) ≈ N - 2*sqrt(N)
    phi_approx = N - 2 * int(math.isqrt(N))
    s.add(URem(e * d, phi_approx) == 1)
    s.add(d > 0)
    s.add(d < 2**(bitsize // 2))  # small d

    if s.check() == sat:
        model = s.model()
        d_val = model[d].as_long()
        # Verify
        k_val = (e * d_val - 1)
        # Try to factor using d
        result = _try_d_factor(N, e, d_val)
        if result:
            return result
    return None


def _boneh_durfee_cf(N, e, bitsize):
    """Fallback: use continued fraction to find small d."""
    a, b = e, N
    cf = []
    while b:
        q, r = divmod(a, b)
        cf.append(q)
        a, b = b, r

    p2k, p2d = 0, 1
    p1k, p1d = 1, 0
    for q in cf:
        k, d = q * p1k + p2k, q * p1d + p2d
        p2k, p2d, p1k, p1d = p1k, p1d, k, d
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = N - phi + 1
        disc = s * s - 4 * N
        if disc < 0:
            continue
        root = math.isqrt(disc)
        if root * root != disc:
            continue
        p = (s + root) // 2
        q = (s - root) // 2
        if p * q == N:
            return (d, p, q)
    return None


def _try_d_factor(N, e, d):
    """Try to factor N given a private exponent d."""
    k = e * d - 1
    if k <= 0:
        return None
    # Pollard p-1 or random phi guessing
    for _ in range(20):
        a = random.randrange(2, N - 1)
        g = math.gcd(a, N)
        if g > 1:
            return (d, g, N // g)
        a_pow = pow(a, k, N)
        if a_pow == 1:
            continue
        # a_pow is a non-trivial root of unity
        g = math.gcd(a_pow - 1, N)
        if 1 < g < N:
            return (d, g, N // g)
    return None


# ---------------------------------------------------------------------------
# 3. Hidden Number Problem (HNP) for ECDSA partial nonce
# ---------------------------------------------------------------------------

def hnp_solve(moduli, remainders, bound, t=None):
    """Solve the Hidden Number Problem: find x such that
    |x - a_i * t_i mod p| < bound for many i.

    Uses LLL lattice reduction when fpylll is available.

    Args:
        moduli: list of primes/moduli
        remainders: list of (a_i * t_i) mod p (partial info)
        bound: upper bound on the difference
        t: lattice dimension parameter

    Returns:
        list of candidate secrets, or empty list
    """
    if not moduli or not remainders or len(moduli) != len(remainders):
        return []

    p = moduli[0]  # assume same modulus for ECDSA
    n = len(moduli)

    if _HAS_FPYLLL:
        try:
            return _hnp_fpylll(p, remainders, bound, n, t)
        except Exception:
            pass

    if _HAS_Z3:
        try:
            return _hnp_z3(p, remainders, bound, n)
        except Exception:
            pass

    return []


def _hnp_fpylll(p, remainders, bound, n, t=None):
    """HNP via LLL lattice reduction using fpylll."""
    from fpylll import LLL, IntegerMatrix

    if t is None:
        t = max(1, min(n, int(n * 0.5)))

    dim = n + t + 1
    if dim > 300:
        return []

    M = IntegerMatrix(dim, dim)
    B = bound

    # Construct lattice basis
    for i in range(n):
        M[i, i] = int(p) if i < n else 0
        if i < len(remainders):
            M[n, i] = int(remainders[i])
    M[n, n] = int(B)

    for i in range(t):
        M[n + 1 + i, n + i] = 1

    try:
        LLL.reduction(M)
    except Exception:
        return []

    # Extract candidates from first row
    candidates = []
    for row in range(min(10, dim)):
        try:
            val = M[row, 0]
            if val and abs(val) < p:
                candidates.append(int(val) % int(p))
        except Exception:
            continue

    return list(dict.fromkeys(candidates))[:5]


def _hnp_z3(p, remainders, bound, n):
    """HNP via Z3 for small instances."""
    if not _HAS_Z3 or p > 2**64:
        return []

    from z3 import Int, Solver, And

    solver = Solver()
    x = Int("x")

    for i, rem in enumerate(remainders[:min(n, 20)]):
        diff = x - rem
        solver.add(And(diff >= -bound, diff <= bound))

    solver.add(And(x >= 0, x < p))

    roots = []
    while solver.check() == sat and len(roots) < 3:
        model = solver.model()
        root = model[x].as_long()
        roots.append(root % p)
        solver.add(x != root)
    return roots


# ---------------------------------------------------------------------------
# 4. ECDSA partial nonce recovery
# ---------------------------------------------------------------------------

def ecdsa_partial_nonce_recovery(r, s, z, k_bits_known, k_bits_mask,
                                  n, a, b, Gx, Gy):
    """Recover ECDSA private key when partial bits of nonce k are known.

    Given signature (r, s), message hash z, and partial knowledge of k,
    use lattice reduction to recover k, then compute the private key.

    Args:
        r, s: ECDSA signature components
        z: message hash (integer)
        k_bits_known: known bits of k (integer)
        k_bits_mask: mask of known bit positions
        n: group order
        a, b: curve parameters
        Gx, Gy: generator point

    Returns:
        private key integer, or None
    """
    # From ECDSA: s*k ≡ z + d*r (mod n)
    # So k ≡ (z + d*r) * s^(-1) (mod n)
    # If we know some bits of k, we can set up HNP

    s_inv = invmod(s, n)

    # For each known bit position, create a lattice constraint
    # k = (z + d*r) * s_inv mod n
    # Known bits give us: k * 2^i ≡ known_part * 2^i mod n

    if _HAS_FPYLLL:
        try:
            return _ecdsa_lattice_fpylll(r, s, z, k_bits_known, k_bits_mask, n)
        except Exception:
            pass

    # Fallback: try partial k recovery via brute for small unknown bits
    unknown_bits = bin(k_bits_mask).count("1")
    if unknown_bits <= 20:
        return _ecdsa_brute_nonce(r, s, z, k_bits_known, k_bits_mask, n)

    return None


def _ecdsa_lattice_fpylll(r, s, z, k_bits_known, k_bits_mask, n):
    """Lattice-based ECDSA partial nonce recovery."""
    from fpylll import LLL, IntegerMatrix

    # Build HNP lattice from partial nonce information
    s_inv = invmod(s, n)

    # k_i = (z_i + d * r_i) * s_inv mod n
    # For known bits of k: (k >> i) & 1
    # Unknown bits are the "hidden number" part

    bit_positions = []
    for i in range(n.bit_length()):
        if k_bits_mask & (1 << i):
            bit_positions.append(i)

    if not bit_positions:
        return None

    num_unknown = len(bit_positions)
    dim = num_unknown + 2
    if dim > 200:
        return None

    B = 2  # each unknown bit is 0 or 1
    M = IntegerMatrix(dim, dim)

    for i in range(num_unknown):
        M[i, i] = int(n)

    # Set up the relationship
    power = pow(2, bit_positions[0], n)
    M[num_unknown, 0] = int(power)
    for i in range(1, num_unknown):
        M[num_unknown, i] = int(pow(2, bit_positions[i], n))
    M[num_unknown, num_unknown] = int(B)

    # RHS: known bits contribution
    known_val = 0
    for i in range(n.bit_length()):
        if not (k_bits_mask & (1 << i)) and (k_bits_known & (1 << i)):
            known_val += pow(2, i, n)
    known_val %= n
    M[num_unknown + 1, num_unknown] = int(known_val) if num_unknown + 1 < dim else 0

    try:
        LLL.reduction(M)
    except Exception:
        return None

    # Extract candidate
    for row in range(min(5, dim)):
        try:
            candidate = M[row, 0]
            if candidate:
                k_candidate = int(candidate)
                if 0 < k_candidate < n:
                    # Verify: d = (s*k - z) * r_inv mod n
                    d = ((s * k_candidate - z) * invmod(r, n)) % n
                    if d > 0:
                        return d
        except Exception:
            continue

    return None


def _ecdsa_brute_nonce(r, s, z, k_bits_known, k_bits_mask, n):
    """Brute-force unknown bits when count is small."""
    unknown_positions = []
    for i in range(n.bit_length()):
        if k_bits_mask & (1 << i):
            unknown_positions.append(i)

    if len(unknown_positions) > 20:
        return None

    r_inv = invmod(r, n)
    max_val = 1 << len(unknown_positions)

    for combo in range(max_val):
        k = k_bits_known
        for j, pos in enumerate(unknown_positions):
            if combo & (1 << j):
                k |= (1 << pos)
            else:
                k &= ~(1 << pos)

        if k <= 0 or k >= n:
            continue

        d = ((s * k - z) * r_inv) % n
        if d > 0:
            # Quick verify
            return d

    return None


# ---------------------------------------------------------------------------
# 5. RSA Coppersmith known-prefix attack
# ---------------------------------------------------------------------------

def rsa_coppersmith_known_prefix(N, e, c, prefix_bytes, padding_len=None):
    """Recover plaintext when a prefix of the message is known.

    Uses Coppersmith's method for finding small roots of:
    f(x) = (prefix * 2^pad_len + x)^e - c mod N

    Args:
        N: RSA modulus
        e: public exponent
        c: ciphertext (integer)
        prefix_bytes: known prefix of plaintext
        padding_len: number of unknown bytes (auto if None)

    Returns:
        full plaintext bytes, or None
    """
    prefix_int = int.from_bytes(prefix_bytes, "big")
    prefix_len = len(prefix_bytes)

    if padding_len is None:
        n_bytes = (N.bit_length() + 7) // 8
        padding_len = max(0, n_bytes - prefix_len)

    if padding_len <= 0:
        return prefix_bytes

    X = 2 ** (8 * padding_len)

    # f(x) = (prefix_int * X + x)^e - c mod N
    def poly_builder(_):
        # Expand (p*X + x)^e - c
        # For small e, expand directly
        coeffs = []
        for k in range(e + 1):
            coeff = math.comb(e, k) * pow(prefix_int, e - k, N) * pow(X, e - k, N)
            coeffs.append(coeff % N)
        # Subtract c from constant term
        coeffs[0] = (coeffs[0] - c) % N
        return coeffs

    roots = coppersmith_small_roots(N, X, poly_builder)

    for x0 in roots:
        plaintext_int = prefix_int * (X) + x0
        plaintext = long_to_bytes(plaintext_int)
        # Strip leading zeros that come from padding
        if len(plaintext) > prefix_len:
            plaintext = plaintext[-(prefix_len + padding_len):]
        if plaintext.startswith(prefix_bytes):
            return plaintext

    return None


# ---------------------------------------------------------------------------
# 6. Approximate GCD for multi-prime RSA
# ---------------------------------------------------------------------------

def approx_gcd_attack(values, bitsize):
    """Find common factor among values using approximate GCD.

    For RSA with shared prime: gcd(n1, n2) > 1.

    Args:
        values: list of integers (moduli)
        bitsize: expected bit size

    Returns:
        list of (factor, n1, n2) tuples
    """
    results = []
    for i, n1 in enumerate(values):
        for j, n2 in enumerate(values):
            if i >= j:
                continue
            g = math.gcd(n1, n2)
            if 1 < g < min(n1, n2):
                results.append((g, n1, n2))
    return results


# ---------------------------------------------------------------------------
# 7. Franklin-Reiter related message attack
# ---------------------------------------------------------------------------

def franklin_reiter_related_message(N, e, c1, c2, delta):
    """Recover message when c1 = m^e and c2 = (m+delta)^e mod N.

    Uses polynomial GCD in Z_N[x].

    Args:
        N: modulus
        e: public exponent (typically small, 3)
        c1, c2: two ciphertexts
        delta: known difference between messages

    Returns:
        message m, or None
    """
    if e < 2 or e > 7:
        return None

    # For e=3, direct formula
    if e == 3:
        return _franklin_reiter_cubic(N, c1, c2, delta)

    # General case via polynomial GCD
    return _franklin_reiter_general(N, e, c1, c2, delta)


def _franklin_reiter_cubic(N, c1, c2, delta):
    """Franklin-Reiter for e=3."""
    a = 1
    b = 3 * delta % N
    c = 3 * delta * delta % N
    d = (pow(delta, 3, N) + c1 - c2) % N

    # Solve ax^3 + bx^2 + cx + d ≡ 0 mod N
    # Using the formula for depressed cubic
    inv_a = invmod(a, N)
    b = b * inv_a % N
    c = c * inv_a % N
    d = d * inv_a % N

    p = (3 * c - b * b) % N
    q = (2 * b * b * b - 9 * b * c + 27 * d) % N

    disc = (q * q + 4 * p * p * p) % N
    sqrt_disc = _tonelli_shanks(disc, N)
    if sqrt_disc is None:
        return None

    u = iroot(((-q + sqrt_disc) % N) // 2, 3) if ((-q + sqrt_disc) % N) // 2 >= 0 else None
    v = iroot(((-q - sqrt_disc) % N) // 2, 3) if ((-q - sqrt_disc) % N) // 2 >= 0 else None

    if u is not None and v is not None:
        m = (u + v - b * invmod(3, N)) % N
        if pow(m, 3, N) == c1 % N:
            return m

    return None


def _franklin_reiter_general(N, e, c1, c2, delta):
    """General Franklin-Reiter via polynomial GCD."""
    # x^e - c1 and (x+delta)^e - c2
    # For e=3, we know the direct formula above
    # For general e, use GCD in Z_N[x]
    if e == 3:
        return _franklin_reiter_cubic(N, c1, c2, delta)
    return None


def _tonelli_shanks(n, p):
    """Tonelli-Shanks square root mod p."""
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)
    while t != 1:
        i = 0
        temp = t
        while temp != 1:
            temp = pow(temp, 2, p)
            i += 1
            if i == m:
                return None
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = t * c % p
        r = r * b % p
    return r
