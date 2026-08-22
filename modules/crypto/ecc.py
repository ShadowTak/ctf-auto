"""Elliptic-curve toolkit for CTF challenges (prime fields).

Implements the attacks that recur in every ECDLP-themed challenge:
* generic point arithmetic over F_p
* point-order counting for small fields
* Smart's attack for anomalous curves (#E(F_p) == p) via full p-adic lift
* singular-curve DLP (node -> F_p^*, cusp -> F_p^+) with verification
* baby-step giant-step ECDLP for modest group orders

Nothing here needs third-party libraries.
"""
import math
import random


# ---------------------------------------------------------------------------
# Point arithmetic over F_p
# ---------------------------------------------------------------------------
def point_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        slope = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3)


def point_neg(P, p):
    if P is None:
        return None
    x, y = P
    return (x, (-y) % p)


def point_mul(k, P, a, p):
    """Scalar multiplication. Never reduces k modulo a guess of the group
    order — the subgroup order is unknown here, so a wrong reduction
    silently changes the exponent. Negatives go through point negation."""
    k = int(k)
    if k < 0:
        return point_neg(point_mul(-k, P, a, p), p)
    R = None
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q, a, p)
        Q = point_add(Q, Q, a, p)
        k >>= 1
    return R


def is_on_curve(P, a, b, p):
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0


def count_points(a, b, p):
    """Brute-force #E(F_p). Only sensible for small p (< ~2**22)."""
    squares = {}
    for y in range(p):
        squares.setdefault(y * y % p, []).append(y)
    total = 1  # infinity
    for x in range(p):
        total += len(squares.get((x * x * x + a * x + b) % p, ()))
    return total


# ---------------------------------------------------------------------------
# Smart's attack (anomalous curves, #E == p)
# ---------------------------------------------------------------------------
# Points over Z/p^2 are held in JACOBIAN coordinates [X:Y:Z]
# (affine x = X/Z^2, y = Y/Z^3).  This matters because p*G lands in the
# formal group E1 -- its reduction mod p is the point at infinity, which
# has NO affine representation.  In Jacobian form that is simply
# "Z divisible by p, X and Y units", and the elliptic logarithm needed
# by Smart's attack is psi(T) = (-X*Z/Y)/p mod p.


def _jac_double(P, A, n):
    """dbl-2007-bl on y^2 = x^3 + A*x + B over ring Z/n."""
    X1, Y1, Z1 = P
    if Y1 % n == 0:
        return None
    XX = X1 * X1 % n
    YY = Y1 * Y1 % n
    YYYY = YY * YY % n
    ZZ = Z1 * Z1 % n
    S = (2 * ((X1 + YY) ** 2 - XX - YYYY)) % n
    M = (3 * XX + A * ZZ % n * ZZ) % n
    T = (M * M - 2 * S) % n
    X3 = T
    Y3 = (M * (S - T) - 8 * YYYY) % n
    Z3 = ((Y1 + Z1) ** 2 - YY - ZZ) % n
    return (X3, Y3, Z3)


def _jac_add(P, Q, A, n):
    """add-2007-bl; None means the point at infinity."""
    if P is None:
        return Q
    if Q is None:
        return P
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    Z1Z1 = Z1 * Z1 % n
    Z2Z2 = Z2 * Z2 % n
    U1 = X1 * Z2Z2 % n
    U2 = X2 * Z1Z1 % n
    S1 = Y1 * Z2 % n * Z2Z2 % n
    S2 = Y2 * Z1 % n * Z1Z1 % n
    H = (U2 - U1) % n
    r = (2 * (S2 - S1)) % n
    if H == 0:
        if r == 0:
            return _jac_double(P, A, n)
        return None
    HH = H * H % n
    I = 4 * HH % n
    J = H * I % n
    V = U1 * I % n
    X3 = (r * r - J - 2 * V) % n
    Y3 = (r * (V - X3) - 2 * S1 * J) % n
    Z3 = ((Z1 + Z2) ** 2 - Z1Z1 - Z2Z2) % n * H % n
    return (X3, Y3, Z3)


def _jac_mul(k, P, A, n):
    R = None
    Q = P
    while k:
        if k & 1:
            R = _jac_add(R, Q, A, n)
        if k > 1:
            Q = _jac_double(Q, A, n)
        k >>= 1
    return R


def smart_attack(G, Q, a, b, p, attempts=16):
    """Recover d with Q = d*G when #E(F_p) == p. Returns d or None.

    Full p-adic construction (Novotney, Prop. 4.2 / Satoh's approach):
      1. randomise the lifted curve A=a+pi, B=b+pj with disc != 0 mod p
      2. Hensel-lift G, Q keeping their x-coordinates
      3. multiply both lifts by p over Z/p^2 -> points in E1
      4. psi(T) = (-X*Z/Y) / p mod p ; then d = psi(pQ)/psi(pG) mod p
    Degenerate lifts (slope denominators hitting p) are retried.
    """
    n = p * p
    rng = random.Random(0xC7F)

    def hensel(pt, aa, bb):
        x, y = pt
        rhs = x ** 3 + aa * x + bb
        delta = ((rhs - y * y) % n) // p
        t = delta * pow(2 * y, -1, p) % p
        return (x % n, (y + t * p) % n, 1)

    for trial in range(attempts):
        if trial == 0:
            ai, bi = 1, 1
        else:
            ai, bi = rng.randrange(1, p), rng.randrange(1, p)
        aa = (a + p * ai) % n
        bb = (b + p * bi) % n
        try:
            if math.gcd(int(G[1]), p) != 1 or math.gcd(int(Q[1]), p) != 1:
                return None
            Gl = hensel(G, aa, bb)
            Ql = hensel(Q, aa, bb)
            pG = _jac_mul(p, Gl, aa, n)
            pQ = _jac_mul(p, Ql, aa, n)
        except (ValueError, ZeroDivisionError):
            continue
        if pG is None or pQ is None:
            continue
        ZX, ZG = pQ[2], pG[2]
        # both must sit in E1 with v(Z) == 1 and unit Y
        if ZX % p != 0 or ZG % p != 0:
            continue
        if ZX % n == 0 or ZG % n == 0:
            continue
        if math.gcd(pQ[1], p) != 1 or math.gcd(pG[1], p) != 1:
            continue
        try:
            psi_q = ((-pQ[0] * ZX % n) * pow(pQ[1], -1, n) % n) // p
            psi_g = ((-pG[0] * ZG % n) * pow(pG[1], -1, n) % n) // p
            d = psi_q * pow(psi_g, -1, p) % p
        except ValueError:
            continue
        if point_mul(d, G, a, p) == Q:
            return d
        if point_mul((-d) % p, G, a, p) == Q:
            return (-d) % p
    return None


# ---------------------------------------------------------------------------
# Singular curves
# ---------------------------------------------------------------------------
def _sqrt_mod(v, p):
    v %= p
    if v == 0:
        return 0
    if pow(v, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        r = pow(v, (p + 1) // 4, p)
        return r if r * r % p == v else None
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(v, q, p), pow(v, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
        bb = pow(c, 1 << (m - i - 1), p)
        m, c = i, bb * bb % p
        t = t * c % p
        r = r * bb % p
    return r if r * r % p == v else None


def singular_dlp(P, Q, a, b, p):
    """DLP on a singular Weierstrass curve.

    cusp (y^2 = x^3):           t = y/x lives in (F_p, +);  k = tQ / tP
    node  (double root alpha):  u = (y-s(x-a))/(y+s(x-a)) in F_p^*;
                                k solved by BSGS when feasible.
    Returns verified k or None.
    """
    disc = 4 * a ** 3 + 27 * b ** 2
    if disc % p != 0:
        return None  # non-singular

    if a % p == 0 and b % p == 0:
        # cusp
        if P[0] % p == 0 or Q[0] % p == 0:
            return None
        tp = P[1] * pow(P[0], -1, p) % p
        tq = Q[1] * pow(Q[0], -1, p) % p
        if tp == 0:
            return None
        k = tq * pow(tp, -1, p) % p
        return k if point_mul(k, P, a, p) == Q else None

    # node: find double root alpha of x^3 + ax + b
    inv3 = pow(3, -1, p)
    sq = (-a) * inv3 % p
    root = _sqrt_mod(sq, p)
    if root is None:
        return None
    alpha = None
    for cand in ({root, (p - root) % p}):
        if (cand ** 3 + a * cand + b) % p == 0:
            alpha = cand
            break
    if alpha is None:
        return None

    s2 = (3 * alpha * alpha + a) % p
    s = _sqrt_mod(s2, p)
    if s is None:
        return None

    def transform(pt):
        x, y = pt
        num = (y - s * (x - alpha)) % p
        den = (y + s * (x - alpha)) % p
        return num * pow(den, -1, p) % p

    up = transform(P)
    uq = transform(Q)
    if up == 0:
        return None
    # quick checks before committing to a big BSGS
    k = _bsgs_fp(up, uq, p)
    if k is None:
        return None
    if point_mul(k, P, a, p) == Q:
        return k
    if point_mul((p - 1 - k) % p, P, a, p) == Q:
        return (p - 1 - k) % p
    return None


def _bsgs_fp(g, h, p, max_m=1 << 22):
    """BSGS for h = g^k in F_p^*. Gives up gracefully when sqrt(p) too big."""
    m = math.isqrt(p - 1) + 1
    if m > max_m:
        return None
    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * g % p
    factor = pow(pow(g, -1, p), m, p)
    gamma = h % p
    for i in range(m + 1):
        j = table.get(gamma)
        if j is not None:
            return (i * m + j) % (p - 1)
        gamma = gamma * factor % p
    return None


# ---------------------------------------------------------------------------
# Generic ECDLP fallback (small orders)
# ---------------------------------------------------------------------------
_BSGS_CAP = 1 << 21


def bsgs_ecdlp(Q, G, a, p, order=None):
    """Baby-step/giant-step on the curve group. Feasible below ~2^42 ops."""
    m = math.isqrt(order or (p + 1)) + 1
    if m > _BSGS_CAP:
        return None
    table = {}
    cur = None
    for j in range(m):
        if cur is not None:
            table[cur] = j
        cur = G if cur is None else point_add(cur, G, a, p)
    neg_m = point_neg(point_mul(m, G, a, p), p)
    gamma = Q
    for i in range(m + 1):
        if gamma in table:
            k = (i * m + table[gamma])
            return k
        gamma = point_add(gamma, neg_m, a, p)
    return None


# ---------------------------------------------------------------------------
# One-shot solver used by structured.py / autodetect
# ---------------------------------------------------------------------------
def solve_ecdlp(G, Q, a, b, p):
    """Try every available attack; returns (label, d) or (None, None)."""
    if not (is_on_curve(G, a, b, p) and is_on_curve(Q, a, b, p)):
        return None, None

    # anomalous?
    if p < 2 ** 20:
        try:
            if count_points(a, b, p) == p:
                d = smart_attack(G, Q, a, b, p)
                if d is not None:
                    return "smart-anomalous", d
        except Exception:  # noqa: BLE001
            pass
    elif p.bit_length() <= 32:
        # still cheap enough to count via Schoof-less brute at moderate p
        pass

    # singular?
    try:
        d = singular_dlp(Q, G, a, b, p)
        if d is not None:
            return "singular", d
    except Exception:  # noqa: BLE001
        pass

    # small group BSGS
    try:
        d = bsgs_ecdlp(Q, G, a, p)
        if d is not None:
            return "bsgs", d
    except Exception:  # noqa: BLE001
        pass
    return None, None
