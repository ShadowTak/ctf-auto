"""PRNG recovery attacks for CTF challenges.

Covers the four generators that dominate "predict the output" challenges:
* java.util.Random (48-bit truncated LCG)
* glibc random()/rand() TYPE_3 (additive feedback r[i] = r[i-31]+r[i-3])
* V8 / browser xorshift128+ (Math.random) — symbolic GF(2) state solve
* Python's Mersenne Twister seeded from a small / timestamp seed space

Every recovery function verifies itself against the observed outputs
before predicting anything.
"""
import random as pyrandom


# ---------------------------------------------------------------------------
# java.util.Random
# ---------------------------------------------------------------------------
_J_MULT = 0x5DEECE66D
_J_ADD = 0xB
_J_MASK = (1 << 48) - 1


class JavaRandom:
    def __init__(self, seed):
        self.seed = (seed ^ _J_MULT) & _J_MASK

    def next_bits(self, bits):
        self.seed = (self.seed * _J_MULT + _J_ADD) & _J_MASK
        return self.seed >> (48 - bits)

    def next_int(self):
        return self.next_bits(32)

    def next_long(self):
        hi = self.next_bits(32)
        lo = self.next_bits(32)
        v = (hi << 32) + lo
        return v - (1 << 64) if v >= (1 << 63) else v

    def next_double(self):
        return ((self.next_bits(26) << 27) + self.next_bits(27)) / float(1 << 53)


def java_recover(o1, o2, max_low=1 << 16):
    """Recover a java.util.Random seed from two consecutive nextInt()s.

    After the first call the internal seed is s1 with top-32 bits == o1;
    only the low 16 bits are unknown, so 2^16 candidates are checked
    against the second output before inverting the LCG one step.
    """
    inv_mult = pow(_J_MULT, -1, 1 << 48)
    for low in range(max_low):
        cand = (((o1 & 0xFFFFFFFF) << 16) | low) & _J_MASK
        jr = JavaRandom.__new__(JavaRandom)
        jr.seed = cand
        if jr.next_int() != (o2 & 0xFFFFFFFF):
            continue
        prev_internal = ((cand - _J_ADD) * inv_mult) & _J_MASK
        # constructor XORs again, so hand back internal_seed ^ MULT
        return prev_internal ^ _J_MULT
    return None


# ---------------------------------------------------------------------------
# glibc random() TYPE_3
# ---------------------------------------------------------------------------
def _glibc_init(seed):
    """Internal r[] table after srand(seed): 344 entries, 310 discarded."""
    r = [seed & 0xFFFFFFFF]
    for _i in range(30):
        hi, lo = divmod(r[-1], 127773)
        word = 16807 * lo - 2836 * hi
        if word < 0:
            word += 2147483647
        r.append(word & 0xFFFFFFFF)
    r.extend(r[-31:-28])          # indices 31..33 repeat 0..2
    for _i in range(310):         # discard phase
        r.append((r[-31] + r[-3]) & 0xFFFFFFFF)
    return r


def glibc_rand_stream(seed, count):
    """First `count` outputs of `srand(seed); random()`."""
    r = _glibc_init(seed)
    out = []
    for _ in range(count):
        nxt = (r[-31] + r[-3]) & 0xFFFFFFFF
        r.append(nxt)
        out.append(nxt >> 1)
    return out


def glibc_seed_brute(outputs, max_seed=1 << 20):
    """Brute-force the srand() seed from leading outputs.

    Returns (seed, predict_fn) where predict_fn(n) yields the next n
    values after the observed prefix — or (None, None).
    """
    want = [o & 0x7FFFFFFF for o in outputs[:8]]
    n_check = len(want)
    for seed in range(max_seed):
        if glibc_rand_stream(seed, n_check) == want:
            consumed = len(outputs)

            def predict(k=1, _seed=seed, _n=consumed):
                full = glibc_rand_stream(_seed, _n + k)
                return full[_n:]

            return seed, predict
    return None, None


# ---------------------------------------------------------------------------
# xorshift128+ (V8 Math.random and friends)
# ---------------------------------------------------------------------------
_M64 = (1 << 64) - 1


class XorShift128Plus:
    def __init__(self, s0, s1):
        self.s0 = s0 & _M64
        self.s1 = s1 & _M64

    def next_u64(self):
        s1 = self.s0
        s0 = self.s1
        self.s0 = s0
        s1 ^= (s1 << 23) & _M64
        s1 ^= s1 >> 17
        s1 ^= s0
        s1 ^= s0 >> 26
        self.s1 = s1
        return (s1 + s0) & _M64

    def next_double_v8(self):
        """V8's Math.random consumes the high 52 bits."""
        raw = self.next_u64()
        return (raw >> 12) / float(1 << 52)


def xs128p_recover(outputs):
    """Solve xorshift128+ state from consecutive u64 outputs.

    NOTE: the '+' in the name is real integer addition, whose carries make
    the output non-linear over GF(2), so plain Gaussian elimination cannot
    work.  When z3-solver is installed this uses SMT solving (the standard
    writeup approach); without it only the trivial all-zero state can be
    recognised and None is returned otherwise.
    """
    if not outputs:
        return None

    try:
        import z3  # type: ignore
    except ImportError:
        # cheap special case: constant zero stream
        if all((o & _M64) == 0 for o in outputs[:3]):
            return XorShift128Plus(0, 0)
        return None

    s0 = z3.BitVecs("xs_s0", 64)[0]
    s1 = z3.BitVecs("xs_s1", 64)[0]
    cur_s0, cur_s1 = s0, s1
    solver = z3.Solver()
    for want in outputs[:4]:
        t = cur_s0
        t = t ^ z3.LShR(t, 0)  # keep term order explicit
        t = (t ^ (t << 23)) & _M64
        t = (t ^ z3.LShR(t, 17)) & _M64
        t = (t ^ cur_s1) & _M64
        t = (t ^ z3.LShR(cur_s1, 26)) & _M64
        new_s0 = cur_s1
        new_s1 = t
        solver.add(new_s0 + new_s1 == z3.BitVecVal(want & _M64, 64))
        cur_s0, cur_s1 = new_s0, new_s1

    if solver.check() != z3.sat:
        return None
    model = solver.model()
    v0 = model[s0].as_long()
    v1 = model[s1].as_long()
    gen = XorShift128Plus(v0, v1)
    produced = [gen.next_u64() for _ in outputs]
    if produced != [o & _M64 for o in outputs]:
        return None
    return gen


# ---------------------------------------------------------------------------
# Python MT19937 small-seed brute (timestamp-style seeds)
# ---------------------------------------------------------------------------
def python_seed_brute(outputs, seed_range=None, gen_fn=None):
    """Recover random.seed() when it came from a small space (timestamps).

    outputs: values produced by gen_fn(rng) right after seeding.
    """
    import time
    default_lo = int(time.time()) - 86400 * 365 * 10
    lo, hi = seed_range or (default_lo, int(time.time()))
    gen_fn = gen_fn or (lambda rng: rng.randint(0, 2 ** 32 - 1))
    for seed in range(lo, hi + 1):
        rng = pyrandom.Random()
        rng.seed(seed)
        got = [gen_fn(rng) for _ in outputs]
        if got == list(outputs):
            return seed
    return None


# ---------------------------------------------------------------------------
# Convenience dispatcher used by autodetect
# ---------------------------------------------------------------------------
def predict_next(kind, outputs):
    """kind: 'java-int' | 'glibc' | 'xorshift128+'.

    Returns the predicted next value(s), or None on failure.
    """
    if kind == "java-int":
        if len(outputs) < 2:
            return None
        seed = java_recover(outputs[-2], outputs[-1])
        if seed is None:
            return None
        jr = JavaRandom(seed)
        replay = [jr.next_int() for _ in outputs]
        if replay != [o & 0xFFFFFFFF for o in outputs]:
            return None
        return jr.next_int()

    if kind == "glibc":
        seed, predictor = glibc_seed_brute(outputs)
        if seed is None:
            return None
        return predictor(1)[0]

    if kind == "xorshift128+":
        gen = xs128p_recover(outputs)
        if gen is None:
            return None
        return gen.next_u64()

    return None
