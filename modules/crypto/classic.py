"""Classical cipher solvers: Caesar/ROT, Affine, Atbash, Vigenere (auto
Kasiski), Railfence, Bacon, Playfair, Hill, Columnar transposition and a
hill-climbing substitution solver."""
import itertools
import math
import re
import string
from collections import Counter

from core import flag as flaglib
from .common import (
    chi_square,
    ensure_model,
    invmod,
    score_candidates,
    text_score,
)

ALPHA = string.ascii_lowercase


def _norm(s):
    return re.sub(r"[^a-zA-Z]", "", s).lower()


def _norm_upper(s):
    return re.sub(r"[^a-zA-Z]", "", s).upper()


# ---------------------------------------------------------------------------
# Caesar / ROT
# ---------------------------------------------------------------------------
def caesar_shift(text, shift):
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def solve_caesar(text):
    """Try all 26 shifts, return ranked candidates."""
    cands = [(f"shift {i}", caesar_shift(text, i)) for i in range(26)]
    return score_candidates(cands, top=5)


# ---------------------------------------------------------------------------
# Affine
# ---------------------------------------------------------------------------
def affine_decrypt(text, a, b):
    inv = invmod(a, 26)
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            x = ord(ch) - base
            out.append(chr((inv * (x - b)) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def solve_affine(text):
    cands = []
    for a in range(1, 26):
        if math.gcd(a, 26) != 1:
            continue
        for b in range(26):
            cands.append((f"a={a},b={b}", affine_decrypt(text, a, b)))
    return score_candidates(cands, top=5)


# ---------------------------------------------------------------------------
# Atbash
# ---------------------------------------------------------------------------
def atbash(text):
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"))


# ---------------------------------------------------------------------------
# Vigenere — auto key length via Kasiski + IC, then per-column chi-square
# ---------------------------------------------------------------------------
def _kasiski_keylen(text, max_len=20):
    trigrams = {}
    for i in range(len(text) - 3):
        tri = text[i:i + 3]
        trigrams.setdefault(tri, []).append(i)
    gaps = []
    for positions in trigrams.values():
        if len(positions) >= 2:
            for a, b in itertools.combinations(positions, 2):
                gaps.append(b - a)
    if not gaps:
        return None
    factors = Counter()
    for gap in gaps:
        for f in range(2, max_len + 1):
            if gap % f == 0:
                factors[f] += 1
    if not factors:
        return None
    return factors.most_common(1)[0][0]


def _ic(text):
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def _best_keylen_ic(text, max_len=20):
    best, best_ic = 1, 0.0
    for k in range(1, max_len + 1):
        cols = [text[i::k] for i in range(k)]
        avg = sum(_ic(c) for c in cols) / k
        if abs(avg - 0.066) < abs(best_ic - 0.066):
            best, best_ic = k, avg
    return best


def _solve_vigenere_col(col):
    best_shift, best_chi = 0, float("inf")
    for shift in range(26):
        shifted = "".join(
            chr((ord(c) - 97 + shift) % 26 + 97) if c.isalpha() else c
            for c in col
        )
        chi = chi_square(shifted)
        if chi < best_chi:
            best_chi, best_shift = chi, shift
    return best_shift


_CRIBS = tuple(dict.fromkeys(
    prefix + "{" for prefix in flaglib.known_prefixes()))


def _decrypt_letters(letters, key):
    key_l = [ord(c.lower()) - 97 for c in key]
    return "".join(
        chr((ord(ch) - 97 - key_l[i % len(key_l)]) % 26 + 97)
        for i, ch in enumerate(letters)
    )


def _decrypt_per_char(text, key):
    """Vigenere decrypt where the key index advances on EVERY character
    (including punctuation/braces), not just letters. Some challenges (and
    naive implementations) encrypt this way."""
    key_l = [ord(c.lower()) - 97 for c in key]
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base - key_l[ki % len(key_l)]) % 26 + base))
        else:
            out.append(ch)
        ki += 1
    return "".join(out)


def _key_period(seq):
    """Smallest p >= 1 such that seq repeats with period p."""
    n = len(seq)
    for p in range(1, n):
        if all(seq[i] == seq[i % p] for i in range(n)):
            return p
    return n


def _recover_vigenere_key(text):
    """Try key lengths 2..min(20, len) plus a known-plaintext crib phase
    (the flag prefix), score each full decryption by English-ness and return
    the best (score, keylen, key, dec). The classic IC-picker is too noisy
    on short texts (35-60 chars); the crib phase nails short flag messages
    (e.g. ciphertext starting 'OvgvyGHW{' + crib 'AegisCTF' -> key ORANGE).
    Decryptions are considered under BOTH key-indexing schemes (per-letter
    and per-character) because naive implementations shift on every char."""
    letters = _norm(text)
    best = None

    def consider(key, dec):
        nonlocal best
        try:
            s = text_score(dec)
        except Exception:
            s = float("inf")
        if best is None or s < best[0]:
            best = (s, len(key), key, dec)

    # 1) plain key-length sweep (works on longer messages)
    for kl in range(2, min(20, len(letters)) + 1):
        key = "".join(ALPHA[_solve_vigenere_col(letters[i::kl])] for i in range(kl))
        consider(key, _decrypt_letters(letters, key))
        consider(key, _decrypt_per_char(text, key))

    # 2) crib phase: derive key letters from a known flag prefix
    for crib in _CRIBS:
        c = re.sub(r"[^a-zA-Z]", "", crib).lower()
        if len(letters) < len(c):
            continue
        derived = "".join(
            ALPHA[(ord(cph) - 97 - (ord(pl) - 97)) % 26]
            for cph, pl in zip(letters, c)
        )
        p = _key_period(derived)
        key = list(derived[:p])
        for i in range(p):
            if i >= len(derived):
                key[i] = ALPHA[_solve_vigenere_col(letters[i::p])]
        key = "".join(key)
        consider(key, _decrypt_letters(letters, key))
        consider(key, _decrypt_per_char(text, key))
    return best


def vigenere_encrypt(text, key):
    key_l = [ord(c.lower()) - 97 for c in key]
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + key_l[ki % len(key_l)]) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_decrypt(text, key=None):
    """If key is None, recover it automatically. Returns (key, plaintext)."""
    letters = _norm(text)
    if not letters:
        return None, text
    if key is None:
        rec = _recover_vigenere_key(text)
        if rec:
            _, _, key, plain_letters = rec
            # the best decryption may use per-char indexing — recompute both
            # and return the better one against the ORIGINAL text
            k1 = _decrypt_letters(letters, key)
            k2 = _decrypt_per_char(text, key)
            try:
                if text_score(k2) < text_score(k1):
                    return key, k2
            except Exception:
                pass
            # rebuild per-letter decryption with original case/punct
            key_l = [ord(c.lower()) - 97 for c in key]
            out = []
            ki = 0
            for ch in text:
                if ch.isalpha():
                    base = ord("A") if ch.isupper() else ord("a")
                    out.append(chr((ord(ch) - base - key_l[ki % len(key_l)]) % 26 + base))
                    ki += 1
                else:
                    out.append(ch)
            return key, "".join(out)
    key_l = [ord(c.lower()) - 97 for c in key]
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base - key_l[ki % len(key_l)]) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return key, "".join(out)


def solve_vigenere(text):
    cands = []
    key, plain = vigenere_decrypt(text)
    if key:
        cands.append((f"key={key}", plain))
    return score_candidates(cands, top=3)


# ---------------------------------------------------------------------------
# Rail fence
# ---------------------------------------------------------------------------
def railfence_decrypt(text, rails):
    n = len(text)
    if rails < 2 or rails >= n:
        return text
    cycle = 2 * (rails - 1)
    positions = []
    for r in range(rails):
        for i in range(n):
            pos = i % cycle
            if pos == r or pos == cycle - r:
                positions.append(i)
    positions.sort()
    mapping = {pos: ch for pos, ch in zip(positions, text)}
    return "".join(mapping[i] for i in range(n))


def solve_railfence(text):
    cands = [
        (f"rails={r}", railfence_decrypt(text, r))
        for r in range(2, max(3, min(30, len(text))))
    ]
    return score_candidates(cands, top=5)


# ---------------------------------------------------------------------------
# Bacon
# ---------------------------------------------------------------------------
BACON = {
    "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E",
    "AABAB": "F", "AABBA": "G", "AABBB": "H", "ABAAA": "I", "ABAAB": "K",
    "ABABA": "L", "ABABB": "M", "ABBAA": "N", "ABBAB": "O", "ABBBA": "P",
    "ABBBB": "Q", "BAAAA": "R", "BAAAB": "S", "BAABA": "T", "BAABB": "U",
    "BABAA": "W", "BABAB": "X", "BABBA": "Y", "BABBB": "Z",
}


def dec_bacon(text, alphabet="AB"):
    up = text.upper()
    # a string of 0s and 1s ("binary-looking") is Bacon with 0->A, 1->B
    if up and all(c in "01 \n\t\r" for c in up):
        up = up.translate(str.maketrans("01", "AB"))
    bits = "".join(c for c in up if c in alphabet)
    out = []
    for i in range(0, len(bits) - 4, 5):
        chunk = bits[i:i + 5]
        out.append(BACON.get(chunk, "?"))
    return "".join(out)


# ---------------------------------------------------------------------------
# Playfair (given key)
# ---------------------------------------------------------------------------
def _playfair_square(key):
    key = _norm_upper(key).replace("J", "I")
    seen = set()
    square = []
    for ch in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.add(ch)
            square.append(ch)
    return square


def _playfair_clean(text):
    clean = _norm_upper(text).replace("J", "I")
    # insert filler X between repeated letters in a digraph
    out = []
    i = 0
    while i < len(clean):
        out.append(clean[i])
        if i + 1 < len(clean) and clean[i] == clean[i + 1]:
            out.append("X")
        i += 1
    if len(out) % 2:
        out.append("X")
    return "".join(out)


def playfair_encrypt(text, key):
    square = _playfair_square(key)
    pos = {c: (i // 5, i % 5) for i, c in enumerate(square)}
    clean = _playfair_clean(text)
    out = []
    for i in range(0, len(clean), 2):
        a, b = clean[i], clean[i + 1]
        r1, c1 = pos[a]
        r2, c2 = pos[b]
        if r1 == r2:
            out.append(square[r1 * 5 + (c1 + 1) % 5])
            out.append(square[r2 * 5 + (c2 + 1) % 5])
        elif c1 == c2:
            out.append(square[((r1 + 1) % 5) * 5 + c1])
            out.append(square[((r2 + 1) % 5) * 5 + c2])
        else:
            out.append(square[r1 * 5 + c2])
            out.append(square[r2 * 5 + c1])
    return "".join(out)


def playfair_decrypt(text, key):
    square = _playfair_square(key)
    pos = {c: (i // 5, i % 5) for i, c in enumerate(square)}
    clean = _norm_upper(text).replace("J", "I")
    if len(clean) % 2:
        clean += "X"
    out = []
    for i in range(0, len(clean), 2):
        a, b = clean[i], clean[i + 1]
        r1, c1 = pos[a]
        r2, c2 = pos[b]
        if r1 == r2:
            out.append(square[r1 * 5 + (c1 - 1) % 5])
            out.append(square[r2 * 5 + (c2 - 1) % 5])
        elif c1 == c2:
            out.append(square[((r1 - 1) % 5) * 5 + c1])
            out.append(square[((r2 - 1) % 5) * 5 + c2])
        else:
            out.append(square[r1 * 5 + c2])
            out.append(square[r2 * 5 + c1])
    return "".join(out)


# ---------------------------------------------------------------------------
# Hill cipher (given key). Key as letters (length 4 or 9) or numbers.
# ---------------------------------------------------------------------------
def _parse_hill_key(key):
    k = key.replace(",", " ").split()
    nums = []
    for tok in k:
        if tok.isdigit():
            nums.append(int(tok))
        else:
            for ch in tok:
                if ch.isalpha():
                    nums.append(ord(ch.upper()) - 65)
    return nums


def hill_decrypt(text, key):
    nums = _parse_hill_key(key)
    if len(nums) not in (4, 9):
        raise ValueError("Hill key must be 4 or 9 numbers/letters")
    size = int(math.sqrt(len(nums)))
    mat = [nums[i * size:(i + 1) * size] for i in range(size)]
    det = mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0] if size == 2 else (
        mat[0][0] * (mat[1][1] * mat[2][2] - mat[1][2] * mat[2][1])
        - mat[0][1] * (mat[1][0] * mat[2][2] - mat[1][2] * mat[2][0])
        + mat[0][2] * (mat[1][0] * mat[2][1] - mat[1][1] * mat[2][0]))
    det_mod = det % 26
    if math.gcd(det_mod, 26) != 1:
        raise ValueError("key matrix not invertible mod 26")
    det_inv = invmod(det_mod, 26)
    if size == 2:
        inv = [[mat[1][1] * det_inv % 26, -mat[0][1] * det_inv % 26],
               [-mat[1][0] * det_inv % 26, mat[0][0] * det_inv % 26]]
    else:
        def adj3(m):
            def cof(i, j):
                sub = [[m[r][c] for c in range(3) if c != j] for r in range(3) if r != i]
                return (sub[0][0] * sub[1][1] - sub[0][1] * sub[1][0])
            return [[cof(j, i) % 26 for j in range(3)] for i in range(3)]
        adj = adj3(mat)
        inv = [[(adj[r][c] * det_inv) % 26 for c in range(3)] for r in range(3)]
    clean = _norm_upper(text)
    if len(clean) % size:
        clean += "X" * (size - len(clean) % size)
    out = []
    for i in range(0, len(clean), size):
        vec = [ord(c) - 65 for c in clean[i:i + size]]
        out.extend(
            chr((sum(inv[r][c] * vec[c] for c in range(size)) % 26) + 65)
            for r in range(size)
        )
    return "".join(out)


# ---------------------------------------------------------------------------
# Columnar transposition (auto key length via score)
# ---------------------------------------------------------------------------
def columnar_decrypt(text, cols):
    n = len(text)
    rows = math.ceil(n / cols)
    grid = [[""] * cols for _ in range(rows)]
    idx = 0
    for c in range(cols):
        for r in range(rows):
            if idx < n:
                grid[r][c] = text[idx]
                idx += 1
    return "".join(grid[r][c] for r in range(rows) for c in range(cols))


def solve_columnar(text):
    cands = []
    for cols in range(2, min(20, len(text))):
        cands.append((f"cols={cols}", columnar_decrypt(text, cols)))
    return score_candidates(cands, top=5)


# ---------------------------------------------------------------------------
# Substitution cipher — hill climbing with trigram model
# ---------------------------------------------------------------------------
def _substitute(text, mapping):
    tbl = str.maketrans(mapping)
    return text.translate(tbl)


def solve_substitution(text, iterations=None):
    """Substitution solver using simulated annealing on a quadgram model
    (english_quadgrams.txt when available, trigram model otherwise).
    Starts from a frequency-ordered mapping plus every Caesar shift; the
    best seeds get a long refinement run."""
    from .common import quadgram_score, load_quadgrams

    letters = _norm(text)
    if not letters or len(letters) < 20:
        return []
    # Long inputs are almost never substitution ciphertext — they are source
    # code / logs / HTML that slipped into the pipeline (annealing on 1500+
    # chars of Python source costs tens of seconds for zero signal). Real
    # substitution CTF challenges are short (100-2000 letters) and nearly
    # all-alphabetic (punct-heavy Python source is not a monoalphabetic
    # substitution).
    if len(letters) > 3000:
        return []
    non_alpha = sum(1 for c in text if not c.isalpha()) / max(len(text), 1)
    if non_alpha > 0.30 and not re.fullmatch(r"[01ABab\s]+", text.strip()):
        return []
    import random
    rng = random.Random(1337)
    has_quad = load_quadgrams()

    def score(mapping):
        tbl = str.maketrans(mapping)
        dec = letters.translate(tbl)
        if has_quad:
            s = quadgram_score(dec)
            if s is not None:
                return s
        # fallback trigram scoring
        total = 0.0
        for i in range(len(dec) - 2):
            tri = dec[i:i + 3]
            total += math.log(_TRIGRAMS.get(tri, 0.0) + 1e-5)
        return total

    def anneal(start, its):
        cur = start.copy()
        cur_score = score(cur)
        best = cur.copy()
        best_score = cur_score
        t0 = 5.0 if has_quad else 3.0
        for it in range(its):
            a, b = rng.sample(ALPHA, 2)
            new = cur.copy()
            new[a], new[b] = new[b], new[a]
            s = score(new)
            if s > cur_score or rng.random() < math.exp((s - cur_score) / t0):
                cur, cur_score = new, s
            if cur_score > best_score:
                best, best_score = cur.copy(), cur_score
            t0 *= 0.9995
        return best, best_score

    from collections import Counter
    freq_order = [c for c, _ in Counter(letters).most_common()]
    english_order = [
        "e", "t", "a", "o", "i", "n", "s", "h", "r", "d", "l", "u",
        "c", "m", "f", "w", "y", "p", "v", "b", "g", "k", "q", "j",
        "x", "z",
    ]
    start = {c: c for c in ALPHA}
    for cl, en in zip(freq_order, english_order):
        start[cl] = en
    seeds = [start] + [
        {c: ALPHA[(ALPHA.index(c) + shift) % 26] for c in ALPHA}
        for shift in range(26)
    ]

    if iterations is None:
        n = len(letters)
        iterations = max(2000, min(40000, n * 150))

    # quick screen: short run on every seed
    screened = []
    for seed in seeds:
        m, s = anneal(seed, max(200, iterations // 10))
        screened.append((s, m))
    screened.sort(key=lambda x: x[0], reverse=True)

    best_overall, best_overall_score = None, -float("inf")
    for _, seed in screened[:3]:
        m, s = anneal(seed, iterations)
        if s > best_overall_score:
            best_overall, best_overall_score = m, s
    plain = _substitute(text, best_overall)
    return [(f"substitution (score={best_overall_score:.2f})", plain)]


def try_all_classic(text):
    """Run every classic solver family CONCURRENTLY (they are independent
    pure functions) and merge their candidates."""
    from core.parallel import run_concurrent

    def _safe(fn):
        def wrapper():
            try:
                return fn()
            except Exception:
                return []
        return wrapper

    letters_hc = _norm(text)

    def job_quick():
        out = []
        out.append(("atbash", atbash(text)))
        out.extend(solve_caesar(text))
        out.extend(solve_affine(text))
        return out

    def job_vigenere():
        return list(solve_vigenere(text))

    def job_beaufort():
        return list(solve_beaufort_variants(text))

    def job_transpositions():
        out = []
        out.extend(solve_railfence(text))
        out.extend(solve_columnar(text))
        return out

    def job_patterns():
        out = []
        if re.fullmatch(r"[abAB01\s]+", text):
            out.append(("bacon", dec_bacon(text)))
        if re.fullmatch(r"[2-9\s]+", text) and len(text.strip()) >= 6:
            out.append(("multitap-t9", dec_multitap(text)))
        stripped = text.strip()
        if re.fullmatch(r"[1-5\s]+", stripped) and \
                len(re.sub(r"\s", "", stripped)) % 2 == 0 and \
                len(stripped) >= 4:
            out.append(("polybius", dec_polybius(stripped)))
        return out

    def job_keyboard():
        out = []
        if len(_norm(text)) >= 8:
            for steps in (1, 2, -1, -2):
                kb = keyboard_shift_decode(text, steps)
                score = text_score(kb)
                if score < 400:
                    out.append((f"keyboard-shift({steps:+d})", kb))
        return out

    def job_substitution():
        try:
            return list(solve_substitution(text))
        except Exception:
            return []

    jobs = [
        ("── caesar/affine/atbash ──", job_quick),
        ("── vigenere ──", job_vigenere),
        ("── beaufort family ──", job_beaufort),
        ("── railfence/columnar ──", job_transpositions),
        ("── patterns ──", job_patterns),
        ("── keyboard ──", job_keyboard),
        ("── substitution ──", job_substitution),
    ]
    results = []
    outputs = run_concurrent([_safe(fn) for _, fn in jobs],
                             workers=len(jobs), desc="classic")
    for (_title, res) in zip(jobs, outputs):
        if isinstance(res, Exception):
            continue
        results.extend(res)

    # hill-climb booster for vigenere: only when nothing convincingly
    # English came out of the parallel pass
    if len(letters_hc) >= 10 and letters_hc.isalpha():
        need_climb = True
        for entry in results:
            dec = entry[-1]
            if isinstance(dec, str) and _english_fitness(dec) >= _GOOD_FITNESS:
                need_climb = False
                break
        if need_climb and len(letters_hc) <= 400:
            minus = lambda kk, vv: (vv - kk) % 26
            hc_ranked = []
            for keylen in _vigenere_keylen_candidates(letters_hc):
                restarts = 6 if keylen <= 4 and len(letters_hc) <= 120 else (
                    3 if len(letters_hc) <= 160 else 1)
                kv, fit_, dec = periodic_hillclimb(
                    letters_hc, minus, keylen, restarts=restarts)
                hc_ranked.append(
                    (fit_ - 0.06 * keylen,
                     f"vigenere-hc key={''.join(str(k) for k in kv)}",
                     dec))
            hc_ranked.sort(key=lambda r: -r[0])
            results.extend((lbl, dec) for _, lbl, dec in hc_ranked[:2])
    return results
    return results


# ---------------------------------------------------------------------------
# Beaufort / Variant Beaufort / Gronsfeld
# ---------------------------------------------------------------------------
def beaufort_decrypt(text, key):
    """Beaufort: plain = key - cipher (mod 26); self-reciprocal in encrypt."""
    return _shift_map(text, key, lambda kk, vv: (kk - vv) % 26)


def variant_beaufort_decrypt(text, key):
    """Variant Beaufort (encrypt = plain - key): plain = cipher + key."""
    return _shift_map(text, key, lambda kk, vv: (vv + kk) % 26)


def vigenere_family_decrypt(text, key):
    """Classic Vigenere: plain = cipher - key."""
    return _shift_map(text, key, lambda kk, vv: (vv - kk) % 26)


def _shift_map(text, key, combine):
    key_l = [ord(c.lower()) - 97 for c in re.sub(r"[^a-zA-Z]", "", key)]
    if not key_l:
        return text
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            v = ord(ch.lower()) - 97
            out.append(chr(combine(key_l[ki % len(key_l)], v) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def _english_fitness(text):
    """Higher = better English. Quadgram fitness when the model exists
    (robust for unspaced letters), chi-square composite otherwise."""
    from .common import load_quadgrams, quadgram_score
    try:
        load_quadgrams()
        q = quadgram_score(text)
        if q is not None:
            return q / max(len(re.sub(r"[^a-zA-Z]", "", text)), 1)
    except Exception:
        pass
    s = text_score(text)
    return -s if s != float("inf") else -1e9


def _neg_alpha(text):
    """Map every letter c -> (26 - c) mod 26 preserving case/punctuation."""
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((26 - (ord(ch.lower()) - 97)) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def solve_beaufort_variants(text):
    """Auto-solve Beaufort / Variant Beaufort / Gronsfeld.

    All three are periodic additive ciphers over the same algebra:
      classic beaufort: P = K - C
      variant-beaufort: P = C + K
      gronsfeld:        P = C - K (digit keys)
    so one quadgram hill-climb engine handles them all; the classic
    Vigenere reduction through solve_vigenere adds crib-phase hits.
    """
    letters_only = _norm(text)
    if len(letters_only) < 10 or not letters_only.isalpha():
        return []

    results = []
    for entry in solve_vigenere(_neg_alpha(text)) or []:
        results.append((f"beaufort via-vigenere {entry[1]}", entry[-1]))
        break  # top hit only; dedicated climb below covers the rest

    jobs = (("beaufort", lambda kk, vv: (kk - vv) % 26, False),
            ("variant-beaufort", lambda kk, vv: (vv + kk) % 26, False),
            ("gronsfeld", lambda kk, vv: (vv - kk) % 26, True))

    for name, combine, digits_only in jobs:
        ranked = []
        for keylen in _vigenere_keylen_candidates(letters_only):
            if keylen > len(letters_only):
                continue
            restarts = 6 if keylen <= 4 and len(letters_only) <= 120 else (
                3 if len(letters_only) <= 160 else 1)
            kv, fit_, dec = periodic_hillclimb(
                letters_only, combine, keylen,
                digits_only=digits_only, restarts=restarts)
            # penalise long keys: a longer key can always mimic a shorter
            # one (repetition) and tends to overfit quadgram fitness
            label = f"{name} key={''.join(str(k) for k in kv)}"
            ranked.append((fit_ - 0.06 * keylen, label, dec))
        ranked.sort(key=lambda r: -r[0])
        results.extend((lbl, dec) for _, lbl, dec in ranked[:2])
    return results


# ---------------------------------------------------------------------------
# Keyboard shift (QWERTY neighbour typing) + phone keypad multi-tap +
# Polybius square — cheap decoders that cover a surprising number of misc
# crypto challenges.
# ---------------------------------------------------------------------------
_KB_ROWS = ("1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./")


def keyboard_shift_decode(text, steps=1):
    """Map each character `steps` keys to the LEFT on a US QWERTY layout.

    Decodes text typed with hands offset by one key (e.g. 'ypu;' -> 'hot '
    style errors are handled per character).
    """
    pos = {}
    for row in _KB_ROWS:
        for ci, ch in enumerate(row):
            pos[ch] = ci
    out = []
    for ch in text:
        low = ch.lower()
        if low in pos:
            row = next(r for r in _KB_ROWS if low in r)
            new = row[(pos[low] - steps) % len(row)]
            out.append(new.upper() if ch.isupper() else new)
        else:
            out.append(ch)
    return "".join(out)


_T9_MAP = {"2": "abc", "3": "def", "4": "ghi", "5": "jkl",
           "6": "mno", "7": "pqrs", "8": "tuv", "9": "wxyz"}


def dec_multitap(text):
    """Old-phone multi-tap: '44 33 555 555 666' and '4433555 555666'
    both decode to 'hello'.  Single spaces are letter separators; two or
    more consecutive spaces become a real word break."""
    out = []
    for token in re.split(r"(\s+)", text.strip()):
        if not token:
            continue
        if token.isspace():
            out.append(" " if len(token) > 1 else "")
            continue
        i = 0
        while i < len(token):
            j = i
            while j < len(token) and token[j] == token[i]:
                j += 1
            digit = token[i]
            if digit in _T9_MAP:
                letters = _T9_MAP[digit]
                out.append(letters[(j - i - 1) % len(letters)])
            else:
                out.append(digit)
            i = j
    return "".join(out).strip()


def dec_polybius(text):
    """5x5 Polybius square (11..55, I/J merged) from digit pairs."""
    digits = re.sub(r"[^1-5]", "", text)
    if not digits or len(digits) % 2:
        return text
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    return "".join(alphabet[(int(a) - 1) * 5 + int(b) - 1]
                   for a, b in zip(digits[::2], digits[1::2]))


# ---------------------------------------------------------------------------
# Generic periodic-shift hill climber (Vigenere family workhorse)
# ---------------------------------------------------------------------------
_FIT_CACHE = {}


def _cached_fitness(txt):
    f = _FIT_CACHE.get(txt)
    if f is None:
        f = _english_fitness(txt)
        if len(_FIT_CACHE) < 200_000:
            _FIT_CACHE[txt] = f
    return f


_GOOD_FITNESS = -6.2   # per-letter quadgram; solid English territory


def periodic_hillclimb(letters, combine, keylen, digits_only=False,
                       restarts=4, rng=None):
    """Recover a periodic additive key over `letters` (lowercase a-z only).

    combine(key_val, cipher_val) -> plain_val.  Seeds each column by
    chi-square, runs coordinate ascent on full-text quadgram fitness from
    several randomized restarts, and stops early once a candidate reaches
    clearly-English fitness.  Returns (key_vals, fitness, plaintext).
    """
    import random as _random
    if rng is None:
        rng = _random.Random(0x5EED + len(letters) * 31 + keylen * 7)
    vals = [ord(c) - 97 for c in letters]
    choices = list(range(10) if digits_only else range(26))

    def decrypt(kv):
        m = len(kv)
        return "".join(chr(combine(kv[j % m], v) % 26 + 97)
                       for j, v in enumerate(vals))

    def col_seed():
        kv = []
        for i in range(keylen):
            col = vals[i::keylen]
            best, best_chi = 0, float("inf")
            for k in choices:
                d = "".join(chr(combine(k, v) % 26 + 97) for v in col)
                c = chi_square(d)
                if c < best_chi:
                    best_chi, best = c, k
            kv.append(best)
        return kv

    def ascend(kv):
        kv = list(kv)
        m = len(kv)
        for _pass in range(6):
            changed = False
            for i in range(m):
                saved = kv[i]
                best_k, best_s = saved, _cached_fitness(decrypt(kv))
                for k in choices:
                    if k == saved:
                        continue
                    kv[i] = k
                    s = _cached_fitness(decrypt(kv))
                    if s > best_s:
                        best_s, best_k = s, k
                kv[i] = best_k
                if best_k != saved:
                    changed = True
                    if best_s >= _GOOD_FITNESS:
                        return kv
            if not changed:
                break
        # coordinate ascent can stall on short/pathological texts (e.g.
        # pangrams) — finish with a short simulated-annealing walk
        import math as _math
        cur_f = _cached_fitness(decrypt(kv))
        best_kv, best_f = kv[:], cur_f
        iters = 1200 if len(vals) <= 200 else 400
        for it in range(iters):
            temp = max(0.02, 1.8 * (1 - it / iters))
            i = rng.randrange(m)
            old = kv[i]
            kv[i] = choices[(choices.index(old) +
                             rng.choice((-3, -2, -1, 1, 2, 3))) % len(choices)]
            f = _cached_fitness(decrypt(kv))
            if f > cur_f or rng.random() < _math.exp((f - cur_f) / temp):
                cur_f = f
                if f > best_f:
                    best_f = f
                    best_kv = kv[:]
                    if best_f >= _GOOD_FITNESS:
                        return best_kv
            else:
                kv[i] = old
        return best_kv

    seeds = [col_seed()]
    for _ in range(max(1, restarts)):
        seeds.append([rng.choice(choices) for _ in range(keylen)])
    best_kv, best_fit = None, -1e18
    for seed in seeds:
        kv = ascend(seed)
        f = _cached_fitness(decrypt(kv))
        if f > best_fit:
            best_fit, best_kv = f, kv[:]
            if best_fit >= _GOOD_FITNESS:
                break
    # short texts: hill-climbing starves on thin per-column signal, so
    # brute-force the cross-product of each column's top-3 chi candidates
    if best_fit < _GOOD_FITNESS and len(vals) <= 140 and keylen <= 6:
        col_cands = []
        for i in range(keylen):
            col = vals[i::keylen]
            scored = []
            for k in choices:
                d = "".join(chr(combine(k, v) % 26 + 97) for v in col)
                scored.append((chi_square(d), k))
            scored.sort()
            col_cands.append([k for _, k in scored[:3]])
        tried = 0
        import itertools as _it
        for combo in _it.product(*col_cands):
            f = _cached_fitness(decrypt(list(combo)))
            if f > best_fit:
                best_fit, best_kv = f, list(combo)
                if best_fit >= _GOOD_FITNESS:
                    break
            tried += 1
            if tried > 900:
                break
    return best_kv, best_fit, decrypt(best_kv)


def _vigenere_keylen_candidates(letters):
    probe = _norm_upper(letters)
    out = set()
    try:
        out.add(int(_best_keylen_ic(
            probe, max_len=min(20, max(2, len(probe) // 3)))))
    except Exception:
        pass
    kas = _kasiski_keylen(probe)
    if kas:
        out.add(int(kas))
    limit = min(10, max(2, len(letters) // 2))
    if len(letters) <= 160:
        out.update(range(1, limit))
    else:
        for extra in (out.copy()):
            out.add(min(20, extra + 1))
            out.add(max(1, extra - 1))
    return sorted(k for k in out if 1 <= k <= max(2, len(letters)))
