"""Classical cipher solvers: Caesar/ROT, Affine, Atbash, Vigenere (auto
Kasiski), Railfence, Bacon, Playfair, Hill, Columnar transposition and a
hill-climbing substitution solver."""
import itertools
import math
import re
import string
from collections import Counter

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


_CRIBS = ("AegisCTF{", "AEGIS{", "aegis{", "FLAG{", "flag{", "picoCTF{",
          "PicoCTF{", "HTB{", "CTF{", "ctf{", "DUCTF{", "N0PS{")


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


# ---------------------------------------------------------------------------
# Public entry: try every classic solver
# ---------------------------------------------------------------------------
def try_all_classic(text):
    results = []
    results.append(("atbash", atbash(text)))
    results.extend(solve_caesar(text))
    results.extend(solve_affine(text))
    cands = solve_vigenere(text)
    results.extend(cands)
    results.extend(solve_railfence(text))
    cands = solve_columnar(text)
    results.extend(cands)
    if re.fullmatch(r"[abAB01\s]+", text):
        results.append(("bacon", dec_bacon(text)))
    try:
        results.extend(solve_substitution(text))
    except Exception:
        pass
    return results
