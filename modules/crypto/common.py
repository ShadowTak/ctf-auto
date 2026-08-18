"""Shared crypto helpers: text scoring, English n-gram model, math utils."""
import math
import os
import re
import string
from collections import Counter

# ---------------------------------------------------------------------------
# English n-gram model (built from an embedded corpus so the tool is offline)
# ---------------------------------------------------------------------------
_CORPUS = """
The quick brown fox jumps over the lazy dog while the five boxing wizards
jump quickly. The flag is hidden somewhere inside this text and every
challenge expects you to find it as fast as possible. Capture the flag
competitions are a great way to learn about security and cryptography.
Players often start with simple encodings and work their way up to complex
mathematical attacks. Decoding is the art of turning gibberish back into
meaningful words that make sense to a human reader. When you solve a puzzle
you should always write down the answer because the answer is what gets you
points on the scoreboard. Teams race against the clock to break ciphers and
exploit vulnerable services before other teams do the same thing first.
The most common letters in the English language are e t a o i n s h r d l u.
Frequency analysis works by counting how often each letter appears in the
ciphertext and comparing those counts with the known distribution of the
language. Simple substitution ciphers are vulnerable to this kind of attack
because the mapping is fixed for the whole message. Polyalphabetic ciphers
like the Vigenere were invented to resist simple frequency analysis but they
too can be broken when the key is short and the message is long. Modern
cryptography relies on hard mathematical problems rather than secrecy of the
algorithm. The security of RSA depends on the difficulty of factoring large
numbers while elliptic curves use the difficulty of the discrete logarithm.
Always remember to look for patterns because humans are lazy and tend to
repeat themselves when they choose keys and passwords. A weak key can undo
even the strongest cipher in the world. Never reuse a one time pad and never
roll your own crypto unless you really know what you are doing. The best
solutions are usually the simplest ones that work reliably every single time.
"""
_TRIGRAMS = None
_BIGRAMS = None


def _build_model():
    global _TRIGRAMS, _BIGRAMS
    text = re.sub(r"[^a-z ]", "", _CORPUS.lower())
    _TRIGRAMS = Counter()
    _BIGRAMS = Counter()
    for i in range(len(text) - 2):
        _TRIGRAMS[text[i:i + 3]] += 1
    for i in range(len(text) - 1):
        _BIGRAMS[text[i:i + 2]] += 1
    total_t = sum(_TRIGRAMS.values())
    total_b = sum(_BIGRAMS.values())
    _TRIGRAMS = {k: v / total_t for k, v in _TRIGRAMS.items()}
    _BIGRAMS = {k: v / total_b for k, v in _BIGRAMS.items()}


def ensure_model():
    if _TRIGRAMS is None:
        _build_model()


# ---------------------------------------------------------------------------
# Quadgram model (the gold standard for substitution-cipher scoring).
# Loaded lazily from data/english_quadgrams.txt when present; falls back to
# the trigram model above otherwise.
# ---------------------------------------------------------------------------
_QUADGRAMS = None
_QUAD_TOTAL = None
_QUAD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "english_quadgrams.txt")


def load_quadgrams():
    global _QUADGRAMS, _QUAD_TOTAL
    if _QUADGRAMS is not None:
        return _QUADGRAMS is not None
    _QUADGRAMS = {}
    try:
        if os.path.exists(_QUAD_PATH):
            with open(_QUAD_PATH, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) == 2 and len(parts[0]) == 4:
                        # file is uppercase; store lowercase keys
                        _QUADGRAMS[parts[0].lower()] = int(parts[1])
    except Exception:
        _QUADGRAMS = {}
    _QUAD_TOTAL = sum(_QUADGRAMS.values())
    return bool(_QUADGRAMS)


def quadgram_score(text):
    """Sum of log-probabilities of overlapping quadgrams. Higher = better.
    Returns None if the quadgram model is unavailable."""
    if not load_quadgrams():
        return None
    clean = re.sub(r"[^a-z]", "", text.lower())
    if len(clean) < 4:
        return None
    total = 0.0
    for i in range(len(clean) - 3):
        q = clean[i:i + 4]
        cnt = _QUADGRAMS.get(q, 0)
        total += math.log((cnt + 1) / _QUAD_TOTAL)
    return total


# ---------------------------------------------------------------------------
# Letter frequency tables
# ---------------------------------------------------------------------------
ENGLISH_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702,
    "f": 2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153,
    "k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749, "o": 7.507,
    "p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056,
    "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150, "y": 1.974,
    "z": 0.074,
}

COMMON_WORDS = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it",
    "for", "not", "on", "with", "he", "as", "you", "do", "at", "this",
    "but", "his", "by", "from", "they", "we", "say", "her", "she", "or",
    "an", "will", "my", "one", "all", "would", "there", "their", "what",
    "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
    "flag", "is", "are", "was", "were", "been", "has", "had", "have",
}


def chi_square(text):
    """Lower = better fit to English letter distribution."""
    letters = [c for c in text.lower() if c in string.ascii_lowercase]
    if not letters:
        return float("inf")
    n = len(letters)
    counts = Counter(letters)
    chi = 0.0
    for ch, expected in ENGLISH_FREQ.items():
        observed = counts.get(ch, 0) / n * 100.0
        chi += (observed - expected) ** 2 / expected
    return chi


_ALLOWED_TEXT = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789 \n{}_!?.,;:'\"()-+/="
)


def text_score(text):
    """Composite score: lower = more English-like. Hard-rejects control and
    non-ASCII bytes; rewards common words, lowercase letters and clean
    characters; penalizes weird punctuation. The chi-square term is
    length-normalized because short samples are noisy."""
    if not text:
        return float("inf")
    n = len(text)
    printable = sum(1 for c in text if c.isprintable() or c == "\n")
    if printable < n * 0.95:
        return float("inf")
    for c in text:
        o = ord(c)
        if (o < 32 and c != "\n") or o > 126:
            return float("inf")
    alpha = [c for c in text if c.isalpha()]
    if not alpha or len(alpha) < n * 0.4:
        return float("inf")
    lowercase_ratio = sum(1 for c in alpha if c.islower()) / len(alpha)
    words = re.findall(r"[a-z]+", text.lower())
    if not words:
        return float("inf")
    chi_norm = chi_square(" ".join(words)) / max(len(words), 5)
    common_hits = sum(1 for w in set(words) if w in COMMON_WORDS)
    word_bonus = (common_hits * 4.0) / max(len(set(words)), 3)
    weird = sum(1 for c in text if c not in _ALLOWED_TEXT)
    return chi_norm - word_bonus - lowercase_ratio * 5.0 + weird * 2.0


def score_candidates(candidates, top=10):
    """candidates: list of (label, text). Returns ranked list."""
    scored = []
    for label, text in candidates:
        try:
            s = text_score(text)
        except Exception:
            s = float("inf")
        if s != float("inf"):
            scored.append((s, label, text))
    scored.sort(key=lambda x: x[0])
    return scored[:top]


def is_probable_english(text, threshold=220):
    """Cheap gate used to filter out garbage decodes."""
    s = text_score(text)
    return s < threshold and s != float("inf")


# ---------------------------------------------------------------------------
# Math helpers
# ---------------------------------------------------------------------------
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x


def invmod(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def iroot(n, k):
    """Integer k-th root (floor) — Newton's method, no floats. The float
    guess in older versions lost precision on big numbers (10^83 off for a
    979-bit input) and looped forever."""
    if n < 0:
        raise ValueError("negative")
    if n == 0:
        return 0
    if k == 1:
        return n
    # upper-bound start via bit length, then Newton converge
    bits = n.bit_length()
    x = 1 << ((bits + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            break
        x = y
    while x ** k > n:
        x -= 1
    while (x + 1) ** k <= n:
        x += 1
    return x


def isqrt(n):
    if n < 0:
        raise ValueError("negative")
    if n == 0:
        return 0
    x = int(math.isqrt(n))
    return x


def gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)


def modpow(b, e, m):
    return pow(b, e, m)


def long_to_bytes(n):
    if n == 0:
        return b"\x00"
    n = int(n)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def bytes_to_long(b):
    return int.from_bytes(bytes(b), "big")


def strip_zeros(b):
    return bytes(b).lstrip(b"\x00")


def is_printable_text(s, min_ratio=0.85):
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return printable / len(s) >= min_ratio


def looks_like_encoding(text, min_len=12):
    """True when the input is clearly an encoding (base64/hex/binary/…)
    rather than natural-language ciphertext — used to skip expensive classic
    solvers (substitution, vigenere) that would waste time on encoded data."""
    if not text:
        return True
    compact = re.sub(r"\s+", "", text)
    if len(compact) < min_len:
        return False
    # real sentences almost always contain spaces
    if " " in text or "\t" in text:
        return False
    if len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return True  # base64-ish blob
    if re.fullmatch(r"[0-9a-fA-Fx]+|x[0-9a-fA-F]+|[0-9a-fA-F]{2}(?:[0-9a-fA-F]{2})+", compact):
        return True  # hex (incl. \x escapes)
    if re.fullmatch(r"[01\s]+", compact):
        return True  # binary
    letters = sum(1 for c in compact if c.isalpha())
    if letters / max(len(compact), 1) < 0.6:
        return True  # too much punctuation/digits for a text cipher
    return False
