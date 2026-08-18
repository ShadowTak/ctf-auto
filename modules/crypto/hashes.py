"""Hash identification + wordlist cracking with common mutations."""
import hashlib
import os
import re
from concurrent.futures import ThreadPoolExecutor

WORDLISTS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "wordlists"))


# ---------------------------------------------------------------------------
# Pure-python MD4 (OpenSSL 3 disabled md4; NTLM needs it)
# ---------------------------------------------------------------------------
def _md4(data):
    """RFC 1320 MD4. (hashlib dropped md4 on OpenSSL 3.)"""
    data = bytes(data)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z

    ml = len(data) * 8
    data += b"\x80"
    while len(data) % 64 != 56:
        data += b"\x00"
    data += ml.to_bytes(8, "little")

    for off in range(0, len(data), 64):
        x = [int.from_bytes(data[off + 4 * i: off + 4 * i + 4], "little") for i in range(16)]
        aa, bb, cc, dd = a, b, c, d
        s1 = [3, 7, 11, 19]
        for i in range(16):
            a, b, c, d = d, rol((a + F(b, c, d) + x[i]) & 0xFFFFFFFF, s1[i % 4]), b, c
        s2 = [3, 5, 9, 13]
        order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i, k in enumerate(order2):
            a, b, c, d = d, rol((a + G(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s2[i % 4]), b, c
        s3 = [3, 9, 11, 15]
        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i, k in enumerate(order3):
            a, b, c, d = d, rol((a + H(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[i % 4]), b, c
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return b"".join(v.to_bytes(4, "little") for v in (a, b, c, d))

# ---------------------------------------------------------------------------
# Identification
# ---------------------------------------------------------------------------
HASH_PATTERNS = [
    ("MD5", r"^[a-fA-F0-9]{32}$"),
    ("SHA-1", r"^[a-fA-F0-9]{40}$"),
    ("SHA-224", r"^[a-fA-F0-9]{56}$"),
    ("SHA-256", r"^[a-fA-F0-9]{64}$"),
    ("SHA-384", r"^[a-fA-F0-9]{96}$"),
    ("SHA-512", r"^[a-fA-F0-9]{128}$"),
    ("SHA3-256", r"^[a-fA-F0-9]{64}$"),   # ambiguous with SHA-256, listed later
    ("NTLM", r"^[a-fA-F0-9]{32}$"),
    ("MD4", r"^[a-fA-F0-9]{32}$"),
    ("MySQL323", r"^[a-fA-F0-9]{16}$"),
    ("MySQL5.x/SHA1($pass$salt)", r"^\*[a-fA-F0-9]{40}$"),
    ("CRC32", r"^[a-fA-F0-9]{8}$"),
    ("Adler32", r"^[a-fA-F0-9]{8}$"),
    ("RIPEMD-160", r"^[a-fA-F0-9]{40}$"),
    ("Whirlpool", r"^[a-fA-F0-9]{128}$"),
    ("bcrypt", r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"),
    ("bcrypt($2x$)", r"^\$2x\$\d{2}\$[./A-Za-z0-9]{53}$"),
    ("bcrypt($2$)", r"^\$2\$\d{2}\$[./A-Za-z0-9]{53}$"),
    ("scrypt", r"^\$scrypt\$[./A-Za-z0-9$]*$"),
    ("argon2", r"^\$argon2(id|i|d)\$[^\s]+$"),
    ("LM hash", r"^[a-fA-F0-9]{32}$"),
    ("Kerberos 5 TGS-REP", r"^\$krb5tgs\$[^\s]+$"),
    ("Kerberos 5 AS-REP", r"^\$krb5asrep\$[^\s]+$"),
    ("SHA-1 (Django)", r"^sha1\$[^\s]+\$[a-fA-F0-9]{40}$"),
    ("MD5 (Django)", r"^md5\$[^\s]+\$[a-fA-F0-9]{32}$"),
    ("PBKDF2-HMAC-SHA256", r"^pbkdf2_sha256\$[^\s]+$"),
    ("PKZIP", r"^[a-fA-F0-9]{16}$"),
    ("APR1 (Apache)", r"^\$apr1\$[^\s]+$"),
    ("MD5crypt", r"^\$1\$[^\s]+$"),
    ("SHA256crypt", r"^\$5\$[^\s]+$"),
    ("SHA512crypt", r"^\$6\$[^\s]+$"),
    ("IPB2", r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{5}$"),
]


def identify_hash(h):
    h = h.strip()
    if not h:
        return []
    matches = []
    for name, pattern in HASH_PATTERNS:
        if re.match(pattern, h):
            matches.append(name)
    if not matches:
        return ["unknown"]
    return matches


# ---------------------------------------------------------------------------
# Cracking
# ---------------------------------------------------------------------------
def _mutations(word):
    yield word
    yield word.capitalize()
    yield word.upper()
    yield word.lower()
    yield word + "1"
    yield word + "123"
    yield word + "!"
    yield word + "@"
    yield word + "123!"
    yield word + "2024"
    yield word + "2025"
    yield word + "2026"
    yield word[::-1]
    # leet-ish
    leet = (word.replace("a", "@").replace("e", "3").replace("i", "1")
                .replace("o", "0").replace("s", "$").replace("t", "7"))
    if leet != word:
        yield leet
        yield leet + "123"


def _digest_fns(hash_name):
    """Return list of (label, fn(password)->hexdigest) for a hash name."""
    lower = hash_name.lower()
    fns = []
    if "md5" in lower and "mysql" not in lower and "django" not in lower:
        fns.append(("md5", lambda p: hashlib.md5(p).hexdigest()))
    if "sha-1" in lower or "sha1" in lower:
        fns.append(("sha1", lambda p: hashlib.sha1(p).hexdigest()))
    if "sha-224" in lower:
        fns.append(("sha224", lambda p: hashlib.sha224(p).hexdigest()))
    if "sha-256" in lower or ("sha3" not in lower and "sha256" in lower):
        fns.append(("sha256", lambda p: hashlib.sha256(p).hexdigest()))
    if "sha-384" in lower:
        fns.append(("sha384", lambda p: hashlib.sha384(p).hexdigest()))
    if "sha-512" in lower:
        fns.append(("sha512", lambda p: hashlib.sha512(p).hexdigest()))
    if "sha3-256" in lower:
        fns.append(("sha3_256", lambda p: hashlib.sha3_256(p).hexdigest()))
    if "ripemd" in lower:
        def ripemd160(p):
            try:
                return hashlib.new("ripemd160", p).hexdigest()
            except ValueError:  # OpenSSL 3 removed ripemd160 in some builds
                return None
        fns.append(("ripemd160", ripemd160))
    if "ntlm" in lower or "lm" in lower:
        def ntlm(p):
            return _md4(p.decode("latin-1").encode("utf-16le")).hex()
        fns.append(("ntlm", ntlm))
    return fns


def crack_hash(h, wordlists=None, workers=16):
    """Crack a hex digest against wordlists with mutations."""
    h = h.strip()
    candidates = identify_hash(h)
    if not candidates or candidates == ["unknown"]:
        return None
    # only crack simple hex digests
    if not re.fullmatch(r"[a-fA-F0-9]{8,128}", h):
        return None
    wordlist_files = wordlists or [
        os.path.join(WORDLISTS, "passwords.txt"),
    ]
    extra = os.environ.get("ROCKYOU")
    if extra and os.path.exists(extra):
        wordlist_files.append(extra)
    seen = set()
    words = []
    for wf in wordlist_files:
        if not os.path.exists(wf):
            continue
        with open(wf, encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if not w or w in seen:
                    continue
                seen.add(w)
                words.append(w)
    if not words:
        return None

    fns = []
    for name in candidates:
        fns.extend(_digest_fns(name))

    target = h.lower()
    result = None

    def try_word(word):
        for _, fn in fns:
            if fn(word.encode("latin-1")) == target:
                return word
        for mut in _mutations(word):
            for _, fn in fns:
                if fn(mut.encode("latin-1")) == target:
                    return mut
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for res in pool.map(try_word, words):
            if res:
                result = res
                break
    return result
