"""Encoding decoders: base*, hex, binary, octal, decimal, URL, unicode,
HTML entities, leetspeak, morse, brainfuck, ROT, compression sniffing,
file-magic detection and recursive chain decoding."""
import base64
import binascii
import gzip
import html
import itertools
import re
import struct
import urllib.parse
import zlib

from .common import is_printable_text

_LLE_CACHE = {}


def _lle_cached(text):
    """Cached looks_like_encoding — the chain beam calls it per candidate
    per level, and the underlying probe is not free."""
    hit = _LLE_CACHE.get(text)
    if hit is None:
        from .common import looks_like_encoding
        hit = looks_like_encoding(text)
        if len(_LLE_CACHE) < 100_000:
            _LLE_CACHE[text] = hit
    return hit

# ---------------------------------------------------------------------------
# Primitive decoders — each returns str or None
# ---------------------------------------------------------------------------

def dec_base64(s):
    for variant in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            out = variant(s.encode())
            if out and is_printable_text(out.decode("latin-1")):
                return out.decode("latin-1")
        except Exception:
            continue
    return None


def dec_base32(s):
    try:
        out = base64.b32decode(s.upper())
        return out.decode("latin-1")
    except Exception:
        return None


def dec_base16(s):
    try:
        out = base64.b16decode(s.upper())
        return out.decode("latin-1")
    except Exception:
        return None


def dec_base85(s):
    for variant in (base64.a85decode, base64.b85decode):
        try:
            out = variant(s)
            return out.decode("latin-1")
        except Exception:
            continue
    return None


def dec_ascii85(s):
    """Adobe-style ASCII85 with optional <~ ~> framing."""
    t = s.strip()
    if t.startswith("<~"):
        t = t[2:]
    if t.endswith("~>"):
        t = t[:-2]
    if not t:
        return None
    try:
        return base64.a85decode(t).decode("latin-1")
    except Exception:
        return None


def dec_uuencode(s):
    """UUencoding: 'begin 644 x' header lines or bare length-char rows."""
    import binascii
    out = bytearray()
    saw_any = False
    for line in s.splitlines():
        line = line.strip()
        if not line or line.startswith("begin "):
            continue
        if line == "end" or line == "`":
            break
        try:
            chunk = binascii.a2b_uu(line)
        except Exception:
            continue
        if chunk:
            saw_any = True
            out += chunk
    if not saw_any or not out:
        return None
    text = bytes(out).decode("latin-1")
    return text if is_printable_text(text) else None


def dec_quoted_printable(s):
    import quopri
    try:
        raw = quopri.decodestring(s.encode("latin-1"))
        text = raw.decode("utf-8", "replace")
    except Exception:
        return None
    return text if "=" in s and is_printable_text(text) else None


def dec_base32hex(s):
    """RFC 4648 base32hex (0-9,A-V) decoded via alphabet translation."""
    t = "".join(c for c in s.upper() if c.isalnum())
    if len(t) < 8 or any(c in "89GHIJKMNOPQRSTUVWXYZ".replace("V", "")
                         for c in t):
        return None
    table = str.maketrans("0123456789ABCDEFGHIJKLMNOPQRSTUV",
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    std = t.translate(table)
    try:
        padded = std + "=" * (-len(std) % 8)
        return base64.b32decode(padded).decode("latin-1")
    except Exception:
        return None


_A1Z26_RE = re.compile(r"\d{1,2}")


def dec_a1z26(s):
    """A1Z26: '8 5 12 12 15' -> HELLO. Only fires when every number fits."""
    toks = _A1Z26_RE.findall(s)
    if len(toks) < 3 or len(toks) * 2 < sum(len(t) for t in toks) // 2:
        pass
    vals = [int(t) for t in toks]
    if len(vals) < 3 or any(not 1 <= v <= 26 for v in vals):
        return None
    # require separators between most numbers (avoid eating decimal/hex data)
    if len(re.sub(r"[^0-9]", "", s)) != sum(len(t) for t in toks):
        return None
    return "".join(chr(64 + v) for v in vals)


_NATO = {
    "alfa": "a", "alpha": "a", "bravo": "b", "charlie": "c", "delta": "d",
    "echo": "e", "foxtrot": "f", "golf": "g", "hotel": "h", "india": "i",
    "juliett": "j", "juliet": "j", "kilo": "k", "lima": "l", "mike": "m",
    "november": "n", "oscar": "o", "papa": "p", "quebec": "q", "romeo": "r",
    "sierra": "s", "tango": "t", "uniform": "u", "victor": "v",
    "whiskey": "w", "xray": "x", "x-ray": "x", "yankee": "y", "zulu": "z",
}


def dec_nato(s):
    words = re.findall(r"[a-z]+", s.lower())
    if len(words) < 3:
        return None
    out = []
    hits = 0
    for w in words:
        if w in _NATO:
            out.append(_NATO[w])
            hits += 1
        elif w in ("space", "spase"):
            out.append(" ")
        else:
            return None
    if hits < max(3, len(words) - 1):
        return None
    return "".join(out)


_TAP_ROWS = "ABCDE FGHIJ LMNOP QRSTU VWXYZ"


def dec_tapcode(s):
    """Tap code: '.. ..' dot groups or '23 31' digit pairs (no letter K)."""
    alpha = _TAP_ROWS.replace(" ", "")
    out = []
    groups = re.split(r"[/\n]+|\s{2,}|(?<=\d)\s+(?=\d)", s.strip())
    groups = [g for g in groups if g]
    if len(groups) < 3:
        return None
    for g in groups:
        digits = re.sub(r"[^1-5]", "", g)
        dots_only = set(g) <= {".", " ", "/", "\n"}
        if dots_only:
            halves = [h for h in re.split(r"\s+", g.strip()) if h]
            if len(halves) != 2:
                return None
            row, col = len(halves[0]), len(halves[1])
        else:
            if len(digits) != 2:
                return None
            row, col = int(digits[0]), int(digits[1])
        if not (1 <= row <= 5 and 1 <= col <= 5):
            return None
        ch = alpha[(row - 1) * 5 + col - 1]
        out.append("c" if ch == "k" else ch.lower())
    return "".join(out)


def dec_jwt_payload(s):
    """Decode a JWT's payload segment as a chain layer (no verification)."""
    parts = s.strip().split(".")
    if len(parts) != 3:
        return None
    seg = parts[1]

    def b64pad(x):
        return x + "=" * (-len(x) % 4)

    for decoder in (
            lambda x: base64.urlsafe_b64decode(b64pad(x)),
            lambda x: base64.b64decode(b64pad(x))):
        try:
            text = decoder(seg).decode("utf-8")
            if text.startswith("{") and is_printable_text(text):
                return text
        except Exception:
            continue
    return None


def _xor_brute_bytes_strict(raw):
    """Shared XOR-brute core over RAW bytes; returns best candidate str."""
    from core.flag import extract_flags as _ef
    from .common import is_probable_english, looks_like_encoding, chi_square
    if len(raw) < 8:
        return None
    enc_charset = frozenset(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "+/=_-{}")
    cands = []
    for k in range(1, 256):
        plain = bytes(b ^ k for b in raw)
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in plain)
        ratio = printable / len(plain)
        if ratio < 0.92:
            continue
        letters = "".join(chr(b) for b in plain if 65 <= b <= 90 or
                          97 <= b <= 122)
        chi = chi_square(letters.lower()) if len(letters) >= 4 else 9999.0
        enc_ratio = sum(1 for b in plain if chr(b) in enc_charset) / len(plain)
        score = (-(ratio * 100.0) - enc_ratio * 60.0 + min(chi, 400.0))
        cands.append((score, k, ratio, plain))
    if not cands:
        return None
    cands.sort(key=lambda t: t[0])
    best_enc = None
    for _, k, ratio, plain in cands[:5]:
        text = plain.decode("latin-1")
        known, cands_f = _ef(text)
        if known or cands_f:
            return text
        if looks_like_encoding(text):
            if ratio >= 0.99:
                return text
            if best_enc is None:
                best_enc = text
            continue
        if is_probable_english(text, threshold=260):
            return text
    return best_enc


def _dec_hex_xor_strict(s):
    """hex-transported single-byte-XOR ciphertext -> next layer, in ONE
    structural step (avoids the unprintable intermediate that used to get
    the branch rejected)."""
    t = s.strip()
    if len(t) < 16 or len(t) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", t):
        return None
    return _xor_brute_bytes_strict(bytes.fromhex(t))


def _dec_b64_xor_strict(s):
    """base64-transported single-byte-XOR ciphertext -> next layer."""
    t = "".join(s.split())
    if len(t) < 12:
        return None
    try:
        raw = base64.b64decode(t, validate=True)
    except Exception:
        try:
            raw = base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
        except Exception:
            return None
    if len(raw) < 8:
        return None
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw)
    if printable / len(raw) > 0.95:
        # decoded payload is plain text — the ordinary base64 layer covers
        # it; XOR brute would only spawn duplicate branches
        return None
    return _xor_brute_bytes_strict(raw)


def _dec_xor_single_strict(s):
    """Single-byte XOR as an IN-CHAIN layer. Fires only when some key
    yields a flag, confidently-English text, OR another decodable encoding
    layer — so nested chains like base64 -> XOR -> base64 resolve
    automatically without drowning the beam in garbage branches.

    Two-phase design: a cheap printable+chi-square filter ranks all 256
    keys first; the expensive checks (flag regex / encoder probes) run on
    only the top handful."""
    t = s.strip()
    # pure transports already have dedicated composite layers (hexxor /
    # b64xor); skipping here avoids a redundant 255-key sweep per node
    if re.fullmatch(r"[0-9a-fA-F]{16,}", t) or len(t) >= 12 and \
            re.fullmatch(r"[A-Za-z0-9+/=]+", t):
        return None
    try:
        raw = s.encode("latin-1")
    except Exception:
        return None
    return _xor_brute_bytes_strict(raw)


def dec_hex(s):
    try:
        if len(s) % 2 != 0:
            return None
        out = bytes.fromhex(s)
        return out.decode("latin-1")
    except Exception:
        return None


def dec_binary(s):
    try:
        bits = s.replace(" ", "").replace("\n", "")
        if not re.fullmatch(r"[01]+", bits) or len(bits) % 8 != 0:
            return None
        out = b"".join(
            int(bits[i:i + 8], 2).to_bytes(1, "big") for i in range(0, len(bits), 8)
        )
        return out.decode("latin-1")
    except Exception:
        return None


def dec_octal(s):
    try:
        toks = re.findall(r"\d{3}", s.replace(" ", ""))
        if not toks or not all(int(t, 8) < 256 for t in toks):
            return None
        out = bytes(int(t, 8) for t in toks)
        return out.decode("latin-1")
    except Exception:
        return None


def dec_decimal(s):
    try:
        toks = re.findall(r"\d{2,3}", s.replace(" ", ""))
        if not toks or not all(0 <= int(t) < 256 for t in toks):
            return None
        out = bytes(int(t) for t in toks)
        return out.decode("latin-1")
    except Exception:
        return None


def dec_url(s):
    try:
        out = urllib.parse.unquote(s)
        if out != s and is_printable_text(out):
            return out
    except Exception:
        pass
    return None


def dec_unicode(s):
    try:
        out = s.encode().decode("unicode_escape")
        if out != s and is_printable_text(out):
            return out
    except Exception:
        pass
    return None


def dec_html(s):
    try:
        out = html.unescape(s)
        if out != s and is_printable_text(out):
            return out
    except Exception:
        pass
    return None


def dec_rot13(s):
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))


def dec_rot47(s):
    out = []
    for ch in s:
        o = ord(ch)
        if 33 <= o <= 126:
            out.append(chr(33 + ((o - 33 + 47) % 94)))
        else:
            out.append(ch)
    return "".join(out)


def dec_leet(s):
    table = {
        "4": "a", "@": "a", "8": "b", "6": "b", "(": "c", "{": "c", "<": "c",
        "3": "e", "€": "e", "9": "g", "6": "g", "#": "h", "1": "l", "|": "l",
        "0": "o", "5": "s", "$": "s", "7": "t", "+": "t", "2": "z", "!": "i",
    }
    out = []
    for ch in s:
        if ch.isalpha():
            out.append(ch)
        elif ch.lower() in table:
            out.append(table[ch.lower()])
        else:
            out.append(ch)
    return "".join(out)


def dec_gzip(s):
    try:
        if s[:2] == b"\x1f\x8b":
            return gzip.decompress(s).decode("latin-1")
    except Exception:
        pass
    try:
        if s[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
            return zlib.decompress(s).decode("latin-1")
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# TCTT-style bases: base45 (RFC 9285), base58, base62 (+ alphabet variants),
# base36. THCTT 2025 had a 'Bad62' challenge where the alphabet was
# case-swapped — we try several common orderings.
# ---------------------------------------------------------------------------

_BASE45_ALPH = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_BASE58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE62_VARIANTS = [
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
]
_BASE36_ALPH = "0123456789abcdefghijklmnopqrstuvwxyz"


def _bigint_decode(s, alph):
    """Decode s as a big-endian base-N number using alphabet alph. Returns
    bytes (with leading zero-digit chars kept as leading zero bytes) or None."""
    if not s or any(c not in alph for c in s):
        return None
    idx = {c: i for i, c in enumerate(alph)}
    zeros = 0
    for c in s:
        if idx[c] == 0:
            zeros += 1
        else:
            break
    val = 0
    for c in s:
        val = val * len(alph) + idx[c]
    if val == 0 and zeros == 0:
        return None
    raw = val.to_bytes((val.bit_length() + 7) // 8, "big") if val else b""
    return b"\x00" * zeros + raw


def dec_base45(s):
    """RFC 9285 base45 — digits group into 16-bit / 8-bit chunks (NOT a
    single big-endian bignum like base58/62): 3 chars -> 2 bytes, 2 chars
    -> 1 byte."""
    s = s.strip()
    if not s or len(s) < 2:
        return None
    idx = {c: i for i, c in enumerate(_BASE45_ALPH)}
    if any(c not in idx for c in s):
        return None
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        if n - i >= 3:
            v = idx[s[i]] + idx[s[i + 1]] * 45 + idx[s[i + 2]] * 45 * 45
            if v > 0xFFFF:
                return None
            out.extend(v.to_bytes(2, "big"))
            i += 3
        else:
            v = idx[s[i]] + idx[s[i + 1]] * 45
            if v > 0xFF:
                return None
            out.append(v)
            i += 2
    try:
        return out.decode("latin-1")
    except Exception:
        return None


def dec_base58(s):
    s = s.strip()
    if not s or len(s) < 2:
        return None
    raw = _bigint_decode(s, _BASE58_ALPH)
    if raw is None:
        return None
    try:
        return raw.decode("latin-1")
    except Exception:
        return None


def dec_base62(s):
    """Try standard + common alphabet orderings (THCTT 'Bad62' swapped the
    case of the alphabet, which silently corrupts plain standard decode).
    Several variants may decode to *printable* garbage, so pick the one that
    scores most English / contains a flag prefix instead of first-hit."""
    s = s.strip()
    if not s or len(s) < 2:
        return None
    decoded = []
    for alph in _BASE62_VARIANTS:
        raw = _bigint_decode(s, alph)
        if raw is None:
            continue
        try:
            decoded.append(raw.decode("latin-1"))
        except Exception:
            continue
    if not decoded:
        return None
    # English-ness + flag bonus — wrong-alphabet decodes score terribly
    def rank(d):
        from .common import text_score
        bonus = -1000.0 if _chain_flaggy(d) else 0.0
        try:
            return bonus + text_score(d)
        except Exception:
            return 999.0
    decoded.sort(key=rank)
    best = decoded[0]
    if is_printable_text(best):
        return best
    for d in decoded:
        if is_printable_text(d):
            return d
    return best


def dec_base62_crib(s):
    """Fallback for case-corrupted base62 (THCTT 'Bad62'): tries to rebuild
    the plaintext from a known flag prefix by re-encoding guesses. Returns
    plaintext or None."""
    prefixes = (b"flag{", b"FLAG{", b"Flag{", b"THCTT", b"thctt", b"tctt",
                b"TCTT", b"NCSA", b"ncsa", b"picoCTF{", b"HTB{", b"AEGIS{",
                b"aegis{", b"CTF{", b"ctf{")
    return _base62_case_crack(s, prefixes)


def dec_base36(s):
    s = s.strip().lower()
    if not s or len(s) < 2:
        return None
    raw = _bigint_decode(s, _BASE36_ALPH)
    if raw is None:
        return None
    try:
        return raw.decode("latin-1")
    except Exception:
        return None


_B62_ALPH = _BASE62_VARIANTS[0]


def _b62_bignum_encode(data):
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        out = _B62_ALPH[n % 62] + out
        n //= 62
    return out or "0"


def _b62_chunked_encode(data, chunk=8):
    out = []
    for i in range(0, len(data), chunk):
        out.append(_b62_bignum_encode(data[i:i + chunk]))
    return "".join(out)


_B62_CASE_CHARS = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "{}_-!@#$%^&*()[];:,./?<>+= '"
)


def _base62_case_crack(s, prefixes):
    """Recover plaintext from case-corrupted base62 (THCTT 'Bad62': the
    ciphertext was enc(plaintext).lower(), which plain decode cannot undo
    because case carried information).

    Exact approach: the ciphertext is a concatenation of per-8-byte-chunk
    encodings (python's base62.encodebytes). Each chunk encodes to 10-11
    base-62 digits; lowercasing lost only the *case* of each digit, so the
    true chunk encoding is a case-variant of the target segment. We enumerate
    every case variant of each segment, decode it with the standard alphabet
    and keep the value that fits 8 bytes. Deterministic — no guessing."""
    s = s.strip().lower()
    if not s or len(s) < 8:
        return None
    for prefix in prefixes:
        pfb = prefix if isinstance(prefix, bytes) else prefix.encode()
        if not pfb:
            continue
        # quick reject: the prefix's first chunk must match s's head
        probe = _b62_bignum_encode(pfb[:8] + b"!" * (8 - len(pfb[:8]))).lower()
        if s[:4] != probe[:4]:
            continue
        chunks = []
        pos = 0
        ok = True
        while pos < len(s):
            remaining = len(s) - pos
            # full chunks encode to 10-11 digits; the tail may be shorter
            lengths = (11, 10) if remaining > 11 else tuple(
                range(min(remaining, 11), 1, -1))
            found = None
            seg_len = 0
            for L in lengths:
                cand = _b62_chunk_variants(
                    s[pos:pos + L], pfb if not chunks else None,
                    partial=(remaining <= 11), is_final=(pos + L == len(s)))
                if cand is not None:
                    found = cand
                    seg_len = L
                    break
            if found is None:
                ok = False
                break
            chunks.append(found)
            pos += seg_len
        if ok:
            plain = b"".join(chunks)
            if _b62_chunked_encode(plain).lower() == s:
                try:
                    return plain.decode("latin-1")
                except Exception:
                    return None
    return None


def _b62_chunk_variants(seg, prefix_bytes, partial=False, is_final=False):
    """Enumerate case variants of one lowercased base-62 segment and return
    the plaintext chunk whose standard-alphabet encoding lowercases to it.
    Full chunks are 8 bytes; the final (partial) chunk can be 1-8 bytes."""
    idx = {c: i for i, c in enumerate(_B62_ALPH)}
    seg_l = seg.lower()
    if any(c not in idx for c in seg_l):
        return None
    # build the list of (position, uppercase_char) toggle choices
    choices = [i for i, ch in enumerate(seg_l) if ch.isalpha()]
    variants = [seg_l]
    for i in choices:
        up = seg_l[i].upper()
        variants += [v[:i] + up + v[i + 1:] for v in list(variants)]
    best = None
    best_score = -1
    for v in variants:
        try:
            n = 0
            for ch in v:
                n = n * 62 + idx[ch]
        except Exception:
            continue
        if partial:
            if not (0 < n < 2 ** 64):
                continue
            nbytes = max(1, (n.bit_length() + 7) // 8)
            if nbytes > 8:
                continue
            raw = n.to_bytes(nbytes, "big")
        else:
            if not (2 ** 56 <= n < 2 ** 64):
                continue
            raw = n.to_bytes(8, "big")
        if prefix_bytes and not raw.startswith(prefix_bytes):
            continue
        # lowercasing destroyed the case info, so MANY values re-encode
        # (lowercased) to the same segment — the real flag body is printable
        # ASCII and mostly [a-zA-Z0-9_{}-], which ranks the true decode first
        if not all(32 <= b <= 126 for b in raw):
            continue
        if _b62_bignum_encode(raw).lower() != seg_l:
            continue
        score = 0
        for b in raw:
            if 97 <= b <= 122:      # lowercase letters (flag bodies mostly)
                score += 3
            elif 48 <= b <= 57:     # digits
                score += 2
            elif 65 <= b <= 90:     # uppercase
                score += 1
            elif b in (ord("_"), ord("{"), ord("}"), ord("-"), ord(" ")):
                score += 1
        # the final chunk of a flag almost always ends with '}'
        if is_final and raw and raw[-1] == ord("}"):
            score += 5
        if score > best_score:
            best, best_score = raw, score
    return best


def _b62_trusted_digits(encfn, solved_bytes, total_len, chunked):
    """How many leading encoded digits of the current guess are trustworthy
    (not influenced by unsolved filler bytes)? Filler bytes sit at the low
    end; each filler byte can move the low ~1.34 base-62 digits, so the
    trusted prefix = total digits - filler influence."""
    filler = total_len - len(solved_bytes)
    if chunked:
        n_solved = len(solved_bytes)
        done = n_solved // 8
        digits = 0
        for i in range(done):
            digits += len(_b62_bignum_encode(b"!" * 8))
        partial = n_solved - done * 8
        if partial:
            in_chunk = 8 - partial
            chunk = solved_bytes[done * 8:] + b"!" * in_chunk
            clen = len(_b62_bignum_encode(chunk))
            digits += max(1, clen - int(in_chunk * 1.35 + 0.999))
        return digits
    # bignum: filler sits at the very end (low bytes)
    full = solved_bytes + b"!" * filler
    return max(1, len(encfn(full)) - int(filler * 1.35 + 0.999))


# ---------------------------------------------------------------------------
# Custom-alphabet base-N — THCTT 2025 'New Base64' used a 64-char Thai
# alphabet; the emoBit challenge was base-100 with emoji. Both are just
# base-N with a non-ASCII alphabet: derive the alphabet from the unique
# characters present (challenge scripts usually build it in codepoint order,
# e.g. chr(range('ก', 'ก'+47))).
# ---------------------------------------------------------------------------
def _candidate_alphabets(uniq):
    """Plausible alphabets for a custom-alphabet base-N message, in
    likelihood order. The THCTT 'New Base64' challenge built its alphabet as
    chr('ก'..)+chr('๐'..)+chr('0'..) — a construction we reproduce exactly;
    generic messages get codepoint order, first-appearance order and every
    block permutation."""
    alphas = []
    alphas.append("".join(uniq))  # codepoint order
    # first-appearance order
    seen = []
    for c in uniq:
        seen.append(c)
    alphas.append("".join(seen))
    # THCTT-style Thai constructions (char_gen trims the 67-char alphabet
    # to 64: 47 consonants + 10 Thai digits + first 7 ASCII digits)
    cons47 = [chr(i) for i in range(0x0E01, 0x0E01 + 47)]
    thai_d = [chr(i) for i in range(0x0E50, 0x0E50 + 10)]
    ascii_d = [chr(i) for i in range(0x30, 0x30 + 10)]
    alphas.append("".join(cons47 + thai_d + ascii_d[:7]))
    alphas.append("".join(cons47 + thai_d + ascii_d))
    alphas.append("".join(cons47[:44] + thai_d + ascii_d[:10]))
    # block permutations (blocks = runs of near-consecutive codepoints)
    blocks = []
    for c in uniq:
        if blocks and ord(c) - ord(blocks[-1][-1]) <= 8:
            blocks[-1].append(c)
        else:
            blocks.append([c])
    if len(blocks) <= 5:
        for perm in itertools.permutations(blocks):
            alphas.append("".join("".join(b) for b in perm))
    return alphas


def dec_custom_base(s):
    """Custom-alphabet base-N with a restricted non-ASCII alphabet (Thai
    chars, shapes, emoji...). The full alphabet is usually larger than the
    subset of chars actually used, so we try several plausible alphabet
    constructions and return the first printable / flaggy decode."""
    s = s.strip()
    if not s or any(c.isspace() for c in s):
        return None
    body = s.replace("=", "")
    if len(body) < 8 or len(body) % 4 != 0:
        return None
    uniq = sorted(set(body))
    if not any(ord(c) > 127 for c in uniq):
        return None
    if not 2 <= len(uniq) <= 128:
        return None
    results = []
    for alpha in _candidate_alphabets(uniq):
        raw = _bigint_decode(body, alpha)
        if raw is None:
            continue
        try:
            text = raw.decode("latin-1")
        except Exception:
            continue
        if is_printable_text(text) or _chain_flaggy(text):
            results.append((0.0 if _chain_flaggy(text) else 1.0, text))
    if not results:
        return None
    results.sort(key=lambda t: t[0])
    return results[0][1]


# ---------------------------------------------------------------------------
# Emoji encodings (THCTT 2024 emoBit / Programming Easy2, dcode base-100):
#   1) two-state emoji -> binary bits
#   2) emoji as base-N digits (custom alphabet)
#   3) per-char unicode offset (subtract 0x1F3F7 etc. -> ASCII)
#   4) single-char substitution with flag-prefix / starter-word crib
# ---------------------------------------------------------------------------

_EMOJI_BLOCKS = (0x1F000, 0x1F300, 0x1F400, 0x1F500, 0x1F600, 0x1F680,
                  0x1F900, 0x2600, 0x2700, 0x1F000)
_EMOJI_BASES = (100, 94, 64, 62, 58, 36, 16, 10, 8)


def _emoji_basen(s):
    """Emoji as base-N digits (dcode.fr 'base 100' style): the alphabet is a
    contiguous codepoint block, index = ord(c) - block_start. Try plausible
    (block, base) pairs and return the first printable / flaggy decode."""
    for off in _EMOJI_BLOCKS:
        for base in _EMOJI_BASES:
            try:
                idxs = [ord(c) - off for c in s]
            except Exception:
                continue
            if any(i < 0 or i >= base for i in idxs):
                continue
            zeros = 0
            for i in idxs:
                if i == 0:
                    zeros += 1
                else:
                    break
            val = 0
            for i in idxs:
                val = val * base + i
            if val == 0 and zeros == 0:
                continue
            raw = val.to_bytes((val.bit_length() + 7) // 8, "big") if val else b""
            raw = b"\x00" * zeros + raw
            try:
                text = raw.decode("latin-1")
            except Exception:
                continue
            if is_printable_text(text) or _chain_flaggy(text):
                return text
    return None


def dec_emoji(s):
    """Two-state emoji -> binary, or emoji as base-N digits."""
    s = s.strip()
    if not s:
        return None
    uniq = sorted(set(s.replace(" ", "")))
    if not any(ord(c) > 0x1F000 for c in uniq):
        return None
    # (1) two-state: 😺/😸 etc -> 0/1
    if len(uniq) == 2:
        a, b = uniq
        bits = s.replace(" ", "").replace(a, "0").replace(b, "1")
        if len(bits) % 8 == 0 and bits:
            try:
                raw = b"".join(
                    int(bits[i:i + 8], 2).to_bytes(1, "big")
                    for i in range(0, len(bits), 8))
                return raw.decode("latin-1")
            except Exception:
                pass
    # (2) base-N with emoji digits (dcode 'base 100' style)
    try:
        out = _emoji_basen(s)
        if out:
            return out
    except Exception:
        pass
    return None


_EMOJI_OFFSETS = (0x1F3F7, 0x1F600, 0x1F300, 0x1F680, 0x1F400, 0x1F500,
                  0x1F900, 0x2600, 0x2700, 0x1F000)


def dec_emoji_offset(s):
    """Every char is emoji in a narrow band; subtracting the right block base
    yields ASCII (THCTT 2024 emoBit: ord(c) - 0x1F3F7 -> flag chars)."""
    s = s.strip()
    if not s or not all(ord(c) > 0x1F000 for c in s):
        return None
    for base in _EMOJI_OFFSETS:
        try:
            out = "".join(chr(ord(c) - base) for c in s)
            if out and is_printable_text(out) and any(c.isalnum() for c in out):
                return out
        except Exception:
            continue
    return None


_SUBST_CRIBS = ["THCTT2024", "THCTT24", "THCTT", "thctt", "tctt", "TCTT",
                "flag{", "FLAG{", "flag", "FLAG", "picoCTF", "AegisCTF",
                "AEGIS", "HTB{", "NCSA", "HELLO", "THE", "WELCOME",
                "CONGRAT", "GOOD JOB", "THIS IS"]


def dec_emoji_subst(s):
    """Single-char substitution where each plaintext char maps to one symbol
    (emoji, shapes, ...). Greedy word-matching: repeatedly match each token
    against a common-word list, keeping the mapping consistent across tokens.
    Unknown chars become '?'. This decodes 'HELLO WORLD ...' style messages
    (THCTT 2024 Programming Easy2) without knowing the exact alphabet."""
    s2 = s.strip()
    uniq = sorted(set(c for c in s2 if not c.isspace()))
    if not any(ord(c) > 0x1F000 for c in uniq):
        return None
    if not 2 <= len(uniq) <= 50:
        return None
    tokens = s2.split()
    mapping = {}
    changed = True
    while changed:
        changed = False
        for tok in tokens:
            if all(c in mapping for c in tok):
                continue  # already fully decoded
            for word in _SUBST_WORDS:
                if len(word) != len(tok):
                    continue
                ok = True
                for c, ch in zip(tok, word):
                    if c in mapping and mapping[c] != ch:
                        ok = False
                        break
                if not ok:
                    continue
                for c, ch in zip(tok, word):
                    mapping[c] = ch
                changed = True
                break
    # apply (extend: use per-position fallback for unmatched tokens)
    out = []
    for c in s2:
        if c.isspace():
            out.append(c)
        elif c in mapping:
            out.append(mapping[c])
        else:
            out.append("?")
    res = "".join(out)
    nonspace = sum(1 for c in s2 if not c.isspace())
    if res.count("?") >= nonspace * 0.5:
        return None
    return res


_SUBST_WORDS = (
    "THE", "AND", "FOR", "YOU", "HELLO", "WORLD", "THIS", "THAT", "IS",
    "FLAG", "FLAGS", "YOUR", "WITH", "HAVE", "FROM", "WELCOME", "GOOD",
    "JOB", "PLEASE", "SECRET", "HACK", "CYBER", "CTF", "THAI", "TALENT",
    "MESSAGE", "CODE", "TEXT", "EASY", "HARD", "LEVEL", "CHALLENGE", "ARE",
    "NOT", "BE", "TO", "OF", "IN", "IT", "ON", "AT", "BY", "WE", "SO",
    "IF", "OR", "MY", "ME", "UP", "DO", "GO", "NO", "AS", "AN", "ALL",
    "BUT", "CAN", "DID", "GET", "HAS", "HER", "HIM", "HIS", "HOW", "ITS",
    "LET", "MAY", "NEW", "NOW", "OLD", "OUT", "OWN", "PUT", "SAW", "SEE",
    "SHE", "THEM", "THEN", "WAS", "WILL", "WOULD", "ABOUT", "AFTER",
    "AGAIN", "BECAUSE", "BEFORE", "COULD", "EVERY", "FIRST", "JUST",
    "KNOW", "LIKE", "LITTLE", "LONG", "MADE", "MAKE", "MORE", "MOST",
    "MUCH", "MUST", "NEVER", "ONLY", "OTHER", "OUR", "OVER", "PEOPLE",
    "RIGHT", "SAID", "SAME", "SHOULD", "SOME", "STILL", "SUCH", "TAKE",
    "THAN", "THEIR", "THERE", "THESE", "THING", "THINK", "THREE",
    "THROUGH", "TIME", "TWO", "UNDER", "VERY", "WAY", "WELL", "WHERE",
    "WHICH", "WHILE", "WHO", "YEAR", "DAYS", "LUCK", "FIND", "FOUND",
    "CONGRATULATIONS", "CONGRATS", "THCTT", "TCTT", "NCSA", "FLAGIS",
    "THEFLAG", "HERE", "HIDDEN", "INSIDE", "FOUND", "SEARCH", "LOOK",
)


# ---------------------------------------------------------------------------
# Esolangs: Ook! (brainfuck with words) and Malbolge (the infamous
# self-modifying language — THCTT 2025 'Advanced Strings Secret' ended in
# a Malbolge program whose output was the flag).
# ---------------------------------------------------------------------------

def dec_ook(code):
    """Ook! is brainfuck with words: pairs of Ook punctuation encode ops:
    (.,.) = >  (.,?) = <  (.,!) = +  (?.,) = -  (?.,?) = .  (?,!) = ,
    (!,.) = [  (!,?) = ]"""
    if "Ook" not in code:
        return None
    pairs = {
        (".", "."): ">", (".", "?"): "<", (".", "!"): "+",
        ("?", "."): "-", ("?", "?"): ".", ("?", "!"): ",",
        ("!", "."): "[", ("!", "?"): "]", ("!", "!"): "",
    }
    puncts = re.findall(r"Ook([.?!])", code)
    if len(puncts) < 4:
        return None
    bf = []
    for i in range(0, len(puncts) - 1, 2):
        bf.append(pairs.get((puncts[i], puncts[i + 1]), ""))
    return dec_brainfuck("".join(bf))


_MAL_JMP = {4, 5, 23, 39, 40, 62, 68, 81}
_MAL_OUT = {3, 9, 30, 33, 52, 55, 80, 90}
_MAL_IN = {10, 25, 32, 41, 47, 71, 83, 84}
_MAL_ROTR = {2, 14, 15, 38, 43, 50, 60, 74}
_MAL_MOVD = {18, 21, 36, 57, 63, 65, 78, 86}
_MAL_HALT = {6, 20, 31, 44, 54, 61, 75, 93}
_MAL_IO = {12, 13, 34, 35, 58, 59, 76, 77}
_MAL_MOVA = {24, 27, 37, 49, 53, 69, 73, 89}
_MAL_CRAZY = ((1, 0, 0), (1, 0, 2), (2, 2, 1))


def _mal_crazy(x, y):
    outv = 0
    p3 = 1
    for _ in range(10):
        outv += _MAL_CRAZY[x % 3][y % 3] * p3
        x //= 3
        y //= 3
        p3 *= 3
    return outv


def _mal_rotr(x):
    return (x % 3) * 59049 + x // 3


def dec_malbolge(code):
    """Run a Malbolge program; return whatever it prints. Implements the
    spec: opcode = (mem[p] + p) % 94, self-modifying memory, tritwise
    'crazy' operation."""
    src = "".join(ch for ch in code if ch not in " \t\r\n")
    if not src or len(src) < 8:
        return None
    mem = [0] * 59049
    for i, ch in enumerate(src):
        if i >= 59049:
            break
        mem[i] = ord(ch)
    d = [0] * 59049
    a = 0
    p = 0
    out = []
    steps = 0
    while True:
        steps += 1
        if steps > 50_000_000 or len(out) > 100_000:
            return None
        o = (mem[p] + p) % 94
        if o in _MAL_HALT:
            break
        if o in _MAL_JMP:
            p = mem[(p + 1) % 59049]
        elif o in _MAL_OUT:
            out.append(chr(a % 256))
        elif o in _MAL_IN:
            a = 0  # no input available
        elif o in _MAL_ROTR:
            a = _mal_rotr(a)
        elif o in _MAL_MOVD:
            d[mem[(p + 1) % 59049] % 59049] = a
        elif o in _MAL_IO:
            c = a % 256
            if c == 10 or 32 <= c <= 126:
                out.append(chr(c))
        elif o in _MAL_MOVA:
            a = d[mem[(p + 1) % 59049] % 59049]
        else:  # OP
            a = _mal_crazy(a, d[mem[(p + 1) % 59049] % 59049])
        mem[p] = _mal_rotr(mem[p])
        p = (p + 1) % 59049
    res = "".join(out)
    return res or None


# ---------------------------------------------------------------------------
# Morse
# ---------------------------------------------------------------------------
MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-.-.--": "!", "-....-": "-", "-..-.": "/", ".--.-.": "@", "---...": ":",
}


def dec_morse(s):
    if not re.search(r"[.\-]", s):
        return None
    words = []
    for word in re.split(r"\s*/\s*|\s{3,}", s.strip()):
        chars = []
        for tok in word.split():
            if tok in MORSE:
                chars.append(MORSE[tok])
            elif re.fullmatch(r"[01]+", tok):  # binary morse 1=-
                bits = tok.replace("1", "-").replace("0", ".")
                if bits in MORSE:
                    chars.append(MORSE[bits])
        words.append("".join(chars))
    return " ".join(words)


# ---------------------------------------------------------------------------
# Brainfuck interpreter
# ---------------------------------------------------------------------------
BF_OPS = set("<>+-.,[]")


def dec_brainfuck(code):
    if not code or not any(c in BF_OPS for c in code) or len(code) > 200_000:
        return None
    tape = [0] * 30000
    ptr = 0
    out = []
    jumps = {}
    stack = []
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                return None
            j = stack.pop()
            jumps[i] = j
            jumps[j] = i
    i = 0
    steps = 0
    while i < len(code):
        steps += 1
        if steps > 10_000_000:
            return None
        c = code[i]
        if c == ">":
            ptr += 1
        elif c == "<":
            ptr -= 1
        elif c == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif c == ".":
            out.append(chr(tape[ptr]))
        elif c == ",":
            pass
        elif c == "[":
            if tape[ptr] == 0:
                i = jumps[i]
        elif c == "]":
            if tape[ptr] != 0:
                i = jumps[i]
        i += 1
    res = "".join(out)
    return res or None


# ---------------------------------------------------------------------------
# File magic sniffing (base64'd files are super common in CTF)
# ---------------------------------------------------------------------------
MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"\x1f\x8b", "GZIP"),
    (b"\x7fELF", "ELF binary"),
    (b"%PDF", "PDF document"),
    (b"BM", "BMP image"),
    (b"RIFF", "RIFF (WAV/AVI)"),
    (b"OggS", "OGG"),
    (b"ID3", "MP3 (ID3)"),
    (b"\xff\xfb", "MP3"),
    (b"\x00\x00\x01\x00", "ICO"),
    (b"SQLite format 3", "SQLite database"),
    (b"d8:announce", "Torrent file"),
    (b"qemu", "QEMU"),
]


def sniff_bytes(data):
    for magic, name in MAGIC:
        if data.startswith(magic):
            return name
    return None


# ---------------------------------------------------------------------------
# Chain decoding — repeatedly peel layers until stable / flag found
# ---------------------------------------------------------------------------
_LAYER_DECODERS = [
    ("base64", lambda s: dec_base64(s)),
    ("base32", lambda s: dec_base32(s)),
    ("hex", lambda s: dec_hex(s)),
    ("binary", lambda s: dec_binary(s)),
    ("rot13", lambda s: dec_rot13(s)),
    ("url", lambda s: dec_url(s)),
    ("unicode", lambda s: dec_unicode(s)),
]

# structural decoders CHANGE the data (base64/hex/binary...). transforms
# (rot13/leet/rot47/morse) merely remap characters and apply to ANY text, so
# they are only used as a dead-end recovery inside the beam search — letting
# them branch freely drowns the real path in nonsense.
_ALL_LAYER_DECODERS = [
    ("base64", dec_base64),
    ("base32", dec_base32),
    ("base85", dec_base85),
    ("ascii85", dec_ascii85),
    ("base45", dec_base45),
    ("base58", dec_base58),
    ("base62", dec_base62),
    ("base36", dec_base36),
    ("hex", dec_hex),
    ("binary", dec_binary),
    ("octal", dec_octal),
    ("decimal", dec_decimal),
    ("url", dec_url),
    ("html", dec_html),
    ("unicode", dec_unicode),
    ("custom-base", dec_custom_base),
    ("emoji", dec_emoji),
    ("gzip", lambda s: dec_gzip(s.encode("latin-1"))),
    ("brainfuck", dec_brainfuck),
    ("ook", dec_ook),
    ("uuencode", dec_uuencode),
    ("quoted-printable", dec_quoted_printable),
    ("base32hex", dec_base32hex),
    ("a1z26", dec_a1z26),
    ("nato", dec_nato),
    ("tapcode", dec_tapcode),
    ("jwt-payload", dec_jwt_payload),
    ("xor1", _dec_xor_single_strict),
    ("hexxor", _dec_hex_xor_strict),
    ("b64xor", _dec_b64_xor_strict),
]

_CHAIN_TRANSFORMS = [
    ("rot13", dec_rot13),
    ("rot47", dec_rot47),
    ("leet", dec_leet),
    ("morse", dec_morse),
    ("emoji-offset", dec_emoji_offset),
    ("emoji-subst", dec_emoji_subst),
]


def chain_decode(text, max_depth=12, flag_hint=None):
    """Greedy layered decode (kept for backward compat / fast path).
    Prefer chain_decode_best for full coverage of multi-layer inputs."""
    stages = []
    cur = text
    seen = {text}
    for _ in range(max_depth):
        applied = None
        for name, fn in _LAYER_DECODERS:
            try:
                nxt = fn(cur)
            except Exception:
                nxt = None
            if nxt and nxt != cur and is_printable_text(nxt):
                applied = (name, nxt)
                break
        if not applied:
            break
        name, nxt = applied
        cur = nxt
        stages.append((name, cur))
        if cur in seen:
            break
        seen.add(cur)
        if flag_hint and flag_hint(cur):
            break
    return stages


def _chain_flaggy(s):
    from core.flag import extract_flags
    known, cands = extract_flags(s)
    return bool(known or cands)


def _chain_score(text):
    """Lower = better: English-ness minus a small length bonus (encoded data
    shrinks as it is decoded)."""
    from .common import text_score
    try:
        eng = text_score(text)
    except Exception:
        eng = 999.0
    return eng - len(text) * 0.05


def chain_decode_best(text, max_depth=12, max_branches=6):
    """Beam-search chain decode: at EVERY layer try ALL decoders and branch.

    A single string can be valid under several decoders at once (e.g. looks
    like hex AND base32); only one path leads to the flag. The greedy
    chain_decode picks the first hit and can wander off. This explores up to
    `max_branches` paths per layer, pruning by English-ness + flag presence.

    Returns list of (path_label, text) for every layer of every kept branch,
    e.g. ('base64>hex>rot13', 'AegisCTF{...}')."""
    # Multi-layer encoding chains in CTF are short blobs. Long inputs (source
    # code, logs, config files) explode the beam with dozens of plausible
    # substrings — no flag hides under 20 layers of a 5 KB file. Punctuation-
    # heavy text (Python source etc.) is also never a layered chain — BUT
    # XOR ciphertext is exactly a dense non-alnum blob with no spaces, so
    # space-free blobs of any charset stay on the full beam.
    if len(text) > 4000:
        return chain_decode(text, max_depth=6)
    has_spaces = " " in text or "\n" in text
    non_alnum = sum(1 for c in text if not (c.isalnum() or c in "+/=" )) / max(len(text), 1)
    if non_alnum > 0.25 and (has_spaces or len(text) > 600):
        return chain_decode(text, max_depth=6)
    results = []
    frontier = [(text, "")]
    seen_nodes = {text}
    transform_names = {n for n, _ in _CHAIN_TRANSFORMS}

    def expand_branch(item):
        """Apply every structural decoder (then transforms on dead ends)
        to one branch. Pure function — safe to run across a thread pool."""
        cur, path = item
        produced = []
        applied_structural = False
        for name, fn in _ALL_LAYER_DECODERS:
            try:
                nxt = fn(cur)
            except Exception:
                nxt = None
            if not nxt or nxt == cur:
                continue
            if not is_printable_text(nxt) and not _chain_flaggy(nxt):
                continue
            if nxt in seen_nodes:
                continue
            applied_structural = True
            new_path = f"{path}>{name}" if path else name
            produced.append((nxt, new_path))
        if applied_structural:
            return produced, True
        # dead end: peel a rot13/leet-style layer. Never chain a transform
        # onto another transform (rot13>rot47>rot13>... is pure noise)
        last = path.rsplit(">", 1)[-1] if path else ""
        if last in transform_names:
            return [], False
        produced = []
        for name, fn in _CHAIN_TRANSFORMS:
            try:
                nxt = fn(cur)
            except Exception:
                nxt = None
            if not nxt or nxt == cur:
                continue
            new_path = f"{path}>{name}" if path else name
            produced.append((nxt, new_path))
        return produced, bool(produced)

    import time as _time
    deadline = _time.monotonic() + 12.0  # hard wall-clock guard per chain
    for _depth in range(max_depth):
        if not frontier or _time.monotonic() > deadline:
            break
        from core.parallel import pmap as _pmap
        next_frontier = []
        for (_branch, produced) in _pmap(expand_branch, frontier,
                                         workers=min(4, max(2, len(frontier))),
                                         desc="chain"):
            if isinstance(produced, Exception):
                continue
            produced_list, _applied = produced
            for nxt, new_path in produced_list:
                if nxt in seen_nodes or len(seen_nodes) > 600:
                    continue
                seen_nodes.add(nxt)
                next_frontier.append((nxt, new_path))
                results.append((new_path, nxt))
        if not next_frontier:
            break

        def sortkey(item):
            txt, _ = item
            bonus = -1000.0 if _chain_flaggy(txt) else 0.0
            # a node that itself looks like another encoding layer MUST
            # outrank same-length junk — this is what keeps multi-layer
            # chains (hex>xor>base64...) alive against decoy branches
            try:
                if _lle_cached(txt):
                    bonus -= 600.0
            except Exception:
                pass
            return bonus + _chain_score(txt)
        next_frontier.sort(key=sortkey)
        frontier = next_frontier[:max_branches]
    return results


# ---------------------------------------------------------------------------
# Public "run all encodings" — used by autodetect
# ---------------------------------------------------------------------------
def try_all_encodings(text):
    """Returns list of (label, decoded_text). Decoders run in parallel —
    they are pure functions, so a thread pool cuts wall time to the slowest
    single decoder instead of the sum."""
    from core.parallel import pmap
    checks = [
        ("base64", dec_base64), ("base32", dec_base32), ("base16", dec_base16),
        ("base85", dec_base85), ("ascii85", dec_ascii85),
        ("base45", dec_base45),
        ("base58", dec_base58), ("base62", dec_base62), ("base36", dec_base36),
        ("hex", dec_hex), ("binary", dec_binary), ("octal", dec_octal),
        ("decimal", dec_decimal), ("url", dec_url), ("unicode", dec_unicode),
        ("html", dec_html), ("rot13", dec_rot13), ("rot47", dec_rot47),
        ("leet", dec_leet), ("morse", dec_morse), ("brainfuck", dec_brainfuck),
        ("ook", dec_ook), ("emoji", dec_emoji),
        ("emoji-offset", dec_emoji_offset), ("emoji-subst", dec_emoji_subst),
        ("malbolge", dec_malbolge), ("custom-base", dec_custom_base),
        ("uuencode", dec_uuencode), ("quoted-printable", dec_quoted_printable),
        ("base32hex", dec_base32hex), ("a1z26", dec_a1z26),
        ("nato", dec_nato), ("tapcode", dec_tapcode),
        ("jwt-payload", dec_jwt_payload),
    ]

    def run_check(item):
        label, fn = item
        try:
            return (label, fn(text))
        except Exception:
            return (label, None)

    results = []
    for (_item, res) in pmap(run_check, checks, workers=8, desc="encodings"):
        if isinstance(res, Exception):
            continue
        label, out = res
        if out and out != text and is_printable_text(out):
            results.append((label, out))
    # gzip works on bytes
    try:
        raw = text.encode("latin-1")
    except Exception:
        raw = b""
    if raw:
        out = dec_gzip(raw)
        if out and is_printable_text(out):
            results.append(("gzip/zlib", out))
    # base64 -> file?
    try:
        raw = base64.b64decode(text, validate=True)
        magic = sniff_bytes(raw)
        if magic:
            results.append((f"base64 -> {magic}", raw.decode("latin-1")))
    except Exception:
        pass
    # chain decode
    try:
        stages = chain_decode(text)
        if stages:
            final = stages[-1][1]
            if final != text:
                results.append(("chain(" + "->".join(n for n, _ in stages) + ")",
                                final))
    except Exception:
        pass
    return results
