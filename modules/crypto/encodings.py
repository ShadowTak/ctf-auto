"""Encoding decoders: base*, hex, binary, octal, decimal, URL, unicode,
HTML entities, leetspeak, morse, brainfuck, ROT, compression sniffing,
file-magic detection and recursive chain decoding."""
import base64
import binascii
import gzip
import html
import re
import struct
import urllib.parse
import zlib

from .common import is_printable_text

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
    ("hex", dec_hex),
    ("binary", dec_binary),
    ("octal", dec_octal),
    ("decimal", dec_decimal),
    ("url", dec_url),
    ("html", dec_html),
    ("unicode", dec_unicode),
    ("gzip", lambda s: dec_gzip(s.encode("latin-1"))),
]

_CHAIN_TRANSFORMS = [
    ("rot13", dec_rot13),
    ("rot47", dec_rot47),
    ("leet", dec_leet),
    ("morse", dec_morse),
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
    results = []
    frontier = [(text, "")]
    seen_nodes = {text}
    for _ in range(max_depth):
        if not frontier:
            break
        next_frontier = []
        for cur, path in frontier:
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
                seen_nodes.add(nxt)
                applied_structural = True
                new_path = f"{path}>{name}" if path else name
                next_frontier.append((nxt, new_path))
                results.append((new_path, nxt))
            if applied_structural:
                continue
            # dead end: peel a rot13/leet-style layer, but never re-run it on
            # its own output (no rot13-of-rot13-of-... nonsense)
            for name, fn in _CHAIN_TRANSFORMS:
                try:
                    nxt = fn(cur)
                except Exception:
                    nxt = None
                if not nxt or nxt == cur:
                    continue
                if nxt in seen_nodes:
                    continue
                seen_nodes.add(nxt)
                new_path = f"{path}>{name}" if path else name
                next_frontier.append((nxt, new_path))
                results.append((new_path, nxt))
        if not next_frontier:
            break

        def sortkey(item):
            txt, _ = item
            bonus = -1000.0 if _chain_flaggy(txt) else 0.0
            return bonus + _chain_score(txt)

        next_frontier.sort(key=sortkey)
        frontier = next_frontier[:max_branches]
    return results


# ---------------------------------------------------------------------------
# Public "run all encodings" — used by autodetect
# ---------------------------------------------------------------------------
def try_all_encodings(text):
    """Returns list of (label, decoded_text)."""
    results = []
    checks = [
        ("base64", dec_base64), ("base32", dec_base32), ("base16", dec_base16),
        ("base85", dec_base85), ("hex", dec_hex), ("binary", dec_binary),
        ("octal", dec_octal), ("decimal", dec_decimal), ("url", dec_url),
        ("unicode", dec_unicode), ("html", dec_html), ("rot13", dec_rot13),
        ("rot47", dec_rot47), ("leet", dec_leet), ("morse", dec_morse),
        ("brainfuck", dec_brainfuck),
    ]
    for label, fn in checks:
        try:
            out = fn(text)
        except Exception:
            out = None
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
