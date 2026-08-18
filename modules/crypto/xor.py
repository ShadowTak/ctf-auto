"""XOR solvers: single-byte, repeating-key (with auto key length via
normalized Hamming distance) and known-plaintext key recovery."""
import base64
import binascii
import itertools
import math
import re

from .common import chi_square, is_printable_text


def _to_bytes(data):
    """Accept str (raw or hex/base64-looking) or bytes. Returns bytes."""
    if isinstance(data, bytes):
        return data
    s = data.strip()
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s) and len(s) >= 8:
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    if re.fullmatch(r"[A-Za-z0-9+/=]+", s) and len(s) % 4 == 0:
        try:
            return base64.b64decode(s, validate=True)
        except Exception:
            pass
    return s.encode("latin-1")


def score_bytes(data):
    """Lower = more likely English plaintext."""
    try:
        return chi_square(data.decode("latin-1"))
    except Exception:
        return float("inf")


def single_byte_xor(data, top=10):
    data = _to_bytes(data)
    results = []
    for key in range(256):
        plain = bytes(b ^ key for b in data)
        if not is_printable_text(plain.decode("latin-1")):
            continue
        s = score_bytes(plain)
        results.append((s, key, plain))
    results.sort(key=lambda x: x[0])
    return [(f"key=0x{k:02x} ('{chr(k)}')", p.decode("latin-1"))
            for _, k, p in results[:top]]


def _hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _guess_keysize(data, max_len=40):
    best = []
    for ks in range(2, max_len + 1):
        blocks = [data[i:i + ks] for i in range(0, len(data) - ks, ks)][:8]
        if len(blocks) < 2:
            continue
        dists = [
            _hamming(blocks[i], blocks[i + 1]) / ks
            for i in range(len(blocks) - 1)
        ]
        avg = sum(dists) / len(dists)
        best.append((avg, ks))
    best.sort()
    return [ks for _, ks in best[:5]]


def _assemble(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# Common CTF flag prefixes used as cribs for XOR key recovery
FLAG_PREFIXES = [
    b"flag{", b"FLAG{", b"Flag{", b"ctf{", b"CTF{", b"picoCTF{",
    b"picoctf{", b"redacted{", b"redacted{", b"HTB{", b"THM{",
]


def _refine_key(data, key, score_fn, rounds=3):
    """Coordinate-descent per-byte refinement; a cheap first pass."""
    key = bytearray(key)
    best_score = score_fn(_assemble(data, key).decode("latin-1"))
    for _ in range(rounds):
        changed = False
        for pos in range(len(key)):
            cur = key[pos]
            for b in range(256):
                if b == cur:
                    continue
                key[pos] = b
                s = score_fn(_assemble(data, key).decode("latin-1"))
                if s < best_score:
                    best_score = s
                    cur = b
                    changed = True
            key[pos] = cur
        if not changed:
            break
    return bytes(key), best_score


def _anneal_key(data, key, score_fn, iters=6000):
    """Simulated annealing over key bytes; escapes local optima that the
    coordinate descent gets stuck in."""
    import random
    rng = random.Random(0xC7F)
    ks = len(key)
    cur = bytearray(key)
    cur_score = score_fn(_assemble(data, cur).decode("latin-1"))
    best = cur.copy()
    best_score = cur_score
    temp = 4.0
    for _ in range(iters):
        pos = rng.randrange(ks)
        new = bytearray(cur)
        new[pos] = rng.randrange(256)
        s = score_fn(_assemble(data, new).decode("latin-1"))
        if s <= cur_score or rng.random() < math.exp(-(s - cur_score) / temp):
            cur, cur_score = new, s
        if cur_score < best_score:
            best, best_score = cur.copy(), cur_score
        temp = max(0.1, temp * 0.998)
    return bytes(best), best_score


def repeating_key_xor(data, top=5, keylen_hint=None):
    from .common import text_score

    data = _to_bytes(data)
    if len(data) < 8:
        return []
    if len(data) > 3000:
        # too long for key recovery; caller should use crib/known-pt instead
        return []
    if keylen_hint is None:
        if len(data) <= 300:
            # try every plausible length; short texts fool hamming/IC heuristics
            keylens = list(range(2, min(40, len(data) // 2) + 1))
        else:
            # longer texts: hamming-distance heuristic is reliable, and brute
            # forcing every length gets expensive on long inputs
            keylens = _guess_keysize(data)
    else:
        keylens = [keylen_hint]
    # anneal budget shrinks as the text grows (score cost is O(len));
    # short texts also cap lower — few chars per column means scoring is
    # noisy anyway and the crib/known-pt paths do the real work
    anneal_iters = max(300, min(3500, 70000 // max(len(data), 1)))
    all_results = []
    for ks in keylens:
        key = bytearray()
        for pos in range(ks):
            col = data[pos::ks]
            best_k, best_s = 0, float("inf")
            for k in range(256):
                plain = bytes(b ^ k for b in col)
                s = score_bytes(plain)
                if s < best_s:
                    best_s, best_k = s, k
            key.append(best_k)
        plain = _assemble(data, key)
        try:
            plain_text = plain.decode("latin-1")
        except Exception:
            continue
        if not is_printable_text(plain_text):
            continue
        all_results.append((text_score(plain_text), ks, key, plain))
    # the expensive refine+anneal only pays off on the few most promising
    # key lengths — the greedy pass already separates those out
    all_results.sort(key=lambda x: x[0])
    refined = []
    for ts, ks, key, plain in all_results[:3]:
        rkey, rts = _refine_key(data, key, text_score)
        rkey, rts = _anneal_key(data, rkey, text_score, iters=anneal_iters)
        rplain = _assemble(data, rkey)
        try:
            rtext = rplain.decode("latin-1")
        except Exception:
            continue
        refined.append((rts, ks, rkey, rplain))
    # merge: refined entries replace their keylen, unrefined stay as-is
    merged = {ks: (ts, key, plain) for ts, ks, key, plain in all_results}
    for ts, ks, rkey, rplain in refined:
        merged[ks] = (ts, rkey, rplain)
    final = sorted((ts, ks, key, plain) for ks, (ts, key, plain) in merged.items())
    return [(f"keylen={ks} key={key!r}",
             plain.decode("latin-1"))
            for _, ks, key, plain in final[:top]]


def crib_attack(data, prefixes=None):
    """Recover a repeating key when the plaintext starts with a known flag
    prefix. The prefix fixes the first key bytes; remaining key bytes are
    solved per column. Cheap printable-prefix gate avoids wasting time on
    inputs that are clearly not XOR data. Returns ranked candidates."""
    from .common import text_score

    data = _to_bytes(data)
    out = []
    for prefix in (prefixes or FLAG_PREFIXES):
        if len(data) < len(prefix):
            continue
        for ks in range(2, min(24, len(data) // 2) + 1):
            key = bytearray(ks)
            know = min(ks, len(prefix))
            for i in range(know):
                key[i] = data[i] ^ prefix[i]
            if ks > len(prefix):
                # cheap gate: with the known key bytes the first full period
                # must already be printable ASCII, else this is not the key
                probe = _assemble(data[:ks * 2], key)
                try:
                    if not is_printable_text(probe.decode("latin-1")):
                        continue
                except Exception:
                    continue
            for pos in range(know, ks):
                col = data[pos::ks]
                best_k, best_s = 0, float("inf")
                for k in range(256):
                    s = score_bytes(bytes(b ^ k for b in col))
                    if s < best_s:
                        best_s, best_k = s, k
                key[pos] = best_k
            plain = _assemble(data, key)
            try:
                text = plain.decode("latin-1")
            except Exception:
                continue
            if not is_printable_text(text):
                continue
            s = text_score(text)
            if s != float("inf") and s < 80:
                out.append(
                    (f"crib={prefix.decode(errors='replace')} keylen={ks} key={bytes(key)!r}",
                     text)
                )
    out.sort(key=lambda t: text_score(t[1]))
    return out[:10]


def known_plaintext_xor(data, known):
    """Recover a repeating key when part of the plaintext is known
    (e.g. starts with 'flag{'). known: str bytes or bytes."""
    data = _to_bytes(data)
    if isinstance(known, str):
        known = known.encode()
    key = bytearray()
    for i, b in enumerate(known):
        if i >= len(data):
            break
        key.append(data[i] ^ b)
    if not key:
        return None
    plain = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return bytes(key), plain


_COMMON_KEYS = [
    "password", "secret", "key", "flag", "admin", "root", "thailand",
    "thai", "ncsa", "cyber", "talent", "ctf", "funny", "hello", "world",
    "orange", "apple", "banana", "monkey", "hacker", "pwned", "crypto",
    "cipher", "decode", "encrypt", "victory", "winner", "challenge",
    "redacted", "redactedctf", "htb", "pico", "letmein", "welcome", "master",
]


def wordlist_crib_xor(data, top=5):
    """THCTT-style: the repeating key is a dictionary word and the plaintext
    contains that word ('message XORed with a word from the list, the result
    contains that word'). Tries every word from the bundled password list +
    common keys as the repeating key and scores the decrypted text."""
    from .common import text_score

    data = _to_bytes(data)
    if not data or len(data) > 8000:
        return []
    words = list(_COMMON_KEYS)
    try:
        import os
        for cand in (
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))), "wordlists", "passwords.txt"),
        ):
            if os.path.exists(cand):
                with open(cand, encoding="utf-8", errors="replace") as fh:
                    words += [w.strip() for w in fh if w.strip()]
                break
    except Exception:
        pass
    seen = set()
    out = []
    for w in words:
        w = w.strip()
        if not w or w in seen:
            continue
        seen.add(w)
        key = w.encode("latin-1", "replace")
        if not 2 <= len(key) <= 40:
            continue
        plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        try:
            text = plain.decode("latin-1")
        except Exception:
            continue
        if not is_printable_text(text):
            continue
        s = text_score(text)
        if s == float("inf"):
            continue
        # require either the word itself in the result (the THCTT spec) or a
        # strongly-English score (generic case)
        if w.lower() not in text.lower() and s >= 55:
            continue
        out.append((s, w, text))
    out.sort(key=lambda t: t[0])
    return [(f"wordlist key='{w}' (score {round(s,1)})", t)
            for s, w, t in out[:top]]


def crack_xor(data, known_plaintext=None):
    """Auto path: crib (decisive for CTF) -> single-byte -> repeating-key ->
    wordlist-key. The expensive anneal only runs when the crib found nothing."""
    from .common import text_score

    out = []
    data = _to_bytes(data)
    if not data:
        return out
    # crib first: flag-prefix XOR is the most common CTF pattern and it is
    # both fast and exact, so a hit can skip the expensive anneal
    try:
        cribs = crib_attack(data)
    except Exception:
        cribs = []
    for label, plain in cribs:
        out.append(("xor-crib " + label, plain))
    crib_hit = any(
        text_score(plain) < 60 for _, plain in cribs
    ) if cribs else False

    cands = single_byte_xor(data, top=5)
    for label, plain in cands:
        out.append(("xor-single " + label, plain))
    if not crib_hit:
        cands = repeating_key_xor(data, top=5)
        for label, plain in cands:
            out.append(("xor-repeating " + label, plain))
    # dictionary-word key (THCTT programming pattern)
    if not crib_hit:
        cands = wordlist_crib_xor(data, top=4)
        for label, plain in cands:
            out.append(("xor-wordlist " + label, plain))
    if known_plaintext:
        try:
            key, plain = known_plaintext_xor(data, known_plaintext)
            if key and is_printable_text(plain.decode("latin-1")):
                out.append((
                    f"xor-knownpt key={key!r}",
                    plain.decode("latin-1"),
                ))
        except Exception:
            pass
    return out
