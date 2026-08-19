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
    b"picoctf{", b"AegisCTF{", b"AEGIS{", b"aegis{", b"HTB{", b"THM{",
    b"THCTT{", b"TCTT{", b"Aegis{", b"CYBERHEROCTF{", b"CyberHeroCTF{",
    b"cyberheroctf{", b"NCSA{", b"WPICTF{",
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
    # Sort: flag-like results first (contain curly braces), then by score
    def _sort_key(item):
        _, text = item
        has_flag = 1 if re.search(r'[A-Za-z]{2,}\{[^}]{2,}\}', text) else 0
        return (-has_flag, text_score(text))
    out.sort(key=_sort_key)
    return out[:20]


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
    "aegis", "aegisctf", "htb", "pico", "letmein", "welcome", "master",
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


def two_time_pad_crib_drag(c1_bytes, c2_bytes, max_crib_len=20):
    """Two-time-pad crib-drag.

    c1 = p1 ^ key, c2 = p2 ^ key  (same key reused → OTP broken).
    xored = c1 ^ c2 = p1 ^ p2.

    Algorithm:
    1. For every flag prefix at every offset of p2, compute the implied
       p1 fragment.  If it *looks English*, record the (offset, prefix) as
       a hit.
    2. For each hit, try closing '}' at every subsequent position.
       Between prefix and '}' we recover p2 byte-by-byte: at each
       position, try every printable flag-character and score the implied
       p1 character for English-ness.  The flag-body candidate whose
       overall implied p1 scores highest wins.
    3. Also try standard repeated-key XOR recovery on c1 (the "reuse"
       might be a short repeating key rather than true OTP).
    """
    from .common import text_score
    if len(c1_bytes) != len(c2_bytes):
        return []
    n = len(c1_bytes)
    results = []
    xored = bytes(a ^ b for a, b in zip(c1_bytes, c2_bytes))

    # ── Method 1: OTP crib-drag ──────────────────────────────────────────
    # Step 1 – find (offset, prefix) pairs where implied p1 is English
    hits = []
    for prefix in FLAG_PREFIXES:
        plen = len(prefix)
        for off in range(n - plen + 1):
            p1_frag = bytes(xored[off + i] ^ prefix[i] for i in range(plen))
            if _looks_english(p1_frag):
                hits.append((off, prefix))

    # Step 2 – crib-drag English phrases against xored to recover p2.
    #
    # Key insight: p1 is English, p2 is the message (containing the flag).
    # If we guess p1 at any position, p2 = xored ^ guess.  Try common
    # English phrases/fragments at various offsets.  When the implied p2
    # contains a flag pattern, we have a match.
    _COMMON_PHRASES = [
        # Full pangram (covers entire 81-byte messages)
        b'The quick brown fox jumps over the lazy dog 0123456789 ABCDEFG',
        b'the quick brown fox jumps over the lazy dog 0123456789 ABCDEFG',
        b'The quick brown fox jumps over the lazy dog',
        b'the quick brown fox jumps over the lazy dog',
        b'The quick brown fox jumps',
        b'The quick brown fox ',
        b'the quick brown fox ',
        # Common short phrases
        b'the ', b'The ', b'jumps over', b'lazy dog',
        b'a ', b'an ', b'is ', b'was ', b'hello', b'Hello',
        b'welcome', b'Welcome', b'message', b'Secret', b'secret',
        b'flag', b'Flag', b'internal', b'memo', b'Memo',
        b'for ', b'and ', b'or ', b'in ', b'of ', b'to ',
        b'with ', b'this ', b'that ', b'are ', b'can ',
        b'not ', b'you ', b'all ', b'any ', b'how ',
        b'what ', b'when ', b'where ', b'who ', b'why ',
    ]
    _FLAG_BODY_RE = re.compile(r'\{[A-Za-z0-9_ -]{2,}\}')

    # For each offset, try each phrase and check if implied p2 has a flag
    for phrase in _COMMON_PHRASES:
        pl = len(phrase)
        for off in range(max(0, n - pl + 1)):
            p2_cand = bytes(xored[off + i] ^ phrase[i] for i in range(pl))
            p2_txt = p2_cand.decode('latin-1', errors='replace')
            # Check if this reveals a flag
            m = re.search(r'[A-Za-z]{2,}\{[A-Za-z0-9_ -]{2,}\}', p2_txt)
            if m:
                flag_str = m.group(0)
                # Verify the full p1 at this zone is English
                flag_start = off + m.start()
                flag_len = m.end() - m.start()
                p1_zone = bytes(xored[flag_start + i] ^ flag_cand_i
                                for i, flag_cand_i in
                                enumerate(flag_str.encode('latin-1')))
                if _looks_english(p1_zone):
                    s = text_score(p1_zone.decode('latin-1', errors='replace'))
                    results.append((max(-s, -10),
                                    f"two-time-pad phrase='{phrase.decode()}' "
                                    f"at={off} flag={flag_str!r}",
                                    flag_str))
    # Also try with the known prefix hits: use the prefix to anchor and
    # extend via English word cribbing.
    for off, prefix in hits:
        plen = len(prefix)
        # Try extending the known p1 fragment with common English words
        known_p1 = bytes(xored[off + i] ^ prefix[i] for i in range(plen))
        for phrase in _COMMON_PHRASES:
            # Place phrase right after the prefix in p1
            ext_off = off + plen
            if ext_off + len(phrase) > n:
                continue
            p2_ext = bytes(xored[ext_off + i] ^ phrase[i]
                           for i in range(len(phrase)))
            p2_ext_txt = p2_ext.decode('latin-1', errors='replace')
            # Check if extension reveals flag chars
            if re.search(r'[A-Za-z0-9_ -]{3,}\}', p2_ext_txt):
                # Build full flag candidate
                full_flag_zone = prefix + p2_ext
                full_p1 = known_p1 + phrase
                flag_m = _FLAG_BODY_RE.search(
                    full_flag_zone.decode('latin-1', errors='replace'))
                if flag_m:
                    flag_str = flag_m.group(0)
                    # Check the prefix part matches a known CTF prefix
                    pre = full_flag_zone.decode('latin-1', errors='replace')
                    pre_part = pre[:pre.index('{') + 1] if '{' in pre else ''
                    if any(p.decode() in pre_part for p in FLAG_PREFIXES):
                        s = text_score(full_p1.decode('latin-1', errors='replace'))
                        results.append((max(-s, -10),
                                        f"two-time-pad ext='{phrase.decode()}' "
                                        f"at={off} flag={flag_str!r}",
                                        flag_str))

    # ── Method 2: repeated-key XOR on c1 (p1 is English) ─────────────────
    for kl in range(2, min(21, n // 2 + 1)):
        key = bytearray()
        for pos in range(kl):
            col = c1_bytes[pos::kl]
            best_k, best_s = 0, float("inf")
            for k in range(256):
                plain = bytes(b ^ k for b in col)
                s = score_bytes(plain)
                if s < best_s:
                    best_s, best_k = s, k
            key.append(best_k)
        full_p2 = bytes(c2_bytes[i] ^ key[i % kl] for i in range(n))
        try:
            full_text = full_p2.decode("latin-1")
        except Exception:
            continue
        if not is_printable_text(full_text):
            continue
        has_flag = bool(re.search(r'[A-Za-z]{2,}\{[^}]{2,}\}', full_text))
        if has_flag:
            results.append((-10,
                            f"two-time keylen={kl} key={bytes(key)!r}",
                            full_text))

    # Deduplicate and sort
    results.sort(key=lambda x: x[0])
    seen = set()
    out = []
    for _s, label, text in results[:30]:
        short = text[:80]
        if short not in seen:
            seen.add(short)
            out.append((label, text))
    return out[:10]


def _looks_english(data, min_alpha=4, min_space_ratio=0.03):
    """Check if a byte/str chunk looks like English text.

    Requirements: mostly alphabetic, spaces at ~3-20%, mixed case,
    no control characters, and common English patterns present.
    """
    if isinstance(data, bytes):
        try:
            text = data.decode('latin-1')
        except Exception:
            return False
    else:
        text = str(data)
    if len(text) < 4:
        return False
    # No control characters (except space/tab/newline)
    ctrl = sum(1 for c in text if ord(c) < 32 and c not in '\t\n\r')
    if ctrl > 0:
        return False
    word_chars = sum(1 for c in text if c.isalnum() or c in ' \t')
    spaces = text.count(' ')
    space_ratio = spaces / len(text)
    has_upper = any(c.isupper() for c in text)
    has_lower = any(c.islower() for c in text)
    # Word chars (alpha+digits+space) must dominate, spaces reasonable
    if not (word_chars / len(text) >= 0.7 and
            min_space_ratio <= space_ratio <= 0.4):
        return False
    # For longer fragments, require mixed case; short ones may be mid-sentence
    if len(text) >= 12 and not (has_upper and has_lower):
        return False
    # Check for common English bigrams/trigrams
    tl = text.lower()
    english_patterns = ['th', 'he', 'in', 'er', 'an', 're', 'on', 'at',
                       'en', 'nd', 'the', 'and', 'ing']
    hits = sum(1 for p in english_patterns if p in tl)
    return hits >= 2


def _english_char_score(ch):
    """Score how likely a character is to appear in English text. Higher = better."""
    ch = ch.lower()
    if ch == ' ':
        return 20
    if ch in 'etaoinshrd':
        return 15
    if ch in 'lcumwfgyp':
        return 10
    if ch in 'bvkjxqz':
        return 5
    if ch.isalpha():
        return 3
    if ch in ',.!?;:-\'"':
        return 2
    return 0


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
