"""Hint-driven bit extraction for images that announce their own parameters.

Some challenges leave the recipe inside the file itself — a PNG text chunk such
as ``profile: alpha7;seed=7a11f00d;count=700`` — and then scatter the payload
across pseudo-random sample positions instead of writing it sequentially.  A
plain LSB dump finds nothing because the *positions* are the key.

This module reads those hints and sweeps the usual generator families
(MT19937, Java LCG48, Python ``random``, xorshift/splitmix/mulberry/sfc32,
linear congruential generators and hash keystreams) crossed with the usual
index mappings (pixel index, bit index, x/y pairs, transposed traversal), so a
solvable file solves and an unsolvable one is reported honestly.
"""

from __future__ import annotations

import hashlib
import random
import re

from core.flag import extract_flags

MAX_COUNT = 120_000
MASK32 = 0xFFFFFFFF
MASK48 = (1 << 48) - 1

_HINT_RE = re.compile(
    r"(?i)\b(seed|count|bits|length|skip|offset|channel|plane|bit)\s*[=:]\s*"
    r"([0-9a-fx]+)")
_ALPHA_HINT_RE = re.compile(r"(?i)\balpha\s*(\d)\b")


def _to_int(raw):
    """Hints mix decimal and bare hex (``seed=7a11f00d``)."""
    for base in (0, 16, 10):
        try:
            return int(raw, base)
        except ValueError:
            continue
    return None


def parse_hints(texts):
    """Extract seed/count/channel/plane parameters from image text chunks."""
    hints = {"seed": None, "count": None, "channel": None, "plane": None,
             "skip": 0, "raw": []}
    for text in texts or ():
        value = str(text or "")
        if not value or len(value) > 4000:
            continue
        if not _HINT_RE.search(value) and not _ALPHA_HINT_RE.search(value):
            continue
        hints["raw"].append(value[:200])
        for key, raw in _HINT_RE.findall(value):
            key = key.lower()
            number = _to_int(raw)
            if number is None:
                continue
            if key == "seed" and hints["seed"] is None:
                hints["seed"] = number
            elif key in ("count", "bits", "length") and hints["count"] is None:
                hints["count"] = number
            elif key in ("skip", "offset") and not hints["skip"]:
                hints["skip"] = number
            elif key == "channel" and hints["channel"] is None:
                hints["channel"] = number
            elif key in ("plane", "bit") and hints["plane"] is None:
                hints["plane"] = number
        alpha = _ALPHA_HINT_RE.search(value)
        if alpha and hints["plane"] is None and "bit" not in value.lower():
            # "alpha7" can mean "the 7th bit" or just a 7-bit alpha channel, so
            # the plane stays open and the sweep tries them all.
            hints["plane"] = None
            hints["alpha_hint"] = int(alpha.group(1))
        lowered = value.lower()
        if hints["channel"] is None:
            for name, index in (("alpha", 3), ("red", 0), ("blue", 2),
                                ("green", 1)):
                if name in lowered:
                    hints["channel"] = index
                    break
    hints["raw"] = list(dict.fromkeys(hints["raw"]))[:4]
    return hints


# Generators ----------------------------------------------------------------


def _mt19937(seed, count):
    state = [seed & MASK32] + [0] * 623
    for i in range(1, 624):
        state[i] = (1812433253 * (state[i - 1] ^ (state[i - 1] >> 30)) + i) & MASK32
    out, index = [], 624
    for _ in range(count):
        if index >= 624:
            for i in range(624):
                y = (state[i] & 0x80000000) | (state[(i + 1) % 624] & 0x7FFFFFFF)
                state[i] = state[(i + 397) % 624] ^ (y >> 1)
                if y & 1:
                    state[i] ^= 2567483615
            index = 0
        y = state[index]
        index += 1
        y ^= y >> 11
        y ^= (y << 7) & 2636928640
        y ^= (y << 15) & 4022730752
        y ^= y >> 18
        out.append(y & MASK32)
    return out


def _java_random(seed, count):
    state = (seed ^ 0x5DEECE66D) & MASK48
    out = []
    for _ in range(count):
        state = (state * 0x5DEECE66D + 0xB) & MASK48
        out.append((state >> 17) & MASK32)
    return out


def _lcg(seed, count, a, c, modulus):
    state = seed & modulus
    out = []
    for _ in range(count):
        state = (a * state + c) & modulus
        out.append(state)
    return out


def _xorshift32(seed, count):
    state = (seed & MASK32) or 0x9E3779B9
    out = []
    for _ in range(count):
        state ^= (state << 13) & MASK32
        state ^= state >> 17
        state ^= (state << 5) & MASK32
        out.append(state & MASK32)
    return out


def _splitmix32(seed, count):
    state = seed & MASK32
    out = []
    for _ in range(count):
        state = (state + 0x9E3779B9) & MASK32
        value = state
        value ^= value >> 16
        value = (value * 0x21F0AAAD) & MASK32
        value ^= value >> 15
        value = (value * 0x735A2D97) & MASK32
        value ^= value >> 15
        out.append(value & MASK32)
    return out


def _mulberry32(seed, count):
    state = seed & MASK32
    out = []
    for _ in range(count):
        state = (state + 0x6D2B79F5) & MASK32
        value = state
        value = ((value ^ (value >> 15)) * (value | 1)) & MASK32
        value ^= (value + (((value ^ (value >> 7)) * (value | 61)) & MASK32)) & MASK32
        out.append((value ^ (value >> 14)) & MASK32)
    return out


def _sfc32(seed, count):
    a = b = c = seed & MASK32
    d = 0x9E3779B9
    out = []
    for _ in range(count):
        a = (a + b) & MASK32
        d ^= d >> 9
        d = (d + a) & MASK32
        a = (a << 9) & MASK32
        b ^= b << 3
        b = (b + a) & MASK32
        a = (a << 11) & MASK32
        out.append((a + b + d) & MASK32)
    return out


def _xorshift128plus(seed, count):
    high = (seed * 0x2545F4914F6CDD1D) & MASK32
    low = (seed & MASK32) or 1
    out = []
    for _ in range(count):
        low ^= (low << 23) & MASK32
        low ^= low >> 17
        low ^= high
        value = (low + high) & MASK32
        high, low = low, value
        out.append(value & MASK32)
    return out


def _hash_stream(seed, count, algorithm):
    block = seed.to_bytes(8, "big", signed=False)
    return [int.from_bytes(algorithm(block + counter.to_bytes(8, "big")).digest()[:4],
                           "big")
            for counter in range(count)]


def _python_random(seed, count):
    rng = random.Random(seed)
    return [rng.getrandbits(32) for _ in range(count)]


def generators(seed, count):
    """Named 32-bit streams for one seed (bounded work per family)."""
    return {
        "python-random": _python_random(seed, count),
        "mt19937": _mt19937(seed, count),
        "java-random": _java_random(seed, count),
        "xorshift32": _xorshift32(seed, count),
        "splitmix32": _splitmix32(seed, count),
        "mulberry32": _mulberry32(seed, count),
        "sfc32": _sfc32(seed, count),
        "xorshift128+": _xorshift128plus(seed, count),
        "lcg-glibc": _lcg(seed, count, 1103515245, 12345, MASK32),
        "lcg-minstd": _lcg(seed, count, 214013, 2531011, MASK32),
        "lcg-numerical": _lcg(seed, count, 1664525, 1013904223, MASK32),
        "sha256-stream": _hash_stream(seed, count, hashlib.sha256),
        "md5-stream": _hash_stream(seed, count, hashlib.md5),
    }


# Index mappings ------------------------------------------------------------


def index_variants(values, total, width, height):
    """Ways to turn a value stream into sample positions."""
    bits_total = total * 8
    power = total & (total - 1) == 0
    variants = {
        "pixel-mod": [value % total for value in values],
        "pixel-high": [(value >> 8) % total for value in values],
        "bit-mod": [value % bits_total for value in values],
        "bit-slice": [(value >> 8) % bits_total for value in values],
        "xy-pairs": [((values[i] >> 8) % width) + (values[i + 1] % height) * width
                     for i in range(0, len(values) - 1, 2)],
        "column-major": [((value % total) // height) * height +
                         ((value % total) % height) for value in values],
    }
    if power:
        variants["pixel-mask"] = [value & (total - 1) for value in values]
    return variants


def _bits_to_bytes(bits, skip=0):
    usable = bits[skip:]
    out = bytearray()
    for pos in range(0, len(usable) - 7, 8):
        value = 0
        for bit in usable[pos:pos + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def _score(raw):
    text = raw.decode("utf-8", "replace").split("\x00", 1)[0].strip()
    if len(text) < 6:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t") / len(text)
    known, candidates = extract_flags(text)
    if printable < 0.92 and not (known or candidates):
        return None
    return {"text": text[:2048], "score": round(printable + 2.0 * len(known) +
                                                0.5 * len(candidates), 3),
            "flags": list(known), "candidates": list(candidates)}


def sweep(path, hints, limit=24):
    """Try hint-seeded extraction over every generator/index combination."""
    try:
        from PIL import Image
    except ImportError:
        return [], "Pillow not installed"
    seed = hints.get("seed")
    if seed is None:
        return [], "no seed hint"
    count = max(8, min(int(hints.get("count") or 700), MAX_COUNT))
    try:
        with Image.open(path) as image:
            image.load()
            width, height = image.size
            if width * height <= 0 or width * height > 4_000_000:
                return [], "hint sweep skipped: image too large"
            rgba = image.convert("RGBA")
            pixels = (list(rgba.get_flattened_data())
                      if hasattr(rgba, "get_flattened_data") else list(rgba.getdata()))
    except (OSError, ValueError) as exc:
        return [], f"hint sweep unavailable: {exc}"
    channel = hints.get("channel")
    channel = 3 if channel is None or not 0 <= int(channel) <= 3 else int(channel)
    if hints.get("plane") is None:
        # Unspecified plane: check the hinted one first, then the rest.
        hinted = hints.get("alpha_hint")
        planes = ([hinted] if isinstance(hinted, int) and 0 <= hinted <= 7 else []) + \
                 [value for value in range(8) if value != hinted]
    else:
        planes = [max(0, min(int(hints["plane"]), 7))]
    skip = max(0, int(hints.get("skip") or 0))

    results = []
    streams = generators(int(seed), count + 4)
    combinations = 0
    for name, values in streams.items():
        if not values:
            continue
        for variant, indices in index_variants(values, len(pixels), width,
                                               height).items():
            if len(indices) < count // 2:
                continue
            for plane in planes:
                combinations += 1
                try:
                    if variant.startswith("bit"):
                        bits = [(pixels[index // 8][channel] >>
                                 (7 - (index % 8))) & 1
                                for index in indices[:count]]
                    else:
                        bits = [(pixels[index][channel] >> plane) & 1
                                for index in indices[:count]]
                except (IndexError, TypeError):
                    continue
                for invert in (False, True):
                    sample = bits if not invert else [1 - bit for bit in bits]
                    scored = _score(_bits_to_bytes(sample, skip=skip))
                    if not scored:
                        continue
                    scored.update({"generator": name, "mapping": variant,
                                   "channel": channel, "plane": plane,
                                   "inverted": invert})
                    results.append(scored)
    results.sort(key=lambda item: (-len(item.get("flags", ())), -item["score"]))
    deduped, seen = [], set()
    for item in results:
        if item["text"] in seen:
            continue
        seen.add(item["text"])
        deduped.append(item)
    note = None
    if not deduped:
        note = ("hint sweep tried %d generator/mapping combinations from seed "
                "0x%X without readable output" % (combinations, int(seed)))
    return deduped[:limit], note
