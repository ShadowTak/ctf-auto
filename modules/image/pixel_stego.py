"""Optional Pillow-backed pixel-plane steganography helpers.

This module is intentionally conservative: it only reads pixels, never
rewrites the input image, and returns bounded candidates with the exact
extraction method so callers can distinguish a real hit from a noisy plane.
"""
import re

from core.flag import extract_flags

MAX_PIXELS = 1_000_000
MAX_CANDIDATES = 80
_FLAG_RE = re.compile(r"[A-Za-z0-9_-]{2,30}\{[^}\n]{1,300}\}")


def _pack_bits(bits, offset=0, invert=False):
    """Pack MSB-first bytes from a bit stream, tolerating a short tail."""
    usable = bits[offset:]
    out = bytearray()
    for pos in range(0, len(usable) - 7, 8):
        value = 0
        for bit in usable[pos:pos + 8]:
            value = (value << 1) | (1 - bit if invert else bit)
        out.append(value)
    return bytes(out)


def _candidate_text(raw):
    text = raw.decode("utf-8", "replace")
    # Stego payloads commonly have NUL padding after the useful message.
    text = text.split("\x00", 1)[0].strip()
    if len(text) < 4:
        return "", 0.0, []
    printable = sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text)
    known, candidates = extract_flags(text)
    marker = bool(_FLAG_RE.search(text))
    score = printable + (1.0 if known else 0.0) + (0.35 if candidates else 0.0)
    if printable < 0.82 and not marker:
        return "", score, known + candidates
    return text, score, known + candidates


def _unique(items):
    out, seen = [], set()
    for item in items:
        key = (item.get("method"), item.get("output"))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_CANDIDATES:
            break
    return out


def extract_pixel_planes(path):
    """Extract common RGB/RGBA bit planes when Pillow is available.

    It checks LSB and all planes for single channels, plus interleaved RGB,
    BGR and RGBA LSB planes. Large images are skipped rather than making an
    automatic scan unexpectedly expensive.
    """
    try:
        from PIL import Image
    except ImportError:
        return [], "Pillow not installed"
    try:
        with Image.open(path) as image:
            image.load()
            width, height = image.size
            count = width * height
            if count <= 0 or count > MAX_PIXELS:
                return [], f"pixel scan skipped: {count} pixels (limit {MAX_PIXELS})"
            rgba = image.convert("RGBA")
            if hasattr(rgba, "get_flattened_data"):
                pixels = list(rgba.get_flattened_data())
            else:
                pixels = list(rgba.getdata())
    except (OSError, ValueError) as exc:
        return [], f"pixel scan unavailable: {exc}"

    channel_names = {0: "R", 1: "G", 2: "B", 3: "A"}
    orders = [(0,), (1,), (2,), (3,), (0, 1, 2), (2, 1, 0), (0, 1, 2, 3)]
    results = []
    for order in orders:
        # All planes for individual channels; combined channels are most
        # useful at bit 0 and are deliberately bounded for speed.
        planes = range(8) if len(order) == 1 else (0,)
        label = "".join(channel_names[index] for index in order)
        for bit in planes:
            bits = []
            for pixel in pixels:
                for index in order:
                    bits.append((pixel[index] >> bit) & 1)
            # offset 0 is the normal format; 1..7 catches a bit prefix before
            # the message without multiplying work for every permutation.
            for offset in (0, 1, 7):
                for invert in (False, True):
                    raw = _pack_bits(bits, offset=offset, invert=invert)
                    text, score, flags = _candidate_text(raw)
                    if not text:
                        continue
                    method = f"Pillow {label} bit-plane {bit} offset {offset}"
                    if invert:
                        method += " inverted"
                    results.append({"method": method, "output": text[:4096],
                                    "score": round(score, 4), "flags": flags})
    results.sort(key=lambda item: (-bool(item.get("flags")), -item.get("score", 0)))
    return _unique(results), None
