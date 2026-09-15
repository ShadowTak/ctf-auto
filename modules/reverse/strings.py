"""Extract printable strings from binaries, including UTF-16.

``strings(1)`` only sees single-byte text, so compiled Android manifests,
Windows resources and Java class files (which store text as UTF-16) appear
empty.  Decoding such data with a blanket ``utf-16`` codec instead produces
garbage that the flag extractor happily turns into brace-shaped noise.  Pulling
out real runs of each encoding keeps the signal and drops the noise.
"""
import re

_MIN_LEN = 4
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_LEN)
_UTF16LE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % _MIN_LEN)
_UTF16BE_RUN = re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % _MIN_LEN)


def extract_strings(data, min_len=_MIN_LEN):
    """Return decoded printable runs from ``data`` (ASCII, UTF-16LE, UTF-16BE).

    Results are de-duplicated and ordered by first appearance so the output is
    deterministic; ``min_len`` counts characters, not bytes.
    """
    if not data:
        return []
    found = {}
    for match in _ASCII_RUN.finditer(data):
        value = match.group(0).decode("ascii")
        found.setdefault(value, match.start())
    for match in _UTF16LE_RUN.finditer(data):
        value = match.group(0).decode("utf-16-le")
        found.setdefault(value, match.start())
    for match in _UTF16BE_RUN.finditer(data):
        value = match.group(0).decode("utf-16-be")
        found.setdefault(value, match.start())
    return [value for value, _ in sorted(found.items(), key=lambda kv: kv[1])]


def extract_flag_like_strings(data, min_len=_MIN_LEN):
    """Only the strings that could plausibly carry a flag or clue.

    Scanning every run of a 30MB binary is wasteful; this pre-filter keeps the
    strings that contain braces or flag vocabulary.
    """
    out = []
    for value in extract_strings(data, min_len=min_len):
        low = value.lower()
        if "{" in value or "flag" in low or "ctf" in low or "key" in low:
            out.append(value)
    return out
