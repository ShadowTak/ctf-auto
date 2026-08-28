"""Web recon: headers, tech fingerprint, robots/sitemap, CMS hints, HTTP
methods, and flag scanning of the homepage."""
import re
import urllib.parse

from core import httpx
from core.flag import extract_flags
from core.output import ok_line, warn_line
from .response_diff import method_matrix

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-content-type-options",
    "x-frame-options", "referrer-policy", "permissions-policy", "x-xss-protection",
]

TECH_HINTS = [
    ("x-powered-by", None), ("server", None), ("x-aspnet-version", "ASP.NET"),
    ("x-aspnet-mvc-version", "ASP.NET MVC"), ("x-generator", "generator"),
    ("x-drupal-cache", "Drupal"), ("x-drupal-dynamic-cache", "Drupal"),
    ("x-joomla-version", "Joomla"), ("x-varnish", "Varnish"),
    ("x-cache", "Varnish/CDN"), ("x-runtime", "Ruby/Rack"),
    ("x-github-request-id", "GitHub Pages"), ("x-vercel-id", "Vercel"),
    ("x-nextjs-cache", "Next.js"), ("x-served-by", None), ("x-amz-cf-id", "CloudFront"),
    ("x-amz-request-id", "AWS S3"), ("cf-ray", "Cloudflare"),
    ("x-azure-ref", "Azure"), ("x-nginx-proxy", "Nginx"),
]


def scan_headers(url):
    r = httpx.get(url, timeout=10)
    if r is None:
        warn_line(f"เชื่อมต่อ {url} ไม่ได้")
        return r, []
    print()
    print(f"  Status : {r.status} {r.reason}")
    found = []
    for key, val in r.headers.items():
        if key == "server":
            print(f"  Server : {val}")
            found.append(f"Server: {val}")
        elif key == "x-powered-by":
            print(f"  Powered: {val}")
            found.append(f"X-Powered-By: {val}")
    # tech hints
    hints = []
    for key, _ in TECH_HINTS:
        if key in r.headers:
            v = r.headers[key]
            hints.append(f"{key}: {v[:80]}")
    if hints:
        print("  Tech   : " + ", ".join(hints))
        found.extend(hints)
    # missing security headers
    missing = [h for h in SECURITY_HEADERS if h not in r.headers]
    if missing:
        warn_line("หัวข้อความปลอดภัยที่ขาด: " + ", ".join(missing))
    else:
        ok_line("มี security headers ครบ")
    # cookies
    cookies = r.headers.get("set-cookie", "")
    if cookies:
        print(f"  Cookies: {cookies[:200]}")
    return r, found


def scan_robots(base):
    r = httpx.get(base + "/robots.txt", timeout=8)
    if r is None or r.status != 200:
        return [], None
    text = r.text
    paths = []
    for line in text.splitlines():
        m = re.match(r"(?i)^\s*(?:Disallow|Allow)\s*:\s*(\S+)", line)
        if m:
            p = m.group(1).strip()
            if p and p != "/":
                paths.append(p.lstrip("/"))
    print(f"  robots.txt: พบ {len(paths)} path")
    return paths, text


def scan_sitemap(base):
    found = []
    for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"):
        r = httpx.get(base + path, timeout=6)
        if r is not None and r.status == 200:
            urls = re.findall(r"<loc>([^<]+)</loc>", r.text)
            print(f"  {path}: พบ {len(urls)} URL")
            origin = urllib.parse.urlparse(base).netloc
            for value in urls:
                parsed = urllib.parse.urlparse(value.strip())
                if parsed.netloc and parsed.netloc != origin:
                    continue
                route = parsed.path or "/"
                if parsed.query:
                    route += "?" + parsed.query
                found.append(route.lstrip("/"))
            # sitemap indexes commonly point at another sitemap; retain the
            # first useful document and let bounded discovery handle the rest.
            if found:
                return list(dict.fromkeys(found))
    return found


def scan_security_txt(base):
    r = httpx.get(base + "/.well-known/security.txt", timeout=6)
    if r is not None and r.status == 200:
        print(f"  security.txt: {len(r.text)} bytes")
        return r.text
    return None


def http_methods(url):
    records = method_matrix(url)
    allowed = []
    for record in records:
        if record["method"] == "OPTIONS" and record.get("allow"):
            allowed = [m.strip() for m in record["allow"].split(",")]
            print(f"  Allow: {', '.join(allowed)}")
        if record["method"] in {"TRACE", "PUT", "PATCH", "DELETE"} and record["status"] not in (403, 404, 405, 501):
            print(f"  [!] {record['method']} -> {record['status']} (อาจใช้ได้)")
    return allowed


def cms_hints(base):
    checks = {
        "/wp-login.php": "WordPress",
        "/wp-content/": "WordPress",
        "/administrator/": "Joomla",
        "/user/login": "Drupal",
        "/index.php?option=com_content": "Joomla",
    }
    found = []
    for path, cms in checks.items():
        r = httpx.get(base + path, timeout=5)
        if r is not None and r.status in (200, 301, 302, 403) and r.status != 404:
            found.append(cms)
    if found:
        print(f"  CMS hint: {', '.join(set(found))}")
    return list(set(found))


def scan_homepage(base):
    """Scan homepage + linked pages for flags and interesting content."""
    flags = []
    r = httpx.get(base + "/", timeout=10)
    if r is None:
        return flags
    known, cands = extract_flags(r.text)
    for f in known + cands:
        if f not in flags:
            flags.append(f)
    # scripts + comments often hide flags
    for m in re.finditer(r"<!--(.*?)-->", r.text, re.S):
        known, cands = extract_flags(m.group(1))
        for f in known + cands:
            if f not in flags:
                flags.append(f)
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", r.text, re.S):
        known, cands = extract_flags(m.group(1))
        for f in known + cands:
            if f not in flags:
                flags.append(f)
    # base64-looking strings on the page
    for m in re.finditer(r"[A-Za-z0-9+/=]{40,}", r.text):
        try:
            import base64
            raw = base64.b64decode(m.group(0), validate=True)
            known, cands = extract_flags(raw.decode("latin-1", "replace"))
            for f in known + cands:
                if f not in flags:
                    flags.append(f)
        except Exception:
            pass
    return flags


def run_recon(base):
    """Full recon pass. Returns list of discovered paths + flags."""
    print()
    print("── Recon ──")
    resp, _ = scan_headers(base + "/")
    paths = []
    flags = []
    rob_paths, rob_text = scan_robots(base)
    paths.extend(rob_paths)
    if rob_text:
        known, cands = extract_flags(rob_text)
        flags.extend(known + cands)
    urls = scan_sitemap(base)
    for u in urls:
        paths.append(u.replace(base, "").lstrip("/"))
    sec = scan_security_txt(base)
    if sec:
        known, cands = extract_flags(sec)
        flags.extend(known + cands)
    http_methods(base + "/")
    cms_hints(base)
    home_flags = scan_homepage(base)
    flags.extend(home_flags)
    return list(dict.fromkeys(p for p in paths if p)), list(dict.fromkeys(flags))
