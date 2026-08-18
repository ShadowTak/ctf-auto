"""Asset & JS crawling: follow scripts/styles/links, extract flags,
endpoints and hardcoded secrets from page source and JavaScript."""
import re
import urllib.parse

from core import httpx
from core.flag import extract_flags
from core.notfound import calibrator_for
from core.parallel import pmap

SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|pwd|auth[_-]?key|"
    r"access[_-]?key|private[_-]?key|session[_-]?id|client[_-]?secret)"
    r"\s*[:=]\s*[\"']([^\"'\s]{6,120})[\"']"
)
ENDPOINT_RE = re.compile(r"[\"'](/[a-zA-Z0-9_\-./?=&%]{3,120})[\"']")
URL_RE = re.compile(r"(?i)https?://[a-zA-Z0-9.\-:/_?=&%#]{5,200}")
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)


def _collect_links(base, html):
    """Gather same-origin asset + navigation links from an HTML page."""
    out = set()
    parsed = urllib.parse.urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for m in re.finditer(r'(?:src|href)=["\']([^"\']+)["\']', html):
        u = m.group(1).strip()
        if not u or u.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
            continue
        if u.startswith("//"):
            u = parsed.scheme + ":" + u
        if u.startswith(("http://", "https://")):
            if urllib.parse.urlparse(u).netloc == parsed.netloc:
                out.add(u)
        elif u.startswith("/"):
            out.add(origin + u)
        else:
            out.add(origin + "/" + u)
    return out


def _scan_one(base, url, findings, flags, extra_paths):
    r = httpx.get(url, timeout=8)
    if r is None:
        return
    if calibrator_for(base).is_missing(r):
        return  # soft-404 skeleton — nothing of value here
    body = r.text
    known, cands = extract_flags(body)
    for f in known + cands:
        if f not in flags:
            flags.append(f)
    # hardcoded secrets in JS
    for m in SECRET_RE.finditer(body):
        kind, val = m.group(1).lower(), m.group(2)
        if val not in (kind, "changeme", "xxxxx"):
            findings.append(f"  [!] secret ใน {url}: {m.group(1)} = {val[:40]}")
    # endpoints discovered in JS (relative paths)
    for m in ENDPOINT_RE.finditer(body):
        p = m.group(1)
        if p.startswith("/") and not p.startswith("//") and "." not in p.split("/")[-1]:
            clean = p.lstrip("/").split("?")[0]
            if clean and len(clean) < 80:
                extra_paths.add(clean)
    # full URLs
    for m in URL_RE.finditer(body):
        u = m.group(0)
        if "flag" in u.lower() or "secret" in u.lower() or "api" in u.lower():
            findings.append(f"  [i] URL ใน JS: {u[:100]}")


def scan_assets(base, page_html, max_urls=60, workers=24):
    """Crawl same-origin assets; returns (findings, flags, extra_paths)."""
    links = _collect_links(base, page_html)
    links = sorted(links)[:max_urls]
    findings = []
    flags = []
    extra_paths = set()

    def do(url):
        _scan_one(base, url, findings, flags, extra_paths)

    for _ in pmap(do, links, workers=workers, desc="asset crawl"):
        pass
    return findings, list(dict.fromkeys(flags)), sorted(extra_paths)


def scan_js_blob(url, body):
    """Direct JS scan (for script URLs found by dirbust)."""
    findings = []
    flags = []
    known, cands = extract_flags(body)
    flags.extend(known + cands)
    for m in SECRET_RE.finditer(body):
        findings.append(f"  [!] secret ใน {url}: {m.group(1)} = {m.group(2)[:40]}")
    return findings, flags
