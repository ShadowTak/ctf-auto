"""Optional read-only Playwright pass for JavaScript-rendered CTF pages."""
import urllib.parse

from core.flag import extract_flags


def _same_origin(base, value):
    url = urllib.parse.urljoin(base, value or "")
    a, b = urllib.parse.urlparse(base), urllib.parse.urlparse(url)
    if (a.scheme, a.netloc) != (b.scheme, b.netloc):
        return None
    if b.scheme not in ("http", "https"):
        return None
    if any(token in b.path.lower().split("/")
           for token in ("logout", "signout", "delete", "remove", "unsubscribe")):
        return None
    return urllib.parse.urlunparse((b.scheme, b.netloc, b.path or "/", "", b.query, ""))


def _network_route_is_interesting(url, resource_type):
    """Keep API-like XHR/fetch routes without depending on `/api/` naming."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()
    query = parsed.query.lower()
    if any(path.endswith(ext) for ext in (
            ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif",
            ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf")):
        return False
    if resource_type in {"xhr", "fetch"}:
        return True
    markers = ("/api", "/graphql", "/graphiql", "/rpc", "/query",
               "/search", "/data", "/json", "/v1/", "/v2/", "/v3/",
               "openapi", "swagger", "schema", "flag")
    return (any(marker in path for marker in markers)
            or path.endswith((".json", ".xml"))
            or any(marker in query for marker in ("api", "query", "json")))


def _route_path(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.path.lstrip("/") + (("?" + parsed.query) if parsed.query else "")


def crawl_dynamic(base, max_pages=12, timeout_ms=12000):
    """Render same-origin pages and collect routes/network resources.

    No forms are submitted and no clicks are performed. This pass exists to
    reveal SPA routes and API calls that static HTML crawling cannot see.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return [], [], [], "Playwright not installed"
    findings, flags, paths, queue, visited = [], [], [], [base.rstrip("/") + "/"], set()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)
            requests = set()
            page.on("request", lambda request: requests.add(
                (request.url, request.resource_type)))
            while queue and len(visited) < max_pages:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                    page.wait_for_timeout(250)
                    body = page.content()
                except Exception as exc:
                    findings.append(f"  [i] browser {url}: {str(exc)[:100]}")
                    continue
                known, candidates = extract_flags(body)
                flags.extend(known + candidates)
                values = page.eval_on_selector_all(
                    "a[href],script[src],link[href],iframe[src],form[action]",
                    "els => els.map(e => e.href || e.src || e.action).filter(Boolean)")
                for value in values:
                    clean = _same_origin(base, value)
                    if clean:
                        paths.append(urllib.parse.urlparse(clean).path.lstrip("/")
                                     + (("?" + urllib.parse.urlparse(clean).query)
                                        if urllib.parse.urlparse(clean).query else ""))
                        if clean not in visited and len(visited) + len(queue) < max_pages:
                            queue.append(clean)
            for value, resource_type in requests:
                clean = _same_origin(base, value)
                if clean and _network_route_is_interesting(clean, resource_type):
                    findings.append(f"  [i] browser network route ({resource_type}): {clean[:180]}")
                    paths.append(_route_path(clean))
            browser.close()
    except Exception as exc:
        return findings, list(dict.fromkeys(flags)), sorted(set(paths)), str(exc)
    return findings, list(dict.fromkeys(flags)), sorted(set(paths)), None
