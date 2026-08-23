"""Bounded recursive Web discovery for authorized CTF targets.

The existing scanner is good at known attack families. This module improves
coverage before those attacks run by finding routes hidden behind links,
forms, JavaScript, source maps and OpenAPI/Swagger documents.
"""
import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser

from core import httpx
from core.flag import extract_flags

MAX_BODY = 1_500_000
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
                 ".css", ".woff", ".woff2", ".ttf")
COMMON_DISCOVERY_PATHS = (
    "/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs",
    "/v3/api-docs", "/swagger/v1/swagger.json", "/swagger/index.html",
    "/redoc", "/graphql", "/graphiql", "/api/schema", "/api/docs",
    "/.well-known/openapi.json", "/actuator/mappings",
)
SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|client[_-]?secret|secret|token|password|passwd|"
    r"authorization|private[_-]?key)\s*[:=]\s*[\"']([^\"'\s]{6,180})[\"']")
JS_URL_RE = re.compile(
    r"[\"'`]((?:https?://[^\"'`\s]+|/[A-Za-z0-9_./?=&%:#-]{2,180}))[\"'`]")
JSON_PATH_RE = re.compile(r"(?i)^/(?:api|graphql|swagger|openapi|v[0-9])")


class _HTMLLinks(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.forms = []
        self.scripts = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        values = {str(key).lower(): str(value or "") for key, value in attrs}
        if tag in ("a", "link", "iframe", "frame") and values.get("href"):
            self.links.append(values["href"])
        if tag in ("img", "script") and values.get("src"):
            self.links.append(values["src"])
            if tag == "script":
                self.scripts.append(values["src"])
        if tag == "form":
            self._form = {"action": values.get("action", ""),
                          "method": values.get("method", "GET").upper(),
                          "fields": []}
        if self._form is not None and tag in ("input", "textarea", "select"):
            if values.get("name"):
                self._form["fields"].append(values["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _origin(base):
    parsed = urllib.parse.urlparse(base)
    return parsed.scheme, parsed.netloc


def _to_url(base, value):
    value = (value or "").strip()
    if not value or value.startswith(("#", "javascript:", "data:",
                                     "mailto:", "tel:", "ws:", "wss:")):
        return None
    url = urllib.parse.urljoin(base, value)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or (parsed.scheme, parsed.netloc) != _origin(base):
        return None
    clean = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/",
                                     "", parsed.query, ""))
    lowered_path = parsed.path.lower()
    if any(token in lowered_path.split("/") for token in
           ("logout", "signout", "delete", "remove", "unsubscribe")):
        return None
    if clean.lower().split("?", 1)[0].endswith(SKIP_SUFFIXES):
        return None
    return clean


def _path(url):
    parsed = urllib.parse.urlparse(url)
    value = parsed.path.lstrip("/")
    return value + (("?" + parsed.query) if parsed.query else "")


def _find_json_paths(value):
    found = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and key.startswith("/"):
                found.add(key)
            found.update(_find_json_paths(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_find_json_paths(child))
    elif isinstance(value, str) and value.startswith("/") and JSON_PATH_RE.search(value):
        found.add(value)
    return found


def _find_api_operations(value):
    """Return useful HTTP operations from OpenAPI-like JSON documents."""
    methods = {"get", "post", "put", "patch", "delete", "head", "options"}
    found = []
    if not isinstance(value, dict):
        return found
    paths_obj = value.get("paths")
    if not isinstance(paths_obj, dict):
        return found
    for route, operations in paths_obj.items():
        if not isinstance(route, str) or not route.startswith("/"):
            continue
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            method_lower = str(method).lower()
            if method_lower not in methods:
                continue
            summary = ""
            if isinstance(operation, dict):
                summary = operation.get("operationId") or operation.get("summary") or ""
            found.append((method_lower.upper(), route, str(summary).strip()))
    return found


def _extract_urls(base, body, content_type):
    links = set()
    parser = _HTMLLinks()
    if "html" in content_type or "xml" in content_type or not content_type:
        try:
            parser.feed(body)
            links.update(parser.links)
        except Exception:
            pass
    for match in JS_URL_RE.finditer(body):
        links.add(match.group(1))
    try:
        value = json.loads(body)
        links.update(_find_json_paths(value))
    except (TypeError, ValueError):
        pass
    urls = {_to_url(base, value) for value in links}
    return {value for value in urls if value}, parser


def _scan_response(base, url, response):
    body = response.text[:MAX_BODY] if response is not None else ""
    findings, flags, links, paths = [], [], set(), set()
    if response is None:
        return findings, flags, links, paths, None
    known, candidates = extract_flags(body)
    flags.extend(known + candidates)
    content_type = response.headers.get("content-type", "").lower()
    links, parser = _extract_urls(base, body, content_type)
    paths.update(_path(item) for item in links)
    for form in parser.forms:
        action = _to_url(url, form.get("action") or url)
        if action:
            paths.add(_path(action))
            findings.append(f"  [i] form {form['method']} {action} fields={','.join(form['fields']) or '-'}")
    for source in parser.scripts:
        script_url = _to_url(url, source)
        if script_url:
            links.add(script_url)
            parsed_script = urllib.parse.urlparse(script_url)
            map_url = urllib.parse.urlunparse(
                (parsed_script.scheme, parsed_script.netloc,
                 parsed_script.path + ".map", "", parsed_script.query, ""))
            links.add(map_url)
            paths.add(_path(script_url))
            paths.add(_path(map_url))
    try:
        value = json.loads(body)
        for method, route, summary in _find_api_operations(value):
            paths.add(route.lstrip("/"))
            suffix = f" ({summary})" if summary else ""
            findings.append(f"  [i] API operation {method} {route}{suffix}")
    except (TypeError, ValueError):
        pass
    for match in SECRET_RE.finditer(body):
        key, value = match.group(1), match.group(2)
        if value.lower() not in {key.lower(), "changeme", "xxxxxxxx"}:
            findings.append(f"  [!] passive secret candidate at {url}: {key}={value[:48]}")
    if any(word in body.lower() for word in ("swagger", "openapi", "__schema", "graphql")):
        findings.append(f"  [i] API/schema hint discovered at {url}")
    return findings, flags, links, paths, parser


def crawl(base, seed_urls=None, max_pages=36, max_depth=2, workers=12):
    """Crawl same-origin pages and return findings, flags and useful paths."""
    base = base.rstrip("/")
    default_seeds = seed_urls is None
    seed_values = [base + "/"] if default_seeds else seed_urls
    queue = []
    fallback_queue = []
    for value in seed_values:
        item = _to_url(base + "/", value)
        if item and item not in {url for url, _ in queue}:
            queue.append((item, 0))
    if default_seeds:
        for value in COMMON_DISCOVERY_PATHS:
            item = _to_url(base + "/", value)
            if item:
                fallback_queue.append((item, 1))
    visited, findings, flags, paths = set(), [], [], set()
    pages = []

    while (queue or fallback_queue) and len(visited) < max_pages:
        if not queue:
            queue, fallback_queue = fallback_queue, []
        current = []
        while queue and len(current) < min(workers, max_pages - len(visited)):
            url, depth = queue.pop(0)
            if url not in visited:
                visited.add(url)
                current.append((url, depth))
        if not current:
            break

        def fetch(item):
            url, depth = item
            return item, httpx.get(url, timeout=8)

        with ThreadPoolExecutor(max_workers=min(workers, len(current))) as pool:
            responses = list(pool.map(fetch, current))
        for (url, depth), response in responses:
            if response is None:
                continue
            pages.append(url)
            local_findings, local_flags, links, local_paths, _ = _scan_response(
                base, url, response)
            findings.extend(local_findings)
            flags.extend(local_flags)
            paths.update(local_paths)
            if depth < max_depth:
                for link in sorted(links):
                    if link not in visited and len(visited) + len(queue) < max_pages:
                        queue.append((link, depth + 1))

    return (list(dict.fromkeys(findings)), list(dict.fromkeys(flags)),
            sorted(paths), pages)
