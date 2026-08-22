"""Fast stdlib HTTP client with a per-thread keep-alive connection pool.
Reusing connections makes dirbusting/fuzzing several times faster than
opening a fresh TCP+TLS handshake per request (the old urllib approach).

Also supports competition-quality session controls: global headers /
cookies applied to every request (for authenticated targets) and an HTTP
proxy (absolute-URI form for http, CONNECT tunnel for https).
"""
import gzip
import http.client
import re
import socket
import ssl
import threading
import time
import urllib.parse
import zlib

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
)

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

_TIMEOUT = 10
_MAX_REDIRECTS = 5

# Session-wide settings configured via configure() / run.py CLI flags
_GLOBAL_HEADERS = {}
_PROXY_URL = None


def configure(headers=None, cookie=None, proxy=None, timeout=None,
              user_agent=None):
    """Set session-wide defaults used by every request.

    headers : dict merged under per-call headers
    cookie  : "k1=v1; k2=v2" shorthand for the Cookie header
    proxy   : "http://127.0.0.1:8080" (http via absolute-URI, https via
              CONNECT tunnel)
    timeout : default per-request timeout
    """
    global _PROXY_URL
    if user_agent:
        _GLOBAL_HEADERS["User-Agent"] = user_agent
    if headers:
        _GLOBAL_HEADERS.update({str(k): str(v) for k, v in headers.items()})
    if cookie:
        _GLOBAL_HEADERS["Cookie"] = cookie.strip()
    if timeout:
        global _TIMEOUT
        _TIMEOUT = max(1, int(timeout))
        _POOL.timeout = _TIMEOUT
    if proxy:
        proxy = proxy.strip()
        if not re.match(r"^https?://", proxy, re.I):
            proxy = "http://" + proxy
        _PROXY_URL = proxy
    elif proxy is not None:  # explicit empty string clears it
        _PROXY_URL = None


def reset_session():
    """Clear cookies/headers/proxy (used between scans)."""
    global _PROXY_URL
    _GLOBAL_HEADERS.clear()
    _PROXY_URL = None


def _proxy_parts():
    if not _PROXY_URL:
        return None
    p = urllib.parse.urlparse(_PROXY_URL)
    return p.hostname, p.port or 80


class Resp:
    __slots__ = ("status", "headers", "body", "url", "reason")

    def __init__(self, status, headers, body, url, reason=""):
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.url = url
        self.reason = reason

    @property
    def text(self):
        try:
            return self.body.decode("utf-8", "replace")
        except Exception:
            return ""


class _ConnPool:
    """Keep-alive connections per thread, keyed by (scheme, host, port)."""

    def __init__(self, timeout=10):
        self.timeout = timeout
        self._local = threading.local()

    def _conns(self):
        conns = getattr(self._local, "conns", None)
        if conns is None:
            conns = self._local.conns = {}
        return conns

    def get(self, scheme, host, port):
        conns = self._conns()
        proxy = _proxy_parts()
        key = (scheme, host, port, bool(proxy))
        conn = conns.get(key)
        if conn is None:
            if proxy:
                phost, pport = proxy
                if scheme == "https":
                    conn = http.client.HTTPSConnection(
                        phost, pport, timeout=self.timeout, context=_CTX)
                    conn.set_tunnel(host, port)
                else:
                    conn = http.client.HTTPConnection(
                        phost, pport, timeout=self.timeout)
            elif scheme == "https":
                conn = http.client.HTTPSConnection(
                    host, port, timeout=self.timeout, context=_CTX)
            else:
                conn = http.client.HTTPConnection(
                    host, port, timeout=self.timeout)
            conns[key] = conn
        return conn

    def evict(self, scheme, host, port):
        proxy = _proxy_parts()
        key = (scheme, host, port, bool(proxy))
        conn = self._conns().pop(key, None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


_POOL = _ConnPool(_TIMEOUT)


def close_pool():
    """Close all pooled connections (call at end of a long scan)."""
    try:
        _POOL.close()
    except Exception:
        pass


def _decompress(body, resp_headers):
    enc = resp_headers.get("content-encoding", "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            return zlib.decompress(body)
        if "br" in enc:
            return body  # brotli not in stdlib; keep raw
    except Exception:
        pass
    return body


def _request_once(method, url, data=None, headers=None, timeout=10):
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower() or "http"
    host = parsed.hostname or ""
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    proxy = _proxy_parts()
    # through a plain-HTTP proxy the request-target is the absolute URI
    request_target = f"{scheme}://{host}:{port}{path}" if (
        proxy and scheme == "http") else path

    hdrs = dict(_GLOBAL_HEADERS)
    hdrs.update({str(k): str(v) for k, v in (headers or {}).items()})
    hdrs.setdefault("User-Agent", UA)
    hdrs.setdefault("Accept", "*/*")
    hdrs.setdefault("Accept-Encoding", "gzip, deflate")
    hdrs.setdefault("Connection", "keep-alive")
    if proxy and "Host" not in {k.lower() for k in hdrs}:
        hdrs["Host"] = host

    conn = _POOL.get(scheme, host, port)
    # stale keep-alive connections (server closed, proxy RST, half-open) are
    # common under burst load — evict and retry with a fresh connection a few
    # times before giving up
    for attempt in range(3):
        try:
            conn.request(method, request_target, body=data, headers=hdrs)
            resp = conn.getresponse()
            body = resp.read()
            r_headers = {k.lower(): v for k, v in resp.getheaders()}
            body = _decompress(body, r_headers)
            return Resp(resp.status, r_headers, body, url, reason=resp.reason)
        except (http.client.HTTPException, OSError, socket.timeout,
                ssl.SSLError, ValueError):
            _POOL.evict(scheme, host, port)
            if attempt < 2:
                conn = _POOL.get(scheme, host, port)
                time.sleep(0.05 * (attempt + 1))
    return None


def request(method, url, data=None, headers=None, timeout=10,
            allow_redirects=True, raw=False):
    """Generic request with optional redirect following. Returns Resp/None."""
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
        elif isinstance(data, str):
            body = data.encode()
        else:
            body = bytes(data)
    current = url
    for _ in range(_MAX_REDIRECTS + 1):
        r = _request_once(method, current, data=body, headers=headers,
                          timeout=timeout)
        if r is None:
            return None
        if not allow_redirects:
            return r
        if r.status in (301, 302, 303, 307, 308):
            loc = r.headers.get("location")
            if loc:
                nxt = urllib.parse.urljoin(current, loc)
                # redirect loop (302 -> same path) — return what we have
                # instead of exhausting _MAX_REDIRECTS and reporting None
                if nxt == current:
                    return r
                current = nxt
                if r.status == 303 and method.upper() != "GET":
                    method = "GET"
                    body = None
                continue
        return r
    return None


def get(url, **kw):
    return request("GET", url, **kw)


def post(url, data=None, **kw):
    return request("POST", url, data=data, **kw)


def normalize_url(u):
    u = u.strip()
    if not u:
        return u
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    return u


def host_of(url):
    return urllib.parse.urlparse(url).hostname or url


def port_of(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.port or (443 if parsed.scheme == "https" else 80)


def try_http(host, port=None, timeout=5):
    """Try http(s) against host[:port]; return first working Resp or None."""
    if port is None:
        for scheme, p in (("http", 80), ("https", 443)):
            r = get(f"{scheme}://{host}:{p}/", timeout=timeout)
            if r is not None and r.status < 500:
                return r
        return None
    for scheme in ("http", "https"):
        r = get(f"{scheme}://{host}:{port}/", timeout=timeout)
        if r is not None and r.status < 500:
            return r
    return None


def is_up(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
