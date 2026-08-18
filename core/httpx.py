"""Fast stdlib HTTP client with a per-thread keep-alive connection pool.
Reusing connections makes dirbusting/fuzzing several times faster than
opening a fresh TCP+TLS handshake per request (the old urllib approach)."""
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
        key = (scheme, host, port)
        conn = conns.get(key)
        if conn is None:
            if scheme == "https":
                conn = http.client.HTTPSConnection(
                    host, port, timeout=self.timeout, context=_CTX)
            else:
                conn = http.client.HTTPConnection(
                    host, port, timeout=self.timeout)
            conns[key] = conn
        return conn

    def evict(self, scheme, host, port):
        conn = self._conns().pop((scheme, host, port), None)
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

    hdrs = dict(headers or {})
    hdrs.setdefault("User-Agent", UA)
    hdrs.setdefault("Accept", "*/*")
    hdrs.setdefault("Accept-Encoding", "gzip, deflate")
    hdrs.setdefault("Connection", "keep-alive")

    conn = _POOL.get(scheme, host, port)
    # stale keep-alive connections (server closed, proxy RST, half-open) are
    # common under burst load — evict and retry with a fresh connection a few
    # times before giving up
    for attempt in range(3):
        try:
            conn.request(method, path, body=data, headers=hdrs)
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
                current = urllib.parse.urljoin(current, loc)
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
