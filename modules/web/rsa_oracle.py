"""RSA parity-oracle recovery for textbook-RSA web challenges.

The service only needs to reveal whether the decrypted integer is even or
odd.  Multiplying the ciphertext by ``2**e`` repeatedly turns that one-bit
answer into a binary search over the plaintext interval.  This module keeps
the request budget bounded and accepts the JSON/HTML response shapes used by
common CTF labs.
"""
import base64
import json
import re
import urllib.parse
from fractions import Fraction

from core import httpx
from core.flag import extract_flags


_NAMES = {
    "n": ("n", "modulus", "rsa_n", "public_modulus"),
    "e": ("e", "exponent", "rsa_e", "public_exponent"),
    "c": ("c", "ciphertext", "cipher", "ct", "token"),
}


def _int_value(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    raw = value.strip().replace("_", "")
    if raw.startswith(("0x", "0X")):
        try:
            return int(raw, 16)
        except ValueError:
            return None
    if re.fullmatch(r"[0-9]+", raw):
        try:
            return int(raw, 10)
        except ValueError:
            return None
    if re.fullmatch(r"[0-9a-fA-F]{32,}", raw) and len(raw) % 2 == 0:
        try:
            return int.from_bytes(bytes.fromhex(raw), "big")
        except ValueError:
            return None
    try:
        decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        return int.from_bytes(decoded, "big") if decoded else None
    except Exception:
        return None


def _walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _params_from_response(response):
    """Extract n/e/c from nested JSON or simple ``n=...`` HTML text."""
    if response is None:
        return {}
    body = response.text or ""
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError):
        parsed = None
    if parsed is not None:
        for mapping in _walk(parsed):
            lowered = {str(k).lower(): v for k, v in mapping.items()}
            values = {}
            for target, names in _NAMES.items():
                for name in names:
                    if name.lower() in lowered:
                        values[target] = _int_value(lowered[name.lower()])
                        break
            if all(values.get(key) is not None for key in ("n", "e", "c")):
                return values
    values = {}
    for target, names in _NAMES.items():
        joined = "|".join(re.escape(name) for name in names)
        match = re.search(rf"(?i)(?:{joined})\s*[=:]\s*"
                          r"([0-9a-fxA-FX]+)", body)
        if match:
            values[target] = _int_value(match.group(1))
    return values


def _parity_from_response(response):
    """Return 0/1 for explicit parity/even/odd response fields."""
    if response is None:
        return None
    body = response.text or ""
    try:
        parsed = json.loads(body)
    except (TypeError, ValueError):
        parsed = None
    if parsed is not None:
        for mapping in _walk(parsed):
            for key, value in mapping.items():
                low = str(key).lower()
                if low in {"parity", "lsb", "least_significant_bit"}:
                    if isinstance(value, bool):
                        return int(value)
                    if str(value).strip() in ("0", "1"):
                        return int(str(value).strip())
                if low in {"even", "is_even"} and isinstance(value, bool):
                    return 0 if value else 1
                if low in {"odd", "is_odd"} and isinstance(value, bool):
                    return 1 if value else 0
    low = body.strip().lower()
    if re.fullmatch(r"(?:parity\s*[:=]\s*)?[01]", low):
        return int(low[-1])
    if re.search(r"\b(?:is\s+)?even\b", low):
        return 0
    if re.search(r"\b(?:is\s+)?odd\b", low):
        return 1
    return None


def recover_parity_oracle(n, e, ciphertext, oracle, max_queries=None):
    """Recover an unpadded RSA plaintext using a parity callback.

    ``oracle(integer_ciphertext)`` must return 0 for an even plaintext and 1
    for an odd plaintext.  The returned bytes are verified against the
    original RSA equation before being accepted.
    """
    n, e, ciphertext = map(int, (n, e, ciphertext))
    if n <= 3 or e <= 1 or not 0 <= ciphertext < n:
        return None, {"queries": 0}
    limit = int(max_queries or (n.bit_length() + 8))
    low, high = Fraction(0), Fraction(n)
    multiplier = pow(2, e, n)
    current = ciphertext
    queries = 0
    for _ in range(limit):
        current = (current * multiplier) % n
        parity = oracle(current)
        queries += 1
        if parity not in (0, 1):
            return None, {"queries": queries, "error": "oracle did not return parity"}
        middle = (low + high) / 2
        if parity == 0:
            high = middle
        else:
            low = middle
        if high - low < Fraction(1, n * 2):
            break
    # Try the narrowed interval and a few adjacent integers to absorb the
    # final Fraction rounding at the boundary.
    candidates = set()
    for bound in (low, high, (low + high) / 2):
        value = int(bound)
        candidates.update(range(max(0, value - 2), min(n, value + 3)))
    for value in sorted(candidates):
        if pow(value, e, n) == ciphertext:
            length = max(1, (value.bit_length() + 7) // 8)
            return value.to_bytes(length, "big"), {
                "queries": queries,
                "bits": n.bit_length(),
            }
    return None, {"queries": queries, "bits": n.bit_length(),
                  "error": "interval did not verify"}


def _post_json(url, payload):
    return httpx.post(url, data=json.dumps(payload),
                      headers={"Content-Type": "application/json"},
                      timeout=6)


def _request_oracle(endpoint, ciphertext):
    """Try common request encodings and return a classified parity bit."""
    decimal = str(int(ciphertext))
    hexadecimal = format(int(ciphertext), "x")
    variants = (
        ("post-ciphertext", lambda: _post_json(endpoint, {"ciphertext": decimal})),
        ("post-c", lambda: _post_json(endpoint, {"c": decimal})),
        ("post-ct", lambda: _post_json(endpoint, {"ct": decimal})),
        ("post-token", lambda: _post_json(endpoint, {"token": decimal})),
        ("post-hex-field", lambda: _post_json(endpoint, {"hex": hexadecimal})),
        ("post-hex", lambda: _post_json(endpoint, {"ciphertext": "0x" + hexadecimal})),
    )
    for _, request in variants:
        response = request()
        parity = _parity_from_response(response)
        if parity is not None:
            return parity
    parsed = urllib.parse.urlsplit(endpoint)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    for key in ("ciphertext", "c", "ct", "token"):
        params = [(name, value) for name, value in query if name != key]
        params.append((key, decimal))
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc,
                                       parsed.path, urllib.parse.urlencode(params),
                                       parsed.fragment))
        parity = _parity_from_response(httpx.get(url, timeout=6))
        if parity is not None:
            return parity
    return None


def scan_rsa_parity_oracles(base, endpoints):
    """Discover and run bounded RSA parity-oracle workflows."""
    paths = []
    for endpoint in endpoints or ():
        parsed = urllib.parse.urlparse(str(endpoint))
        path = parsed.path or "/"
        if any(word in path.lower() for word in
               ("decrypt", "rsa", "oracle", "parity")):
            paths.append(path)
    paths.extend(("/decrypt", "/rsa/decrypt", "/oracle", "/api/decrypt"))
    findings, flags = [], []
    for path in list(dict.fromkeys(paths))[:6]:
        endpoint = base.rstrip("/") + path
        params = _params_from_response(httpx.get(endpoint, timeout=6))
        n, e, ciphertext = (params.get(key) for key in ("n", "e", "c"))
        if not n or not e or ciphertext is None or not (128 <= n.bit_length() <= 4096):
            continue
        probe = _request_oracle(endpoint, ciphertext)
        if probe not in (0, 1):
            continue

        def oracle(value):
            return _request_oracle(endpoint, value)

        plaintext, evidence = recover_parity_oracle(n, e, ciphertext, oracle)
        if not plaintext:
            continue
        text = plaintext.decode("latin-1", "replace")
        known, candidates = extract_flags(text)
        if known or candidates:
            findings.append(f"  [!] RSA parity oracle at {path} "
                            f"({evidence.get('queries', '?')} queries)")
            flags.extend(known + candidates)
            break
    return findings, list(dict.fromkeys(flags))
