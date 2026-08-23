"""Bounded AES-ECB oracle workflows used by common CTF web labs.

The generic web scanner can discover an endpoint, but ECB challenges need a
stateful request sequence.  This module supports two high-signal patterns:

* byte-at-a-time recovery of ``unknown_prefix || attacker_input || secret``;
* profile/token cut-and-paste where a role field is aligned into a block.

Every path is probed conservatively and only a flag returned by the target is
reported.  The byte oracle uses printable flag bytes by default, keeping a
normal web scan bounded; callers can use ``recover_ecb_suffix`` directly with
an expanded alphabet for unusual binary secrets.
"""
import base64
import json
import string
import urllib.parse

from core import httpx
from core.flag import extract_flags


def _flags(response):
    if response is None:
        return []
    values = [response.text]
    try:
        obj = json.loads(response.text or "{}")
    except (TypeError, ValueError):
        obj = None
    if isinstance(obj, dict):
        values.extend(str(obj.get(key, "")) for key in ("flag", "secret", "token"))
    out = []
    for value in values:
        known, candidates = extract_flags(value)
        for item in known + candidates:
            if item not in out:
                out.append(item)
    return out


def _json_value(response, names=("ciphertext", "cipher", "ct", "token",
                                 "data", "encrypted", "result", "output",
                                 "value")):
    if response is None:
        return None
    try:
        obj = json.loads(response.text or "{}")
    except (TypeError, ValueError):
        obj = None
    wanted = {x.lower() for x in names}
    if isinstance(obj, dict):
        stack = [obj]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                for key, value in item.items():
                    if str(key).lower() in wanted:
                        if isinstance(value, str):
                            return value
                        if isinstance(value, (dict, list)):
                            stack.append(value)
                    elif isinstance(value, (dict, list)):
                        stack.append(value)
            elif isinstance(item, list):
                stack.extend(item)
    body = response.text.strip().strip('"')
    return body if body else None


def _decode_cipher(value):
    if not isinstance(value, str):
        return None
    raw = value.strip().strip('"')
    try:
        if len(raw) >= 32 and len(raw) % 2 == 0:
            data = bytes.fromhex(raw)
            if len(data) % 16 == 0:
                return data
    except ValueError:
        pass
    padded = raw + "=" * (-len(raw) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            data = decoder(padded, validate=True) if decoder is base64.b64decode \
                else decoder(padded)
            if len(data) % 16 == 0:
                return data
        except Exception:
            continue
    return None


def _post_json(url, body, timeout=8):
    return httpx.post(url, data=json.dumps(body),
                      headers={"Content-Type": "application/json"},
                      timeout=timeout)


def _encrypt_oracle(endpoint, payload, timeout=8):
    """Return ciphertext bytes for a JSON hex/data oracle, or ``None``."""
    response = _post_json(endpoint, {"hex": payload.hex()}, timeout=timeout)
    value = _json_value(response)
    data = _decode_cipher(value)
    if data is not None:
        return data
    # A few labs only expose the friendly ``data`` field.  Retry once with
    # printable bytes, but do not send binary guesses through that path.
    if all(32 <= byte < 127 for byte in payload):
        response = _post_json(endpoint, {"data": payload.decode()}, timeout=timeout)
        return _decode_cipher(_json_value(response))
    return None


def _block_repetitions(data, block):
    blocks = [data[i:i + block] for i in range(0, len(data), block)]
    return [index for index in range(len(blocks) - 1)
            if blocks[index] == blocks[index + 1]]


def recover_ecb_suffix(endpoint, *, max_bytes=128, alphabet=None, timeout=8):
    """Recover a printable unknown suffix from an ECB encryption oracle.

    Returns ``(plaintext_suffix, evidence_dict)`` or ``(None, None)``.  The
    prefix length/alignment is inferred from repeated blocks, so fixed random
    prefixes work without challenge-specific constants.
    """
    alphabet = alphabet or (string.ascii_letters + string.digits +
                            string.punctuation + " \t")
    baseline = _encrypt_oracle(endpoint, b"", timeout=timeout)
    if not baseline or len(baseline) < 32:
        return None, None

    # Infer the block size from the first ciphertext length increase.  CTF
    # AES oracles should increase by exactly one block.
    block = None
    for size in range(1, 65):
        current = _encrypt_oracle(endpoint, b"A" * size, timeout=timeout)
        if current and len(current) > len(baseline):
            delta = len(current) - len(baseline)
            if delta in (8, 16, 24, 32):
                block = delta
            break
    if block is None or block < 8:
        return None, None

    align_pad = None
    repeated_index = None
    marker = b"\x00" * block
    for pad in range(block):
        # Probe with a marker that cannot be confused with a repeated block
        # from the unknown prefix.  The actual request remains printable on
        # data-only endpoints, but the hex field is preferred by the oracle.
        marker_probe = _encrypt_oracle(endpoint,
                                       b"A" * pad + marker + marker,
                                       timeout=timeout)
        other_marker = b"\xff" * block
        other_probe = _encrypt_oracle(endpoint,
                                      b"A" * pad + other_marker + other_marker,
                                      timeout=timeout)
        if not marker_probe or not other_probe:
            continue
        first = _block_repetitions(marker_probe, block)
        second = set(_block_repetitions(other_probe, block))
        # A repeated block already present in the unknown prefix survives
        # both probes unchanged.  The attacker-controlled pair changes when
        # the marker changes, which disambiguates the alignment.
        candidates = [index for index in first if index in second]
        for index in candidates:
            left = marker_probe[index * block:(index + 1) * block]
            right = other_probe[index * block:(index + 1) * block]
            if left != right:
                align_pad, repeated_index = pad, index
                break
        if align_pad is not None:
            break
    if align_pad is None:
        return None, None

    # If prefix_len + align_pad reaches the repeated block, prefix_len is
    # known.  The ciphertext's padding threshold gives total unknown length.
    prefix_len = repeated_index * block - align_pad
    first_growth = None
    for size in range(1, block + 1):
        current = _encrypt_oracle(endpoint, b"A" * size, timeout=timeout)
        if current and len(current) > len(baseline):
            first_growth = size
            break
    if first_growth is None:
        return None, None
    suffix_len = max(0, len(baseline) - first_growth - prefix_len)
    suffix_len = min(suffix_len, max_bytes)

    recovered = bytearray()
    guesses = list(dict.fromkeys(alphabet.encode("latin-1", "ignore")))
    for position in range(suffix_len):
        extra = block - 1 - (position % block)
        target_input = b"A" * (align_pad + extra)
        target = _encrypt_oracle(endpoint, target_input, timeout=timeout)
        if target is None:
            break
        block_index = (prefix_len + align_pad + extra + position) // block
        target_block = target[block_index * block:(block_index + 1) * block]
        found = None
        for guess in guesses:
            # Keep the alignment bytes, then place the last block-sized known
            # window immediately before the guessed byte.
            candidate = (b"A" * (align_pad + extra) +
                         bytes(recovered) + bytes([guess]))
            probe = _encrypt_oracle(endpoint, candidate, timeout=timeout)
            if probe is None:
                continue
            if probe[block_index * block:(block_index + 1) * block] == target_block:
                found = guess
                break
        if found is None:
            break
        recovered.append(found)
        if recovered.endswith(b"}"):
            break
    if not recovered:
        return None, None
    return bytes(recovered), {
        "block_size": block,
        "prefix_length": prefix_len,
        "alignment": align_pad,
        "requests_bound": suffix_len * (len(guesses) + 2),
    }


def _token_from(response):
    return _decode_cipher(_json_value(response, ("token", "ciphertext", "ct")))


def exploit_cut_and_paste(base, register_path="/register", profile_path="/profile",
                          timeout=8):
    """Forge an ``admin`` role block in a profile token."""
    first_email = "A" * 10 + "admin" + ("\x0b" * 11)
    one = httpx.get(base + register_path + "?email=" +
                    urllib.parse.quote(first_email, safe=""), timeout=timeout)
    first = _token_from(one)
    if not first or len(first) < 32 or len(first) % 16:
        return [], None
    admin_block = first[16:32]
    two = httpx.get(base + register_path + "?email=attacker@example.com",
                    timeout=timeout)
    normal = _token_from(two)
    if not normal or len(normal) < 32:
        return [], None
    forged = (normal[:32] + admin_block).hex()
    result = httpx.get(base + profile_path + "?token=" + forged, timeout=timeout)
    flags = _flags(result)
    return flags, forged if flags else None


def scan_ecb_oracles(base, endpoints):
    """Discover and run bounded ECB oracle chains."""
    paths = []
    for endpoint in endpoints or ():
        parsed = urllib.parse.urlparse(str(endpoint))
        path = parsed.path.lower()
        if any(word in path for word in ("encrypt", "oracle", "register", "token")):
            paths.append(parsed.path or "/")
    paths.extend(("/encrypt", "/api/encrypt", "/oracle", "/api/oracle"))
    findings, flags = [], []
    for path in list(dict.fromkeys(paths))[:10]:
        endpoint = base.rstrip("/") + path
        recovered, evidence = recover_ecb_suffix(endpoint, max_bytes=96)
        if recovered:
            known, candidates = extract_flags(recovered.decode("latin-1", "replace"))
            if known or candidates:
                findings.append(f"  [!] AES-ECB byte oracle at {path} "
                                f"(block={evidence['block_size']}, "
                                f"prefix={evidence['prefix_length']})")
                flags.extend(known + candidates)
                break

    register = next((p for p in paths if "register" in p), "/register")
    profile = "/profile"
    cut_flags, forged = exploit_cut_and_paste(base, register, profile)
    if cut_flags:
        findings.append("  [!] AES-ECB cut-and-paste forged an admin profile")
        flags.extend(cut_flags)
    return findings, list(dict.fromkeys(flags))
