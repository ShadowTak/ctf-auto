"""AES-CTR bit-flip attack, auto-detected.

Stream ciphers (CTR mode) reuse the keystream for every block: flipping a
ciphertext bit flips the same plaintext bit. A notes service that encrypts
your data inside a fixed template and only reveals the flag when the
decrypted text contains ';admin=true;' is broken by:

  1. POST /encrypt {data} -> ciphertext hex
  2. POST /decrypt {ciphertext} -> echoes the *plaintext* -> keystream known
  3. craft ciphertext2 = (plaintext2 XOR keystream) where plaintext2 has
     ;admin=true; replacing our own data
  4. POST /decrypt ciphertext2 -> admin -> flag

Detection is generic: any JSON API with POST encrypt + POST decrypt
endpoints (found via dirbust or the homepage). Returns (findings, flags).
"""
import json

from core import httpx
from core.flag import extract_flags

MARKER = b";admin=true;"


def _json(r):
    if r is None:
        return {}
    try:
        return json.loads(r.text)
    except Exception:
        return {}


def _post_json(url, payload, timeout=8):
    r = httpx.post(url, data=json.dumps(payload),
                   headers={"Content-Type": "application/json"}, timeout=timeout)
    return r


def _find_endpoints(base, endpoints):
    """Pick candidate encrypt/decrypt endpoint URLs. Keeps the FIRST match
    per kind (dirbust can list both /encrypt and /api/encrypt — prefer the
    simpler path and never let a later entry overwrite an earlier one)."""
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


def _try_attack(base, enc_url, dec_url, probe="A" * 32):
    """Return (finding, flag) or (None, None)."""
    r = _post_json(enc_url, {"data": probe})
    if r is None or r.status != 200:
        return None, None
    try:
        ct = bytes.fromhex(_json(r).get("ciphertext", ""))
    except Exception:
        return None, None
    if not ct:
        return None, None

    # learn the exact plaintext from the decrypt echo
    r2 = _post_json(dec_url, {"ciphertext": ct.hex()})
    if r2 is None or r2.status != 200:
        return None, None
    pt = _json(r2).get("plaintext", "")
    if not pt or len(pt) != len(ct):
        return None, None
    try:
        pt = pt.encode("utf-8") if isinstance(pt, str) else bytes(pt)
    except Exception:
        return None, None

    # where does our probe data sit in the plaintext?
    idx = pt.find(probe.encode())
    if idx < 0:
        return None, None

    # craft a new plaintext: replace our data with marker + padding
    pad = b"x" * (len(probe) - len(MARKER))
    new_pt = pt[:idx] + MARKER + pad + pt[idx + len(probe):]
    if len(new_pt) != len(pt):
        return None, None

    # keystream = ct XOR pt ; ciphertext2 = new_pt XOR keystream
    ks = bytes(a ^ b for a, b in zip(ct, pt))
    ct2 = bytes(a ^ b for a, b in zip(new_pt, ks))

    r3 = _post_json(dec_url, {"ciphertext": ct2.hex()})
    if r3 is None:
        return None, None
    known, cands = extract_flags(r3.text)
    flags = known + cands
    is_admin = bool(_json(r3).get("admin")) or "admin" in r3.text.lower()
    if is_admin or flags:
        finding = (f"AES-CTR bit-flip สำเร็จ: {enc_url} -> forged ciphertext "
                   f"({ct2.hex()[:32]}...) ทำให้ decrypt ได้ ';admin=true;'")
        return finding, flags
    return None, None


def scan_ctr_bitflip(base, endpoints):
    """Auto-detect and exploit AES-CTR bit-flip services."""
    if not endpoints:
        endpoints = [base + "/"]
    enc, dec = _find_endpoints(base, endpoints)
    if not (enc and dec):
        return [], []
    findings = []
    flags = []

    for probe in ("A" * 32, "B" * 32, "0123456789abcdef" * 2):
        f, fl = _try_attack(base, enc, dec, probe)
        if f:
            findings.append(f)
            flags.extend(fl)
            break
    return findings, list(dict.fromkeys(flags))
