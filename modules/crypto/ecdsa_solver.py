"""ECDSA signature analysis and attack solvers.

Handles nonce reuse, partial nonce recovery via lattice, signature malleability,
and cross-file signature correlation for CTF challenges.
"""
import hashlib
import math
import re

from .common import invmod

# ---------------------------------------------------------------------------
# Common elliptic curves (small CTF-friendly sizes)
# ---------------------------------------------------------------------------

CURVES = {
    "secp256k1": {
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        "a": 0, "b": 7,
        "Gx": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        "Gy": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    },
    "secp256r1": {
        "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        "Gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        "Gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    },
    "secp192r1": {
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF,
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831,
        "a": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF,
        "b": 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1,
        "Gx": 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
        "Gy": 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811,
    },
}


def parse_der_signature(data):
    """Parse a DER-encoded ECDSA signature into (r, s)."""
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data.lstrip("0x"))
        except ValueError:
            return None, None

    if len(data) < 6:
        return None, None

    idx = 0
    if data[idx] != 0x30:
        return None, None
    idx += 1

    # Read SEQUENCE length (DER length encoding)
    seq_len = data[idx]
    idx += 1
    if seq_len & 0x80:
        num_bytes = seq_len & 0x7F
        seq_len = int.from_bytes(data[idx:idx + num_bytes], "big")
        idx += num_bytes

    def read_int():
        nonlocal idx
        if idx >= len(data):
            return None
        if data[idx] != 0x02:
            return None
        idx += 1
        length = data[idx]
        idx += 1
        val = int.from_bytes(data[idx:idx + length], "big")
        idx += length
        return val

    r = read_int()
    s = read_int()
    return r, s


def parse_pem_signatures(text):
    """Extract ECDSA signatures from PEM-encoded data."""
    results = []
    for m in re.finditer(
        r"-----BEGIN ([A-Z ]*SIGNATURE[A-Z ]*)-----([A-Za-z0-9+/=\s]+)-----END \1-----",
        text,
    ):
        import base64
        body = "".join(m.group(2).split())
        raw = base64.b64decode(body)
        r, s = parse_der_signature(raw)
        if r is not None:
            results.append({"r": r, "s": s, "label": m.group(1), "raw": raw.hex()})
    return results


# ---------------------------------------------------------------------------
# Nonce reuse detection
# ---------------------------------------------------------------------------

def detect_nonce_reuse(signatures):
    """Detect nonce reuse across multiple ECDSA signatures.

    If two signatures share the same r value, they used the same k,
    and the private key can be recovered.

    Args:
        signatures: list of dicts with 'r', 's', 'z' (hash) keys

    Returns:
        list of (r, s1, s2, z1, z2, d_recovered) tuples
    """
    r_map = {}
    results = []

    for sig in signatures:
        r = sig["r"]
        s = sig["s"]
        z = sig["z"]

        if r in r_map:
            prev = r_map[r]
            d = _recover_key_from_reuse(r, s, prev["s"], z, prev["z"])
            if d is not None:
                results.append({
                    "r": r, "s1": s, "s2": prev["s"],
                    "z1": z, "z2": prev["z"],
                    "private_key": d,
                })
        else:
            r_map[r] = {"s": s, "z": z}

    return results


def _recover_key_from_reuse(r, s1, s2, z1, z2):
    """Recover private key from nonce-reused ECDSA signatures.

    When same k is used:
        s1 = (z1 + d*r) / k mod n
        s2 = (z2 + d*r) / k mod n
    So: k = (z1 - z2) / (s1 - s2) mod n
    And: d = (s1*k - z1) / r mod n
    """
    for curve in CURVES.values():
        n = curve["n"]
        ds = s1 - s2
        if ds == 0:
            continue
        dz = z1 - z2
        try:
            k = (dz * invmod(ds, n)) % n
            d = ((s1 * k - z1) * invmod(r, n)) % n
            if 0 < d < n:
                return d
        except (ValueError, ZeroDivisionError):
            continue
    return None


# ---------------------------------------------------------------------------
# Partial nonce recovery via lattice
# ---------------------------------------------------------------------------

def partial_nonce_recovery(signatures, known_bits_per_sig, curve_name="secp256k1"):
    """Recover private key when partial nonce bits are known for each signature.

    Uses lattice reduction (HNP) when fpylll is available.

    Args:
        signatures: list of {'r', 's', 'z'} dicts
        known_bits_per_sig: list of {'known': int, 'mask': int} for each sig
        curve_name: which curve

    Returns:
        private key integer, or None
    """
    curve = CURVES.get(curve_name)
    if not curve:
        return None

    n = curve["n"]
    s_inv_cache = {}

    # For each signature, compute: s_inv * r mod n
    moduli = []
    remainders = []
    bound = 2

    for sig, kb in zip(signatures, known_bits_per_sig):
        r, s, z = sig["r"], sig["s"], sig["z"]
        s_inv = invmod(s, n)
        k_partial = kb.get("known", 0)
        mask = kb.get("mask", 0)

        # From ECDSA: k = (z + d*r) * s_inv mod n
        # Known bits of k give us constraints
        if mask:
            # Remaining unknown bits
            unknown_mask = ~mask & ((1 << n.bit_length()) - 1)
            unknown_bits = bin(unknown_mask).count("1")
            if unknown_bits > 0:
                bound = 2 ** unknown_bits
                moduli.append(n)
                remainders.append((k_partial * s_inv) % n)

    if not moduli:
        return None

    # Try lattice-based HNP
    try:
        from .lattice import hnp_solve
        candidates = hnp_solve(moduli, remainders, bound)
        for candidate in candidates:
            # Verify by computing private key
            for sig, kb in zip(signatures, known_bits_per_sig):
                r, s, z = sig["r"], sig["s"], sig["z"]
                k = candidate
                d = ((s * k - z) * invmod(r, n)) % n
                if 0 < d < n:
                    return d
    except Exception:
        pass

    return None


# ---------------------------------------------------------------------------
# Signature malleability
# ---------------------------------------------------------------------------

def malleable_variants(r, s, curve_name="secp256k1"):
    """Generate malleable ECDSA signature variants.

    ECDSA signature (r, s) is malleable because (r, n-s) is also valid.
    This is critical for transaction replay in Bitcoin-like systems.

    Args:
        r, s: signature components
        curve_name: which curve

    Returns:
        list of variant dicts
    """
    curve = CURVES.get(curve_name, CURVES["secp256k1"])
    n = curve["n"]
    variants = []
    s_neg = (n - s) % n
    if s_neg != s:
        variants.append({"r": r, "s": s_neg, "type": "s negation"})
    return variants


# ---------------------------------------------------------------------------
# Signature parsing from text/JSON/PEM
# ---------------------------------------------------------------------------

def extract_signatures_from_text(text):
    """Extract ECDSA signatures from arbitrary text (JSON, PEM, hex strings).

    Returns list of dicts with 'r', 's', 'source' keys.
    """
    results = []
    seen = set()

    # Try PEM signatures
    for sig in parse_pem_signatures(text):
        key = (sig["r"], sig["s"])
        if key not in seen:
            seen.add(key)
            results.append(sig)

    # Try JSON r,s patterns
    for m in re.finditer(
        r'[\"\']?r[\"\']?\s*[:=]\s*[\"\']?(0x[0-9a-fA-F]+|\d+)[\"\']?\s*[,;]\s*'
        r'[\"\']?s[\"\']?\s*[:=]\s*[\"\']?(0x[0-9a-fA-F]+|\d+)',
        text,
    ):
        try:
            r = int(m.group(1), 0)
            s = int(m.group(2), 0)
            key = (r, s)
            if key not in seen:
                seen.add(key)
                results.append({"r": r, "s": s, "source": "json"})
        except ValueError:
            continue

    # Try raw hex signatures (DER format)
    for m in re.finditer(r"[0-9a-fA-F]{60,200}", text):
        raw = bytes.fromhex(m.group(0))
        r, s = parse_der_signature(raw)
        if r is not None and (r, s) not in seen:
            seen.add((r, s))
            results.append({"r": r, "s": s, "source": "der", "raw": m.group(0)})

    return results
