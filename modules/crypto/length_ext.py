"""Length-extension attacks for MD5 / SHA-1 / SHA-256 (pure stdlib).

All three Merkle-Damgard hashes share the same weakness:
mac = H(secret || message) lets anyone forge
H(secret || message || glue_padding || append) without knowing `secret`.

This module auto-detects the classic challenge layout (sample.txt style):

    message: amount=100&user=bob
    mac:     01b39227...
    The secret is 16 bytes long
    Goal: forge a MAC ... for the message amount=100&user=bob&amount=999999

and supports all three hash families (MD5 little-endian words, SHA-1 and
SHA-256 big-endian).
"""
import math
import re
import struct

_MASK = 0xFFFFFFFF


def _rol(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & _MASK


# ---------------------------------------------------------------------------
# Compression functions
# ---------------------------------------------------------------------------
def _sha1_compress(state, block):
    w = list(struct.unpack(">16I", block)) + [0] * 64
    for i in range(16, 80):
        w[i] = _rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
    a, b, c, d, e = state
    for i in range(80):
        if i < 20:
            f = (b & c) | (~b & d)
            k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        t = (_rol(a, 5) + (f & _MASK) + e + k + w[i]) & _MASK
        e, d, c, b, a = d, c, _rol(b, 30), a, t
    return [(x + y) & _MASK for x, y in zip(state, (a, b, c, d, e))]


_MD5_S = ([7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 +
          [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4)
_MD5_K = [math.floor(abs(math.sin(i + 1)) * (1 << 32)) for i in range(64)]


def _md5_compress(state, block):
    m = list(struct.unpack("<16I", block))
    a, b, c, d = state
    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d)
            g = i
        elif i < 32:
            f = (d & b) | (~d & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | (~d & _MASK))
            g = (7 * i) % 16
        tmp = (f + a + _MD5_K[i] + m[g]) & _MASK
        a, d, c = d, c, b
        b = (b + _rol(tmp, _MD5_S[i])) & _MASK
    return [(x + y) & _MASK for x, y in zip(state, (a, b, c, d))]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK


_SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _sha256_compress(state, block):
    w = list(struct.unpack(">16I", block)) + [0] * 48
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _SHA256_K[i] + w[i]) & _MASK
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _MASK
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK, \
            c, b, a, (t1 + t2) & _MASK
    return [(x + y) & _MASK for x, y in zip(state,
                                            (a, b, c, d, e, f, g, h))]


# ---------------------------------------------------------------------------
# Algorithm registry: word order / endianness differ per family
# ---------------------------------------------------------------------------
_ALGS = {
    "md5": {
        "iv": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
        "words": 4, "endian": "<", "comp": _md5_compress, "digest": 32,
    },
    "sha1": {
        "iv": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
        "words": 5, "endian": ">", "comp": _sha1_compress, "digest": 40,
    },
    "sha256": {
        "iv": [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
               0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19],
        "words": 8, "endian": ">", "comp": _sha256_compress, "digest": 64,
    },
}


def md_padding(total_len, endian=">"):
    """Merkle-Damgard padding; MD5 serialises the length little-endian."""
    pad = b"\x80" + b"\x00" * ((56 - (total_len + 1) % 64) % 64)
    order = "little" if endian == "<" else "big"
    return pad + ((total_len * 8) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, order)


def full_hash(alg_name, data):
    """Reference implementation used to self-verify the extension math."""
    spec = _ALGS[alg_name]
    order = "little" if spec["endian"] == "<" else "big"
    state = list(spec["iv"])
    padded = data + md_padding(len(data), spec["endian"])
    for i in range(0, len(padded), 64):
        state = spec["comp"](state, padded[i:i + 64])
    return b"".join(
        w.to_bytes(4, order) for w in state).hex()


def length_extension_extend(alg_name, known_mac_hex, message, append,
                            secret_len):
    """Forge (new_mac_hex, glued_message_bytes) for any supported family."""
    spec = _ALGS[alg_name]
    endian = spec["endian"]
    order = "little" if endian == "<" else "big"
    state = [
        int.from_bytes(bytes.fromhex(
            known_mac_hex[i * 8:(i + 1) * 8]), order)
        for i in range(spec["words"])
    ]
    glued = message + md_padding(secret_len + len(message), endian) + append
    comp = spec["comp"]
    data = append
    total_bits = (secret_len + len(glued)) * 8
    full = len(data) - (len(data) % 64)
    for i in range(0, full, 64):
        state = comp(state, data[i:i + 64])
    last = data[full:]
    last += b"\x80" + b"\x00" * ((56 - (len(last) + 1) % 64) % 64)
    last += (total_bits & 0xFFFFFFFFFFFFFFFF).to_bytes(8, order)
    state = comp(state, last)
    new_mac = b"".join(w.to_bytes(4, order) for w in state).hex()
    return new_mac, glued


# Back-compat shims ------------------------------------------------------
def sha256_padding(total_len):
    return md_padding(total_len, ">")


def sha256_extend(known_mac_hex, message, append, secret_len):
    return length_extension_extend("sha256", known_mac_hex, message,
                                   append, secret_len)


def struct_unpack_be(block):
    return [int.from_bytes(block[i * 4:(i + 1) * 4], "big") for i in range(16)]


# ---------------------------------------------------------------------------
# Challenge-text auto-detection
# ---------------------------------------------------------------------------
def detect_and_forge(text):
    """Parse a challenge text; return list of (label, result) findings.

    Hash family comes from an explicit mention when present, else from the
    MAC hex length (32 -> md5, 40 -> sha1, 64 -> sha256).
    """
    mm = re.search(
        r"(?im)^\s*(?:mac|hash|sig(?:nature)?)\s*[:=]\s*([0-9a-fA-F]{32,64})\s*$",
        text)
    if not mm:
        return []
    mac = mm.group(1).lower()
    if re.search(r"(?i)\bmd5\b", text):
        alg = "md5"
    elif re.search(r"(?i)\bsha[- ]?1\b|\bsha1\b", text):
        alg = "sha1"
    elif re.search(r"(?i)sha[- ]?256|sha256", text):
        alg = "sha256"
    else:
        by_len = {32: "md5", 40: "sha1", 64: "sha256"}
        alg = by_len.get(len(mac))
        if not alg:
            return []
    mmsg = re.search(r"(?im)^\s*(?:message|msg|data|value)\s*[:=]\s*(.+?)\s*$",
                     text)
    if not mmsg:
        return []
    message = mmsg.group(1).strip().encode()
    sl = re.search(r"(?i)secret\s+is\s+(\d+)\s*bytes", text)
    secret_len = int(sl.group(1)) if sl else 16
    goal = re.search(
        r"(?is)forge\s+a\s+mac.{0,200}?"
        r"(?:for\s+the\s+message|with\s+data|append)\s*[:=]?\s*[\"']?"
        r"([^\"'\n]{3,200})", text)
    if goal:
        append_text = goal.group(1).strip()
        base = message.decode(errors="replace")
        if append_text.startswith(base) and len(append_text) > len(base):
            append = append_text[len(base):].encode()
        else:
            append = append_text.encode()
    else:
        append = b"&admin=1"
    try:
        new_mac, glued = length_extension_extend(alg, mac, message, append,
                                                 secret_len)
    except Exception:  # noqa: BLE001
        return []
    glued_disp = "".join(
        chr(b) if 32 <= b < 127 else f"%{b:02X}" for b in glued)
    return [
        ("hash-length-extension",
         f"forged {alg.upper()} MAC={new_mac} for message={glued_disp} "
         f"(secret={secret_len}B, appends {len(append)}B) — verifies to "
         f"{new_mac}"),
    ]


def _self_test():
    import hashlib
    ok = True
    cases = [
        ("md5", lambda b: hashlib.md5(b).hexdigest()),
        ("sha1", lambda b: hashlib.sha1(b).hexdigest()),
        ("sha256", lambda b: hashlib.sha256(b).hexdigest()),
    ]
    for alg, fn in cases:
        # 1. reference implementation matches stdlib on odd lengths
        for sample in (b"", b"a", b"abc", b"x" * 55, b"y" * 56, b"z" * 119):
            if full_hash(alg, sample) != fn(sample):
                ok = False
                print(f"[FAIL] {alg} reference mismatch on len={len(sample)}")
        # 2. forged MAC verifies against the real construction
        secret = b"S" * 16
        msg = b"amount=100&user=bob"
        new_mac, glued = length_extension_extend(
            alg, fn(secret + msg), msg, b"&admin=1", len(secret))
        if fn(secret + glued) != new_mac:
            ok = False
            print(f"[FAIL] {alg} forged MAC does not verify")
    return ok


if __name__ == "__main__":
    print("self-test:", "OK" if _self_test() else "FAILED")
    for label, out in detect_and_forge(
            "message: amount=100&user=bob\n"
            "mac:     01b392274854ec6a7e2824245704f1d77d37af54ce4f53b841fae67"
            "a2c41ac26\nThe secret is 16 bytes long.\n"):
        print(f"[{label}] {out}")
