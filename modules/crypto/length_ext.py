"""SHA-256 length extension attack (pure stdlib).

sha256(secret || message) is a broken MAC: without knowing `secret` you can
extend a known (message, mac) pair to forge a MAC for
message || padding || append. This module also auto-detects the classic
challenge layout (sample.txt style):

    message: amount=100&user=bob
    mac:     01b39227...
    The secret is 16 bytes long
    Goal: forge a MAC ... for the message amount=100&user=bob&amount=999999
"""
import re

_K = [
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

_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
       0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

_MASK = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK


def _compress(state, block):
    w = list(struct_unpack_be(block)) + [0] * 48
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _K[i] + w[i]) & _MASK
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _MASK
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK, c, b, a, (t1 + t2) & _MASK
    return [(x + y) & _MASK for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def struct_unpack_be(block):
    return [int.from_bytes(block[i * 4:(i + 1) * 4], "big") for i in range(16)]


def sha256_padding(total_len):
    """Standard SHA-256 padding for a message of total_len bytes."""
    n = (total_len * 8) & _MASK
    pad = b"\x80" + b"\x00" * ((56 - (total_len + 1) % 64) % 64)
    return pad + n.to_bytes(8, "big")


def sha256_extend(known_mac_hex, message, append, secret_len):
    """Forge (new_mac_hex, glued_message_bytes).

    known_mac_hex = hex(sha256(secret || message)) with secret of secret_len
    bytes. The glued message verifies: sha256(secret || glued) == new_mac.
    """
    pad = sha256_padding(secret_len + len(message))
    glued = message + pad + append
    state = [int(known_mac_hex[i * 8:(i + 1) * 8], 16) for i in range(8)]
    total_bits = (secret_len + len(glued)) * 8
    # the MAC state already covers secret || message || pad — continue with
    # ONLY the appended bytes, then the final padding for the NEW length
    data = append
    full = len(data) - (len(data) % 64)
    for i in range(0, full, 64):
        state = _compress(state, data[i:i + 64])
    last = data[full:]
    last += b"\x80" + b"\x00" * ((56 - (len(last) + 1) % 64) % 64)
    last += (total_bits & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
    state = _compress(state, last)
    new_mac = "".join(f"{w:08x}" for w in state)
    return new_mac, glued


def _self_test():
    """sha256(secret || glued) must verify against the forged MAC."""
    import hashlib
    secret = b"0123456789abcdef"  # 16 bytes
    msg = b"amount=100&user=bob"
    mac = hashlib.sha256(secret + msg).hexdigest()
    new_mac, glued = sha256_extend(mac, msg, b"&amount=999999", 16)
    return hashlib.sha256(secret + glued).hexdigest() == new_mac


def detect_and_forge(text):
    """Parse a challenge text; return list of (label, result) findings."""
    if not re.search(r"(?i)sha-?256|sha256", text):
        return []
    mm = re.search(r"(?im)^\s*(?:mac|hash|sig(?:nature)?)\s*[:=]\s*([0-9a-fA-F]{64})\s*$", text)
    if not mm:
        return []
    mac = mm.group(1).lower()
    mmsg = re.search(r"(?im)^\s*(?:message|msg|data|value)\s*[:=]\s*(.+?)\s*$", text)
    if not mmsg:
        return []
    message = mmsg.group(1).strip().encode()
    sl = re.search(r"(?i)secret\s+is\s+(\d+)\s*bytes", text)
    secret_len = int(sl.group(1)) if sl else 16
    # goal message: "forge a MAC ... for the message <msg>" or "&append" style
    goal = re.search(r"(?is)forge\s+a\s+mac.{0,200}?(?:for\s+the\s+message|with\s+data|append)\s*[:=]?\s*[\"']?([^\"'\n]{3,200})", text)
    if goal:
        append_text = goal.group(1).strip()
        # find the part that extends the original message
        base = message.decode()
        if append_text.startswith(base) and len(append_text) > len(base):
            append = append_text[len(base):].encode()
        else:
            append = append_text.encode()
    else:
        # no explicit goal — extend with a benign marker to prove the attack
        append = b"&admin=1"
    new_mac, glued = sha256_extend(mac, message, append, secret_len)
    # url-encode the padding bytes so the forged message is printable/submittable
    glued_disp = "".join(
        chr(b) if 32 <= b < 127 else f"%{b:02X}" for b in glued
    )
    return [
        ("hash-length-extension",
         f"forged MAC={new_mac} for message={glued_disp} "
         f"(secret={secret_len}B, appends {len(append)}B) — "
         f"sha256(secret||msg) verifies to {new_mac}"),
    ]


if __name__ == "__main__":
    print("self-test:", "OK" if _self_test() else "FAILED")
    sample = """message: amount=100&user=bob
mac:     01b392274854ec6a7e2824245704f1d77d37af54ce4f53b841fae67a2c41ac26
The secret is 16 bytes long.
Goal: forge a MAC that verifies for the message amount=100&user=bob&amount=999999
"""
    for label, out in detect_and_forge(sample):
        print(f"[{label}] {out}")
