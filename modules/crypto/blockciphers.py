"""TEA-family block ciphers and Fernet token attacks.

TEA / XTEA / XXTEA show up constantly as "custom cipher" CTF challenges;
this module provides decryptors plus a key-sweep cracker (wordlist,
repeated-byte, small-integer keys).  Fernet tokens are parsed, verified
and brute-forced against a wordlist without third-party libraries —
AES-CBC comes from modules.crypto.modern.
"""
import base64
import hashlib
import hmac as hmac_mod
import struct

from .modern import aes_cbc

_DELTA = 0x9E3779B9
_M32 = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# TEA (tiny encryption algorithm, 64-bit block)
# ---------------------------------------------------------------------------
def _words(data, little=True):
    fmt = "<%dI" % (len(data) // 4) if little else ">%dI" % (len(data) // 4)
    return list(struct.unpack(fmt, data))


def _pack(words, little=True):
    fmt = ("<" if little else ">") + "%dI" % len(words)
    return struct.pack(fmt, *words)


def tea_decrypt_block(v0, v1, k, rounds=32):
    """Original TEA: v0 += ((v1<<4)+k0)^(v1+s)^((v1>>5)+k1); then v1 with k2/k3."""
    s = (_DELTA * rounds) & _M32
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & _M32
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & _M32
        s = (s - _DELTA) & _M32
    return v0, v1


def xtea_decrypt_block(v0, v1, k, rounds=32):
    """XTEA decrypt: undo v1 first with F(v0) at key index (s>>11)&3,
    then step s back and undo v0 with F(v1) at key index s&3."""
    s = (_DELTA * rounds) & _M32
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^
                    (s + k[(s >> 11) & 3]))) & _M32
        s = (s - _DELTA) & _M32
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^
                    (s + k[s & 3]))) & _M32
    return v0, v1


def _feistel_decrypt(data, key, block_fn):
    if len(key) != 16 or len(data) % 8:
        return None
    kw = list(struct.unpack("<4I", key))
    out = []
    for i in range(0, len(data), 8):
        v0, v1 = struct.unpack_from("<2I", data, i)
        out.append(struct.pack("<2I", *block_fn(v0, v1, kw)))
    return b"".join(out)


def xxtea_decrypt(data, key):
    """Corrected Block TEA over n words; needs len(data) >= 8."""
    if len(key) != 16 or len(data) < 8 or len(data) % 4:
        return None
    k = list(struct.unpack("<4I", key))
    v = _words(data)
    nn = len(v)
    rounds = 6 + 52 // nn
    total = (rounds * _DELTA) & _M32

    def mx(z, y, s_sum, p_idx, e):
        return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^
                ((s_sum ^ y) + (k[(p_idx & 3) ^ e] ^ z))) & _M32

    while total != 0:
        e = (total >> 2) & 3
        for p in range(nn - 1, -1, -1):
            z = v[(p - 1) % nn]
            y = v[(p + 1) % nn]
            v[p] = (v[p] - mx(z, y, total, p, e)) & _M32
        total = (total - _DELTA) & _M32
    return _pack(v)


# ---------------------------------------------------------------------------
# Key-sweep cracker
# ---------------------------------------------------------------------------
_DEFAULT_KEYS = [
    b"\x00" * 16,
    b"0123456789abcdef",
    b"abcdefghijklmnop",
    b"ABCDEFGHIJKLMNOP",
    b"aaaaaaaaaaaaaaaa",
    b"1234567890123456",
    b"ThisKeyIsSecret!",
]


def _key_candidates(extra=None):
    keys = list(_DEFAULT_KEYS)
    for i in range(256):
        keys.append(bytes([i]) * 16)
    for w in range(1, 4096):  # same small word in all four slots
        keys.append(struct.pack("<4I", w, w, w, w))
    if extra:
        for item in extra:
            if isinstance(item, str):
                item = item.encode("utf-8", "ignore")
            if not item:
                continue
            keys.append(item[:16].ljust(16, b"\x00"))
            try:
                dec = base64.b64decode(item, validate=True)
                if len(dec) == 16:
                    keys.append(dec)
            except Exception:  # noqa: BLE001
                pass
    seen, out = set(), []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _crib_score(plain):
    score = 0
    low = plain.lower()
    for crib in (b"flag{", b"flag", b"ctf{", b"{"):
        if crib in low:
            score += len(crib) * 10
            break
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in plain)
    ratio = printable / max(len(plain), 1)
    score += int(ratio * 100)
    if ratio > 0.95:
        score += 50
    return score


def crack_tea_family(blob, wordlist=None, top=5):
    """Try TEA/XTEA/XXTEA decryption with many candidate keys.

    blob must be a byte string whose length fits each cipher (8-aligned for
    TEA/XTEA, 4-aligned and >=8 bytes for XXTEA).  Returns ranked
    [(label, plaintext)] with the most flag-like / printable results first.
    """
    results = []
    keys = _key_candidates(wordlist)

    from core.parallel import pmap

    def sweep(cipher_fn, name, buf):
        def one(item):
            _, key = item
            try:
                plain = cipher_fn(key)
            except Exception:
                return None
            if not plain:
                return None
            score = _crib_score(plain)
            if score > 120:
                return (score, f"{name} key={key!r}", plain)
            return None

        out = []
        for (_item, res) in pmap(one, list(enumerate(keys)), workers=16,
                                 desc=name):
            if isinstance(res, Exception) or res is None:
                continue
            out.append(res)
        return out

    for endian, buf in (("little", blob), ("big", _words_swap(blob))):
        if len(buf) % 8 == 0:
            results.extend(sweep(
                lambda k: _feistel_decrypt(
                    buf, k, lambda a, b, kk: tea_decrypt_block(a, b, kk)),
                f"tea-{endian}", buf))
            results.extend(sweep(
                lambda k: _feistel_decrypt(
                    buf, k, lambda a, b, kk: xtea_decrypt_block(a, b, kk)),
                f"xtea-{endian}", buf))
        if len(buf) % 4 == 0 and len(buf) >= 8:
            results.extend(sweep(lambda k: xxtea_decrypt(buf, k),
                                 f"xxtea-{endian}", buf))
    results.sort(key=lambda r: -r[0])
    dedup = []
    seen = set()
    for _, label, plain in results[: top * 4]:
        if plain in seen:
            continue
        seen.add(plain)
        dedup.append((label, plain))
    return dedup[:top]


def _words_swap(data):
    """Byte-swapped view for big-endian implementations."""
    out = bytearray(data)
    for i in range(0, len(out) - len(out) % 4, 4):
        out[i:i + 4] = out[i:i + 4][::-1]
    return bytes(out)


# ---------------------------------------------------------------------------
# Fernet (cryptography.io format, pure python verification + cracking)
# ---------------------------------------------------------------------------
def fernet_parse(token):
    """Parse a Fernet token. Returns dict or None.

    Layout: version(1)=0x80 || timestamp(8 BE) || iv(16) || ct || hmac(32),
    all urlsafe-base64 encoded; HMAC-SHA256 over everything before it.
    """
    raw = token.strip().encode() if isinstance(token, str) else token
    try:
        padded = raw + b"=" * (-len(raw) % 4)
        data = base64.urlsafe_b64decode(padded)
    except Exception:  # noqa: BLE001
        return None
    if len(data) < 1 + 8 + 16 + 16 + 32 or data[0] != 0x80:
        return None
    ts = int.from_bytes(data[1:9], "big")
    iv = data[9:25]
    body = data[25:-32]
    tag = data[-32:]
    if len(body) % 16:
        return None
    return {"ts": ts, "iv": iv, "ct": body, "tag": tag,
            "signed": data[:-32]}


def _fernet_keys(candidate):
    """Expand a candidate into possible Fernet keys.

    Standard Fernet: 32 raw bytes, usually shipped urlsafe-b64-encoded
    (signing key = first 16, encryption key = last 16).  CTF variants
    frequently derive it as sha256(secret) or pad a plain string.
    """
    outs = []
    if isinstance(candidate, str):
        cand_bytes = candidate.encode()
        try:
            dec = base64.urlsafe_b64decode(
                candidate + "=" * (-len(candidate) % 4))
            if len(dec) == 32:
                outs.append(dec)
        except Exception:  # noqa: BLE001
            pass
        outs.append(hashlib.sha256(cand_bytes).digest())
        outs.append(hashlib.sha256(cand_bytes).hexdigest().encode()[:32])
        outs.extend([cand_bytes[:32].ljust(32, b"\x00")])
    elif isinstance(candidate, (bytes, bytearray)):
        if len(bytes(candidate)) == 32:
            outs.append(bytes(candidate))
        else:
            outs.append((bytes(candidate) * 32)[:32])
            outs.append(hashlib.sha256(bytes(candidate)).digest())
    else:
        return []
    seen, uniq = set(), []
    for k in outs:
        if k not in seen:
            seen.add(k)
            uniq.append(k)
    return uniq


def fernet_decrypt(token, key_candidate):
    """Verify HMAC then decrypt. Returns (plaintext, key_used) or None."""
    parsed = fernet_parse(token)
    if not parsed:
        return None
    for key in _fernet_keys(key_candidate):
        signing = key[:16]
        enc_key = key[16:]
        want = hmac_mod.new(signing, parsed["signed"], hashlib.sha256).digest()
        if not hmac_mod.compare_digest(want, parsed["tag"]):
            continue
        try:
            plain = aes_cbc(parsed["ct"], enc_key, parsed["iv"], decrypt=True)
        except ValueError:
            continue
        pad = plain[-1] if plain else 0
        if isinstance(pad, int) and 1 <= pad <= 16 and \
                plain[-pad:] == bytes([pad]) * pad:
            plain = plain[:-pad]
        return plain, key
    return None


def crack_fernet(token, wordlist=None):
    """Brute-force a Fernet token's key from candidate strings."""
    candidates = list(wordlist or [])
    candidates.extend(["password", "secret", "secret_key", "changeme",
                       "supersecret", "flask_secret_key", "ctf"])
    hit = fernet_decrypt(token, candidates[0]) if candidates else None
    for cand in candidates:
        hit = fernet_decrypt(token, cand)
        if hit:
            return hit
    return None
