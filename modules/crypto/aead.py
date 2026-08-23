"""Modern symmetric modes and nonce-reuse helpers.

Primitive decryption uses PyCryptodome when present. Nonce-reuse recovery is
keystream algebra and therefore remains available without a cipher backend.
"""
import base64

_GCM_R = 0xE1000000000000000000000000000000


def gf128_mul(left, right):
    """Multiply two GHASH field elements in GF(2^128)."""
    left, right = int(left), int(right)
    result, value = 0, right
    for bit in range(128):
        if left & (1 << (127 - bit)):
            result ^= value
        value = (value >> 1) ^ (_GCM_R if value & 1 else 0)
    return result


def gf128_pow(value, exponent):
    # In the GHASH bit ordering, x^127 (not integer 1) is the field identity.
    result, base = 1 << 127, int(value)
    while exponent:
        if exponent & 1:
            result = gf128_mul(result, base)
        base = gf128_mul(base, base)
        exponent >>= 1
    return result


def ghash(h, aad=b"", ciphertext=b""):
    """Compute GHASH for already-decoded AAD and ciphertext bytes."""
    h = int(h)
    blocks = []
    for source in (aad or b"", ciphertext or b""):
        blocks.extend(source[i:i + 16].ljust(16, b"\0")
                      for i in range(0, len(source), 16))
    blocks.append((len(aad or b"") * 8).to_bytes(8, "big") +
                  (len(ciphertext or b"") * 8).to_bytes(8, "big"))
    value = 0
    for block in blocks:
        value = gf128_mul(value ^ int.from_bytes(block, "big"), h)
    return value


def recover_gcm_subkey_one_block(first, second):
    """Recover GCM H and mask from two same-nonce, one-block records.

    This applies only to equal-length one-block ciphertexts with identical
    AAD. The relation is verified against both supplied tags.
    """
    if not isinstance(first, dict) or not isinstance(second, dict):
        return None
    if first.get("nonce") != second.get("nonce"):
        return None
    c1, c2 = decode_bytes(first.get("ciphertext")), decode_bytes(second.get("ciphertext"))
    t1, t2 = decode_bytes(first.get("tag")), decode_bytes(second.get("tag"))
    a1, a2 = decode_bytes(first.get("aad", "")), decode_bytes(second.get("aad", ""))
    if not c1 or not c2 or not t1 or not t2 or len(c1) != 16 or len(c2) != 16 or a1 != a2:
        return None
    delta_c = int.from_bytes(bytes(x ^ y for x, y in zip(c1, c2)), "big")
    delta_t = int.from_bytes(bytes(x ^ y for x, y in zip(t1, t2)), "big")
    if delta_c == 0:
        return None
    try:
        h_squared = gf128_mul(delta_t, gf128_pow(delta_c, (1 << 128) - 2))
        h = gf128_pow(h_squared, 1 << 127)
    except Exception:
        return None
    # Same-nonce mask E(K,J0) is tag xor GHASH.
    mask = int.from_bytes(t1, "big") ^ ghash(h, a1, c1)
    if (mask ^ ghash(h, a2, c2)) != int.from_bytes(t2, "big"):
        return None
    return h, mask


def forge_gcm_tag(h, mask, ciphertext, aad=b""):
    """Forge a tag for a same-nonce ciphertext after subkey recovery."""
    value = mask ^ ghash(int(h), decode_bytes(aad) or b"",
                         decode_bytes(ciphertext) or b"")
    return value.to_bytes(16, "big")


def gcm_nonce_reuse_analysis(records):
    out = []
    records = [r for r in records or () if isinstance(r, dict)]
    for i, first in enumerate(records):
        for second in records[i + 1:]:
            recovered = recover_gcm_subkey_one_block(first, second)
            if recovered:
                h, mask = recovered
                out.append(("aead-gcm-nonce-reuse",
                            f"H={h:032x} mask={mask:032x} (verified)"))
    return out


def decode_bytes(value):
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        return None
    raw = value.strip()
    try:
        if raw.lower().startswith("0x"):
            return bytes.fromhex(raw[2:])
        if len(raw) % 2 == 0 and raw and all(c in "0123456789abcdefABCDEF" for c in raw):
            return bytes.fromhex(raw)
    except ValueError:
        pass
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
    except Exception:
        return raw.encode("utf-8")


def decrypt_aes(mode, key, ciphertext, *, iv=None, nonce=None, tag=None,
                aad=b""):
    """Decrypt AES modes represented by common CTF JSON fields."""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        return None
    mode = str(mode or "").upper().replace("AES-", "")
    key, ciphertext = decode_bytes(key), decode_bytes(ciphertext)
    iv, nonce, tag, aad = (decode_bytes(x) if x is not None else None
                           for x in (iv, nonce, tag, aad))
    if not key or ciphertext is None:
        return None
    constants = {"ECB": AES.MODE_ECB, "CBC": AES.MODE_CBC,
                 "CTR": AES.MODE_CTR, "CFB": AES.MODE_CFB,
                 "OFB": AES.MODE_OFB}
    try:
        if mode in constants:
            kwargs = {}
            if mode in ("CBC", "CFB", "OFB"):
                kwargs["iv"] = iv or nonce
            if mode == "CTR":
                kwargs["nonce"] = nonce or b""
            cipher = AES.new(key, constants[mode], **kwargs)
            return cipher.decrypt(ciphertext)
        if mode in ("GCM", "EAX", "CCM", "OCB"):
            cipher = AES.new(key, getattr(AES, "MODE_" + mode),
                             nonce=nonce or iv, mac_len=len(tag) if tag else 16)
            if aad:
                cipher.update(aad)
            plain = cipher.decrypt(ciphertext)
            if tag:
                cipher.verify(tag)
            return plain
        if mode == "SIV":
            cipher = AES.new(key, AES.MODE_SIV, nonce=nonce)
            if aad:
                cipher.update(aad)
            plain = cipher.decrypt(ciphertext)
            if tag:
                cipher.verify(tag)
            return plain
    except (ValueError, TypeError, AttributeError):
        return None
    return None


def recover_stream_nonce_reuse(known_plaintext, known_ciphertext,
                               target_ciphertext):
    """Recover the target prefix when two stream encryptions reuse a nonce."""
    plain = decode_bytes(known_plaintext)
    known = decode_bytes(known_ciphertext)
    target = decode_bytes(target_ciphertext)
    if not plain or not known or not target:
        return None
    stream = bytes(a ^ b for a, b in zip(plain, known))
    return bytes(a ^ b for a, b in zip(target, stream))


def nonce_reuse_records(records):
    """Return verified known-plaintext recoveries from a list of records."""
    out = []
    known = [r for r in records or () if isinstance(r, dict) and
             any(k in r for k in ("known_plaintext", "plaintext", "message"))]
    for source in known:
        plain = source.get("known_plaintext", source.get("plaintext", source.get("message")))
        cipher = source.get("ciphertext", source.get("ct"))
        nonce = source.get("nonce", source.get("iv"))
        if not plain or not cipher:
            continue
        for target in records or ():
            if target is source or not isinstance(target, dict):
                continue
            if target.get("nonce", target.get("iv")) != nonce:
                continue
            target_ct = target.get("ciphertext", target.get("ct"))
            recovered = recover_stream_nonce_reuse(plain, cipher, target_ct)
            if recovered:
                out.append(("aead-nonce-reuse", recovered))
    return out
