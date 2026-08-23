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


def _gf128_quadratic_roots(coef_square, coef_linear, constant):
    """Solve ``a*x^2 + b*x = c`` in GF(2^128), returning verified roots.

    GCM nonce reuse normally gives the simpler ``a*x^2 = c`` equation when
    records have equal lengths.  Different one-block lengths add a linear
    length-block term; solving the resulting characteristic-two quadratic
    keeps those short-flag challenges in the automatic path without pulling
    in a CAS.
    """
    a, b, c = map(int, (coef_square, coef_linear, constant))
    if a == 0:
        if b == 0:
            return []
        x = gf128_mul(c, gf128_pow(b, (1 << 128) - 2))
        return [x] if gf128_mul(b, x) == c else []

    inv_a = gf128_pow(a, (1 << 128) - 2)
    q = gf128_mul(b, inv_a)
    r = gf128_mul(c, inv_a)
    if q == 0:
        x = gf128_pow(r, 1 << 127)
        return [x] if gf128_mul(x, x) == r else []

    q2 = gf128_mul(q, q)
    t = gf128_mul(r, gf128_pow(q2, (1 << 128) - 2))
    # Substitute x=q*y, reducing to y^2 + y = t.  Solve this linear map
    # over GF(2) with a 128-row Gaussian elimination; the second root is
    # y+1 whenever a solution exists.
    basis = [1 << i for i in range(128)]
    rows = [0] * 128
    for i, unit in enumerate(basis):
        image = gf128_mul(unit, unit) ^ unit
        for bit in range(128):
            if image & (1 << bit):
                rows[bit] ^= 1 << i
    augmented = [rows[bit] | (((t >> bit) & 1) << 128)
                 for bit in range(128)]
    pivot_row = 0
    pivot_cols = []
    for col in range(128):
        pivot = next((row for row in range(pivot_row, 128)
                      if (augmented[row] >> col) & 1), None)
        if pivot is None:
            continue
        augmented[pivot_row], augmented[pivot] = (
            augmented[pivot], augmented[pivot_row])
        for row in range(128):
            if row != pivot_row and ((augmented[row] >> col) & 1):
                augmented[row] ^= augmented[pivot_row]
        pivot_cols.append(col)
        pivot_row += 1
        if pivot_row == 128:
            break
    for row in range(pivot_row, 128):
        if (augmented[row] & ((1 << 128) - 1)) == 0 and \
                ((augmented[row] >> 128) & 1):
            return []
    y = 0
    for row, col in enumerate(pivot_cols):
        if (augmented[row] >> 128) & 1:
            y |= 1 << col
    roots = []
    # In this GHASH bit ordering the multiplicative identity is 2^127.
    for candidate_y in (y, y ^ (1 << 127)):
        candidate = gf128_mul(q, candidate_y)
        if gf128_mul(a, gf128_mul(candidate, candidate)) ^ \
                gf128_mul(b, candidate) == c:
            roots.append(candidate)
    return list(dict.fromkeys(roots))


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


def recover_gcm_subkey_one_block(first, second, verify_records=None):
    """Recover GCM H and mask from two same-nonce, one-block records.

    This applies to one-block ciphertexts with identical AAD.  If two records
    leave the characteristic-two quadratic with two valid roots, additional
    same-nonce records supplied via ``verify_records`` disambiguate them.
    """
    if not isinstance(first, dict) or not isinstance(second, dict):
        return None
    if first.get("nonce") != second.get("nonce"):
        return None
    c1, c2 = decode_bytes(first.get("ciphertext")), decode_bytes(second.get("ciphertext"))
    t1, t2 = decode_bytes(first.get("tag")), decode_bytes(second.get("tag"))
    a1, a2 = decode_bytes(first.get("aad", "")), decode_bytes(second.get("aad", ""))
    # A one-block GHASH record can contain fewer than 16 ciphertext bytes;
    # GHASH right-pads that block with zeroes.  The old exact-16 check silently
    # rejected the common short-flag form of this challenge.
    if not c1 or not c2 or not t1 or not t2 or \
            not (0 < len(c1) <= 16 and 0 < len(c2) <= 16) or \
            len(t1) != 16 or len(t2) != 16 or a1 != a2:
        return None
    c1_block, c2_block = c1.ljust(16, b"\0"), c2.ljust(16, b"\0")
    delta_c = int.from_bytes(bytes(x ^ y for x, y in
                                   zip(c1_block, c2_block)), "big")
    delta_len = ((len(c1) * 8) ^ (len(c2) * 8)) & ((1 << 64) - 1)
    delta_t = int.from_bytes(bytes(x ^ y for x, y in zip(t1, t2)), "big")
    if delta_c == 0 and delta_len == 0:
        return None
    try:
        roots = _gf128_quadratic_roots(delta_c, delta_len, delta_t)
    except Exception:
        return None
    # Same-nonce mask E(K,J0) is tag xor GHASH.  A quadratic can have two
    # roots; verify each against both complete tags before accepting one.
    candidates = []
    for h in roots:
        mask = int.from_bytes(t1, "big") ^ ghash(h, a1, c1)
        if (mask ^ ghash(h, a2, c2)) == int.from_bytes(t2, "big"):
            candidates.append((h, mask))
    if not candidates:
        return None
    extra_records = [record for record in (verify_records or ())
                     if record is not first and record is not second and
                     isinstance(record, dict) and
                     record.get("nonce") == first.get("nonce")]
    # Two records can leave two mathematically valid H values.  Do not claim
    # a forgeable key unless a third same-nonce record disambiguates it.
    if len(candidates) > 1 and not extra_records:
        return None
    for h, mask in candidates:
        valid = True
        for record in verify_records or ():
            if record is first or record is second or not isinstance(record, dict):
                continue
            if record.get("nonce") != first.get("nonce"):
                continue
            ciphertext = decode_bytes(record.get("ciphertext"))
            tag = decode_bytes(record.get("tag"))
            aad = decode_bytes(record.get("aad", ""))
            if not ciphertext or len(ciphertext) > 16 or len(tag or b"") != 16:
                continue
            expected = mask ^ ghash(h, aad or b"", ciphertext)
            if expected != int.from_bytes(tag, "big"):
                valid = False
                break
        if valid:
            return h, mask
    return None


def recover_gcm_subkey_last_block(first, second, verify_records=None):
    """Recover GCM H when same-nonce records differ only in the last block.

    For equal-length messages, equal AAD, and identical ciphertext blocks
    before the last one, the GHASH delta collapses to
    ``delta_tag = delta_last_ciphertext * H``.  This is a useful multi-block
    hard-mode case and avoids pretending that a generic high-degree GHASH
    polynomial has a cheap universal solver.
    """
    if not isinstance(first, dict) or not isinstance(second, dict):
        return None
    if first.get("nonce") != second.get("nonce"):
        return None
    c1, c2 = decode_bytes(first.get("ciphertext")), decode_bytes(second.get("ciphertext"))
    t1, t2 = decode_bytes(first.get("tag")), decode_bytes(second.get("tag"))
    a1, a2 = decode_bytes(first.get("aad", "")), decode_bytes(second.get("aad", ""))
    if not c1 or not c2 or len(c1) != len(c2) or a1 != a2 or \
            len(t1 or b"") != 16 or len(t2 or b"") != 16 or len(c1) <= 16:
        return None
    blocks1 = [c1[i:i + 16].ljust(16, b"\0") for i in range(0, len(c1), 16)]
    blocks2 = [c2[i:i + 16].ljust(16, b"\0") for i in range(0, len(c2), 16)]
    if blocks1[:-1] != blocks2[:-1] or blocks1[-1] == blocks2[-1]:
        return None
    delta_c = int.from_bytes(bytes(a ^ b for a, b in zip(blocks1[-1], blocks2[-1])), "big")
    delta_t = int.from_bytes(bytes(a ^ b for a, b in zip(t1, t2)), "big")
    if not delta_c:
        return None
    try:
        ratio = gf128_mul(delta_t, gf128_pow(delta_c, (1 << 128) - 2))
        # The last ciphertext block is followed by GHASH's length block, so
        # the delta is delta_C * H^2 (not delta_C * H).
        h = gf128_pow(ratio, 1 << 127)
        if gf128_mul(delta_c, gf128_mul(h, h)) != delta_t:
            return None
        mask = int.from_bytes(t1, "big") ^ ghash(h, a1 or b"", c1)
    except (ValueError, TypeError):
        return None
    for record in verify_records or ():
        if not isinstance(record, dict) or record.get("nonce") != first.get("nonce"):
            continue
        ciphertext = decode_bytes(record.get("ciphertext"))
        tag = decode_bytes(record.get("tag"))
        aad = decode_bytes(record.get("aad", "")) or b""
        if not ciphertext or len(tag or b"") != 16:
            continue
        if mask ^ ghash(h, aad, ciphertext) != int.from_bytes(tag, "big"):
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
            recovered = recover_gcm_subkey_one_block(
                first, second, verify_records=records)
            if recovered is None:
                recovered = recover_gcm_subkey_last_block(
                    first, second, verify_records=records)
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
