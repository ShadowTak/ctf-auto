"""DSA/ECDSA signature parsing and nonce-reuse recovery."""


def _der_length(data, offset):
    if offset >= len(data):
        raise ValueError("truncated DER length")
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7f
        if not count or offset + count > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return length, offset


def decode_dss_signature(signature):
    """Decode a DER ECDSA/DSA signature into ``(r, s)``."""
    if isinstance(signature, str):
        raw = bytes.fromhex(signature.removeprefix("0x"))
    else:
        raw = bytes(signature)
    if len(raw) < 6 or raw[0] != 0x30:
        raise ValueError("not a DER sequence")
    length, pos = _der_length(raw, 1)
    end = pos + length
    if end > len(raw):
        raise ValueError("truncated DER sequence")
    values = []
    while pos < end:
        if raw[pos] != 0x02:
            raise ValueError("DER signature item is not INTEGER")
        size, pos = _der_length(raw, pos + 1)
        if not size or pos + size > end:
            raise ValueError("truncated DER integer")
        values.append(int.from_bytes(raw[pos:pos + size], "big", signed=False))
        pos += size
    if len(values) != 2:
        raise ValueError("ECDSA signature needs r and s")
    return values[0], values[1]


def recover_reused_nonce(n, r, s1, z1, s2, z2):
    """Recover ``(private_key, nonce)`` from two ECDSA signatures sharing r."""
    n, r, s1, z1, s2, z2 = map(int, (n, r, s1, z1, s2, z2))
    if r % n == 0 or (s1 - s2) % n == 0:
        return None
    try:
        k = ((z1 - z2) * pow((s1 - s2) % n, -1, n)) % n
        private = ((s1 * k - z1) * pow(r, -1, n)) % n
    except ValueError:
        return None
    if (s1 * k - z1 - r * private) % n:
        return None
    return private, k


def recover_known_nonce(n, r, s, z, k):
    n, r, s, z, k = map(int, (n, r, s, z, k))
    try:
        private = ((s * k - z) * pow(r, -1, n)) % n
    except ValueError:
        return None
    return private if (s * k - z - r * private) % n == 0 else None

