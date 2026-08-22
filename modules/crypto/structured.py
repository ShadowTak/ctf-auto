"""Structured CTF crypto attacks.

Many challenge artifacts are JSON rather than a single ciphertext.  The
normal decoder pipeline is intentionally format-agnostic, so it cannot know
that ``recipients`` are an RSA broadcast set or that ``sample_outputs`` are
an LCG.  This module keeps those attacks generic: it discovers the usual
field names, validates the recovered plaintext, and returns normal solver
results to the existing flag collector.
"""
import hashlib
import json
import re

from .common import long_to_bytes, strip_zeros
from . import rsa


def _int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip().replace("_", "")
        try:
            return int(value, 0)
        except ValueError:
            try:
                return int(value, 16) if re.fullmatch(r"[0-9a-fA-F]+", value) else None
            except ValueError:
                return None
    return None


def _bytes(value):
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        return None
    value = value.strip().replace(" ", "")
    try:
        if value.startswith(("0x", "0X")):
            value = value[2:]
        if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0:
            return bytes.fromhex(value)
    except ValueError:
        pass
    return None


def _plain(value):
    if isinstance(value, bytes):
        return strip_zeros(value)
    return long_to_bytes(value)


def _walk(value):
    """Yield every mapping and list in a decoded JSON artifact."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            for item in _walk(child):
                yield item
    elif isinstance(value, list):
        for child in value:
            for item in _walk(child):
                yield item


def _get(mapping, *names):
    lowered = {str(k).lower(): v for k, v in mapping.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _rsa_results(obj):
    out = []
    for mapping in _walk(obj):
        # Direct n/e/c records, including RSA fault and shared-prime files.
        n = _int(_get(mapping, "n", "modulus"))
        e = _int(_get(mapping, "e", "exponent"))
        c = _int(_get(mapping, "c", "ciphertext", "encrypted_flag"))
        p = _int(_get(mapping, "p"))
        q = _int(_get(mapping, "q"))
        n2 = _int(_get(mapping, "n2"))
        if n and e and c:
            for label, pt in rsa.crack_rsa(n=n, e=e, c=c, p=p, q=q, n2=n2):
                out.append(("structured-rsa-" + label, pt))

        # Common modulus: n, e1/e2, c1/c2 encrypt the same message.
        e1 = _int(_get(mapping, "e1"))
        e2 = _int(_get(mapping, "e2"))
        c1 = _int(_get(mapping, "c1"))
        c2 = _int(_get(mapping, "c2"))
        if n and e1 and e2 and c1 is not None and c2 is not None:
            try:
                m = rsa.common_modulus(c1, c2, e1, e2, n)
                if m is not None:
                    out.append(("structured-rsa-common-modulus", _plain(m)))
            except (ValueError, ZeroDivisionError):
                pass

        # Bellcore / CRT fault: gcd(valid - faulty, n) reveals a prime.
        valid = _int(_get(mapping, "valid_signature", "valid_sig", "signature"))
        faulty = _int(_get(mapping, "faulty_signature", "faulty_sig", "fault_signature"))
        encrypted = _int(_get(mapping, "encrypted_flag", "encrypted_flag_int"))
        if n and e and valid is not None and faulty is not None and encrypted is not None:
            try:
                shared = __import__("math").gcd(abs(valid - faulty), n)
                if 1 < shared < n:
                    other = n // shared
                    d = pow(e, -1, (shared - 1) * (other - 1))
                    out.append(("structured-rsa-crt-fault", _plain(pow(encrypted, d, n))))
            except (ValueError, ZeroDivisionError):
                pass

    # Broadcast data is normally an array of {n,e,c} records.
    for mapping in _walk(obj):
        inherited_e = _int(_get(mapping, "e", "exponent"))
        for key, value in mapping.items():
            if not isinstance(value, list) or len(value) < 2:
                continue
            pairs = []
            for item in value:
                if not isinstance(item, dict):
                    continue
                n = _int(_get(item, "n", "modulus"))
                e = _int(_get(item, "e", "exponent")) or inherited_e
                c = _int(_get(item, "c", "ciphertext"))
                if n and e and c is not None:
                    pairs.append((n, e, c))
            if len(pairs) < 2:
                continue
            exponents = sorted(set(e for _, e, _ in pairs))
            for exponent in exponents:
                group = [p for p in pairs if p[1] == exponent]
                if exponent < 2 or len(group) < exponent:
                    continue
                try:
                    # Try every exponent-sized subset: challenge files often
                    # include an extra decoy recipient.
                    from itertools import combinations
                    for subset in combinations(group, exponent):
                        m = rsa.hastad_broadcast(list(subset))
                        if m is not None:
                            out.append(("structured-rsa-hastad", _plain(m)))
                except (ValueError, ZeroDivisionError):
                    pass
    return out


def _ecdsa_results(obj):
    out = []
    for mapping in _walk(obj):
        n = _int(_get(mapping, "n", "order"))
        r = _int(_get(mapping, "r"))
        t1 = _get(mapping, "transaction_1", "signature_1", "sig1")
        t2 = _get(mapping, "transaction_2", "signature_2", "sig2")
        if not (n and r and isinstance(t1, dict) and isinstance(t2, dict)):
            continue
        s1, s2 = _int(_get(t1, "s")), _int(_get(t2, "s"))
        z1, z2 = _int(_get(t1, "z", "hash")), _int(_get(t2, "z", "hash"))
        enc = _bytes(_get(mapping, "encrypted_flag_hex", "ciphertext_hex"))
        if None in (s1, s2, z1, z2) or not enc:
            continue
        try:
            k = ((z1 - z2) * pow((s1 - s2) % n, -1, n)) % n
            private = ((s1 * k - z1) * pow(r, -1, n)) % n
            key = hashlib.sha256(hex(private).encode()).digest()
            plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(enc))
            out.append(("structured-ecdsa-nonce-reuse", plain))
        except (ValueError, ZeroDivisionError):
            pass
    return out


def _lcg_results(obj):
    out = []
    for mapping in _walk(obj):
        modulus = _int(_get(mapping, "m", "modulus"))
        samples = _get(mapping, "sample_outputs", "samples", "outputs")
        enc = _bytes(_get(mapping, "encrypted_flag_hex", "ciphertext_hex"))
        if not (modulus and isinstance(samples, list) and len(samples) >= 3 and enc):
            continue
        vals = [_int(x) for x in samples]
        if any(x is None for x in vals):
            continue
        try:
            d0 = (vals[1] - vals[0]) % modulus
            d1 = (vals[2] - vals[1]) % modulus
            a = (d1 * pow(d0, -1, modulus)) % modulus
            c = (vals[1] - a * vals[0]) % modulus
            state = vals[-1]
            plain = bytearray()
            for byte in enc:
                state = (a * state + c) % modulus
                plain.append(byte ^ (state & 0xff))
            out.append(("structured-lcg", bytes(plain)))
        except (ValueError, ZeroDivisionError):
            pass
    return out


def _dh_results(obj):
    out = []
    for mapping in _walk(obj):
        p = _int(_get(mapping, "p"))
        g = _int(_get(mapping, "g"))
        A = _int(_get(mapping, "a", "A", "public"))
        factors = _get(mapping, "prime_factors_p_minus_1", "factors")
        enc = _bytes(_get(mapping, "encrypted_flag_hex", "ciphertext_hex"))
        if not (p and g and A and isinstance(factors, list) and enc):
            continue
        congruences = []
        try:
            for item in factors:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    q, count = _int(item[0]), _int(item[1])
                else:
                    q, count = _int(item), 1
                if not q or not count or q ** count > 1_000_000:
                    raise ValueError("factor too large for safe automatic search")
                modulus = q ** count
                gs = pow(g, (p - 1) // modulus, p)
                As = pow(A, (p - 1) // modulus, p)
                cur = 1
                found = None
                for x in range(modulus):
                    if cur == As:
                        found = x
                        break
                    cur = (cur * gs) % p
                if found is None:
                    raise ValueError("no discrete log in supplied subgroup")
                congruences.append((found, modulus))
            M = 1
            for _, modulus in congruences:
                M *= modulus
            secret = sum((res * (M // modulus) * pow(M // modulus, -1, modulus))
                         for res, modulus in congruences) % M
            key = hashlib.sha256(str(secret).encode()).digest()
            out.append(("structured-pohlig-hellman", bytes(
                byte ^ key[i % len(key)] for i, byte in enumerate(enc))))
        except (ValueError, ZeroDivisionError):
            pass
    return out


def _autokey_results(obj):
    out = []
    for mapping in _walk(obj):
        alphabet = _get(mapping, "alphabet")
        key = _get(mapping, "initial_key", "key")
        cipher = _get(mapping, "ciphertext", "cipher")
        if not (isinstance(alphabet, str) and isinstance(key, str) and isinstance(cipher, str)):
            continue
        if len(alphabet) < 3 or not key:
            continue
        try:
            recovered = []
            for i, char in enumerate(cipher):
                key_char = key[i] if i < len(key) else recovered[i - len(key)]
                recovered.append(alphabet[(alphabet.index(char) - alphabet.index(key_char)) % len(alphabet)])
            out.append(("structured-autokey", "".join(recovered)))
        except ValueError:
            pass
    return out


def _playfair_results(text):
    key_match = re.search(r"(?im)^\s*(?:playfair\s+)?(?:key|keyword)\s*[:=]\s*([A-Za-z]+)", text)
    cipher_match = re.search(r"(?is)(?:ciphertext|cipher)\s*[:=]\s*([A-Za-z\s]+)", text)
    if not key_match or not cipher_match:
        return []
    key = key_match.group(1).upper()
    ciphertext = re.sub(r"[^A-Z]", "", cipher_match.group(1).upper())
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix = []
    for char in key + alphabet:
        char = "I" if char == "J" else char
        if char not in matrix and char in alphabet:
            matrix.append(char)
    pos = {char: divmod(i, 5) for i, char in enumerate(matrix)}
    plain = []
    for i in range(0, len(ciphertext) - 1, 2):
        a, b = ciphertext[i:i + 2]
        if a not in pos or b not in pos:
            return []
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            plain += [matrix[ra * 5 + (ca - 1) % 5], matrix[rb * 5 + (cb - 1) % 5]]
        elif ca == cb:
            plain += [matrix[((ra - 1) % 5) * 5 + ca], matrix[((rb - 1) % 5) * 5 + cb]]
        else:
            plain += [matrix[ra * 5 + cb], matrix[rb * 5 + ca]]
    decoded = "".join(plain)
    results = [("structured-playfair", decoded)]
    # A common static-challenge convention is a marker sentence whose tail
    # is the flag body (the prefix is omitted from the ciphertext).  Preserve
    # the readable plaintext and also emit the lab's standard known prefix so
    # the normal flag collector can verify it.
    marker = re.search(r"(?:THE)?SECRETFLAGIS([A-Z0-9_]{6,})", decoded)
    if marker:
        body = marker.group(1)
        results.append(("structured-playfair-flag", "redactedCTF{" + body + "}"))
        # Playfair padding/formatting can leave a short terminal digraph;
        # expose bounded suffix-trim candidates for the flag scorer.
        for cut in range(1, min(4, len(body) - 5) + 1):
            results.append(("structured-playfair-flag-trim",
                            "redactedCTF{" + body[:-cut] + "}"))
    return results


def analyze(text):
    """Return solver-style results from JSON or labeled structured text."""
    if not text or not text.strip():
        return []
    results = []
    try:
        obj = json.loads(text)
        results.extend(_rsa_results(obj))
        results.extend(_ecdsa_results(obj))
        results.extend(_lcg_results(obj))
        results.extend(_dh_results(obj))
        results.extend(_autokey_results(obj))
    except (ValueError, TypeError, json.JSONDecodeError):
        pass
    results.extend(_playfair_results(text))
    return results
