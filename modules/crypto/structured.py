"""Structured CTF crypto attacks.

Many challenge artifacts are JSON rather than a single ciphertext.  The
normal decoder pipeline is intentionally format-agnostic, so it cannot know
that ``recipients`` are an RSA broadcast set or that ``sample_outputs`` are
an LCG.  This module keeps those attacks generic: it discovers the usual
field names, validates the recovered plaintext, and returns normal solver
results to the existing flag collector.
"""
import base64
import hashlib
import json
import re
import struct

from .common import long_to_bytes, strip_zeros
from . import rsa
from . import modern
from . import ecc
from . import blockciphers
from . import aead
from . import dh
from . import signatures
from . import lattice
from . import rsa_hard
from core.flag import infer_prefixes


def _int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip().replace("_", "")
        try:
            return int(value, 10) if re.fullmatch(r"[0-9]+", value) else int(value, 0)
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
    # Challenge artifacts frequently mix hex and base64 fields.  Only try
    # base64 after the hex path so a hexadecimal-looking value stays stable.
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded, validate=True)
        if decoded:
            return decoded
    except (ValueError, base64.binascii.Error):
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
    # Cross-record attacks must precede the expensive per-key factoring ladder.
    from .rsa_bundle import records_from_bytes, solve_records
    bundle = solve_records(records_from_bytes(json.dumps(obj).encode(), "JSON"))
    bundle_plaintexts = [int(item["plaintext_hex"], 16) for item in bundle]
    out.extend(("structured-" + item["method"], bytes.fromhex(item["plaintext_hex"]))
               for item in bundle)
    for mapping in _walk(obj):
        # Direct n/e/c records, including RSA fault and shared-prime files.
        n = _int(_get(mapping, "n", "modulus"))
        e = _int(_get(mapping, "e", "exponent"))
        c = _int(_get(mapping, "c", "ciphertext", "encrypted_flag"))
        p = _int(_get(mapping, "p"))
        q = _int(_get(mapping, "q"))
        n2 = _int(_get(mapping, "n2"))
        dp = _int(_get(mapping, "dp", "d_p", "d mod p-1"))
        dq = _int(_get(mapping, "dq", "d_q", "d mod q-1"))
        qinv = _int(_get(mapping, "qinv", "q_inv", "iqmp"))
        prime_list = _get(mapping, "primes", "factors", "prime_factors")
        specialized = False
        if n and e and 2 <= e <= 2**32 and c is not None:
            specialized = any(m < n and pow(m, e, n) == c for m in bundle_plaintexts)

        # Multi-prime RSA and CRT exponent leaks are both common hard-mode
        # artifacts.  Solve these before generic factoring: a 2048-bit n with
        # a leaked dp should be instant, not a FactorDB timeout.
        if n and e and c is not None and isinstance(prime_list, list):
            factors = [_int(value) for value in prime_list]
            if factors and all(value and value > 1 for value in factors):
                plain = rsa_hard.decrypt_multi_prime(n, e, c, factors)
                if plain is not None:
                    out.append(("structured-rsa-multi-prime", plain))
                    specialized = True
        if n and e and c is not None and (dp or dq or (p and q)):
            recovered = rsa_hard.recover_private_from_crt(
                n, e, dp=dp, dq=dq, p=p, q=q, qinv=qinv)
            if recovered:
                d, rp, rq = recovered
                plain = rsa_hard.strip_zeros(rsa_hard.long_to_bytes(
                    pow(c, d, n)))
                if pow(int.from_bytes(plain, "big"), e, n) == c % n:
                    out.append(("structured-rsa-crt-leak", plain))
                    specialized = True

        # Shared-prime records often use n1/n2 instead of a single n. Solve
        # this before the generic RSA ladder, which would otherwise try to
        # factor a 1024-bit modulus for several minutes.
        n1 = _int(_get(mapping, "n1"))
        n2_pair = _int(_get(mapping, "n2"))
        if n1 and n2_pair and e and c is not None:
            try:
                shared_results = rsa.shared_prime_attack(n1, n2_pair, e, c)
                for label, pt in shared_results:
                    out.append(("structured-rsa-" + label, pt))
                specialized = bool(shared_results)
            except (ValueError, ZeroDivisionError):
                pass

        # Bellcore / CRT fault: gcd(valid - faulty, n) reveals a prime. Do
        # this before crack_rsa for the same reason as the shared-prime path.
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
                    specialized = True
            except (ValueError, ZeroDivisionError):
                pass

        if n and e and c and not specialized:
            for label, pt in rsa.crack_rsa(n=n, e=e, c=c, p=p, q=q, n2=n2):
                out.append(("structured-rsa-" + label, pt))

        # Bounded univariate small-root inputs.  The lattice adapter verifies
        # roots modulo n; malformed/oversized instances simply produce none.
        polynomial = _get(mapping, "polynomial", "poly")
        bound = _int(_get(mapping, "root_bound", "bound"))
        if n and isinstance(polynomial, list) and bound:
            roots = lattice.coppersmith_univariate(polynomial, n, bound)
            for root in roots:
                out.append(("structured-rsa-coppersmith-root", str(root)))
        prefix = _get(mapping, "known_prefix", "message_prefix")
        unknown_bytes = _int(_get(mapping, "unknown_bytes", "suffix_bytes"))
        if n and e and c is not None and prefix is not None and unknown_bytes is not None:
            for root in lattice.rsa_known_prefix_roots(
                    c, n, e, prefix, unknown_bytes,
                    _get(mapping, "known_suffix", "message_suffix") or b""):
                out.append(("structured-rsa-coppersmith-prefix", root))

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

        # Signature artifacts are often shipped next to the message in JSON.
        # A verified signature is useful evidence in its own right and can
        # reveal a flag when the challenge asks the solver to validate a
        # forged/forged-looking message.
        signed_message = _get(mapping, "message", "message_bytes", "data")
        signature = _get(mapping, "signature", "sig", "s")
        hash_name = _get(mapping, "hash", "hash_algorithm", "digest") or "sha256"
        if n and e and signed_message is not None and signature is not None:
            message_bytes = signed_message if isinstance(signed_message, bytes) else _bytes(signed_message)
            if message_bytes is None and isinstance(signed_message, str):
                message_bytes = signed_message.encode()
            sig_bytes = _bytes(signature)
            if sig_bytes is None and isinstance(signature, int):
                sig_bytes = long_to_bytes(signature)
            if message_bytes and sig_bytes and rsa_hard.verify_pkcs1_v15_signature(
                    message_bytes, sig_bytes, n, e, hash_name):
                out.append(("structured-rsa-signature-verified", message_bytes))

    # Broadcast data is normally an array of {n,e,c} records.
    for mapping in _walk(obj):
        # Re-read parameters for this mapping; do not reuse the last first-pass
        # record when applying Franklin-Reiter to a different nested object.
        n = _int(_get(mapping, "n", "modulus"))
        e = _int(_get(mapping, "e", "exponent"))
        c = _int(_get(mapping, "c", "ciphertext", "encrypted_flag"))
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
                if exponent < 2 or exponent > 7 or len(group) < exponent:
                    continue
                try:
                    # Try every exponent-sized subset: challenge files often
                    # include an extra decoy recipient.
                    from itertools import combinations
                    from itertools import islice
                    for subset in islice(combinations(group[:64], exponent), 256):
                        m = rsa.hastad_broadcast(list(subset))
                        if m is not None:
                            out.append(("structured-rsa-hastad", _plain(m)))
                except (ValueError, ZeroDivisionError):
                    pass

        # Franklin-Reiter: two related messages under the same RSA modulus.
        n = _int(_get(mapping, "n", "modulus"))
        e = _int(_get(mapping, "e", "exponent"))
        c = _int(_get(mapping, "c", "ciphertext", "encrypted_flag"))
        delta = _int(_get(mapping, "delta", "message_delta", "difference"))
        if n and e and c is not None and delta is not None:
            c2_related = _int(_get(mapping, "c2", "related_ciphertext",
                                   "ciphertext2"))
            if c2_related is not None:
                recovered = rsa.franklin_reiter(c, c2_related, n, e, delta)
                if recovered is not None:
                    out.append(("structured-rsa-franklin-reiter",
                                _plain(recovered)))
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
        r1, r2 = _int(_get(t1, "r")), _int(_get(t2, "r"))
        if s1 is None:
            try:
                r1, s1 = signatures.decode_dss_signature(
                    _get(t1, "signature", "sig", "der"))
            except (TypeError, ValueError):
                pass
        if s2 is None:
            try:
                r2, s2 = signatures.decode_dss_signature(
                    _get(t2, "signature", "sig", "der"))
            except (TypeError, ValueError):
                pass
        z1, z2 = _int(_get(t1, "z", "hash")), _int(_get(t2, "z", "hash"))
        enc = _bytes(_get(mapping, "encrypted_flag_hex", "ciphertext_hex"))
        if None in (s1, s2, z1, z2) or not enc or r1 != r2:
            continue
        try:
            recovered = signatures.recover_reused_nonce(
                n, r1 or r, s1, z1, s2, z2)
            if recovered is None:
                continue
            private, _k = recovered
            key = hashlib.sha256(hex(private).encode()).digest()
            plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(enc))
            out.append(("structured-ecdsa-nonce-reuse", plain))
        except (ValueError, ZeroDivisionError):
            pass
    return out


def _generic_dh_results(obj):
    """Recover finite-field DH secrets and decrypt XOR-style challenge data."""
    out = []
    for mapping in _walk(obj):
        p = _int(_get(mapping, "p", "prime", "modulus"))
        g = _int(_get(mapping, "g", "generator", "base"))
        public_a = _int(_get(mapping, "A", "alice_public", "public_a"))
        public_b = _int(_get(mapping, "B", "bob_public", "public_b"))
        private_a = _int(_get(mapping, "a_private", "alice_private"))
        factors = _get(mapping, "prime_factors_p_minus_1", "factors")
        if not (p and g and (public_a or private_a)):
            continue
        try:
            secret_a = private_a
            if secret_a is None:
                secret_a = dh.recover_dh_private(
                    public_a, p, g, factors=factors, order=p - 1)
            if secret_a is None:
                continue
            out.append(("structured-dh-private-recovered",
                        f"a = {secret_a} (verified)"))
            shared = None
            if public_b is not None:
                shared = pow(public_b, secret_a, p)
                out.append(("structured-dh-shared-secret",
                            f"shared = {shared}"))
            enc = _bytes(_get(mapping, "encrypted_flag", "encrypted_flag_hex",
                              "ciphertext", "ciphertext_hex"))
            if shared is not None and enc:
                for label, key in dh.derive_key_candidates(shared):
                    plain = bytes(byte ^ key[i % len(key)]
                                  for i, byte in enumerate(enc))
                    out.append((f"structured-dh-xor[{label}]", plain))
        except (ValueError, TypeError, ZeroDivisionError):
            continue
    return out


def _aead_results(obj):
    out = []
    for mapping in _walk(obj):
        algorithm = _get(mapping, "algorithm", "mode", "cipher_mode")
        key = _get(mapping, "key", "key_hex", "secret")
        ciphertext = _get(mapping, "ciphertext", "ct", "encrypted_flag",
                           "encrypted_flag_hex")
        if isinstance(algorithm, str) and key is not None and ciphertext is not None:
            plain = aead.decrypt_aes(
                algorithm, key, ciphertext,
                iv=_get(mapping, "iv", "initialization_vector"),
                nonce=_get(mapping, "nonce", "iv"),
                tag=_get(mapping, "tag", "auth_tag"),
                aad=_get(mapping, "aad", "associated_data",) or b"")
            if plain is not None:
                out.append((f"structured-aes-{algorithm.lower()}", plain))
        records = _get(mapping, "records", "messages", "encryptions")
        if isinstance(records, list):
            out.extend(aead.nonce_reuse_records(records))
            out.extend(aead.gcm_nonce_reuse_analysis(records))
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


def _xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def _stream_reuse_results(obj):
    """Recover plaintext when a stream/CTR/GCM nonce was reused.

    A common CTF artifact gives one known plaintext/ciphertext pair and a
    second ciphertext encrypted with the same keystream.  This is also the
    useful first step of many AES-GCM nonce-reuse challenges: ciphertexts
    share the stream even though the authentication tags need separate work.
    """
    out = []
    for mapping in _walk(obj):
        known_plain = _bytes(_get(mapping, "known_plaintext", "known_message",
                                  "plaintext", "message"))
        known_cipher = _bytes(_get(mapping, "known_ciphertext",
                                   "known_ct", "ciphertext1", "ct1"))
        target_cipher = _bytes(_get(mapping, "target_ciphertext",
                                    "flag_ciphertext", "ciphertext2", "ct2",
                                    "encrypted_flag", "encrypted_flag_hex"))
        if not known_plain or not known_cipher or not target_cipher:
            continue
        keystream = _xor_bytes(known_plain, known_cipher)
        if not keystream:
            continue
        recovered = _xor_bytes(target_cipher, keystream)
        out.append(("structured-stream-nonce-reuse", recovered))
    return out


def _mt_results(obj):
    """Clone MT19937 from 624 outputs and decrypt a byte-wise stream."""
    out = []
    for mapping in _walk(obj):
        samples = _get(mapping, "mt_outputs", "random_outputs", "outputs")
        enc = _bytes(_get(mapping, "encrypted_flag", "encrypted_flag_hex",
                           "ciphertext", "ciphertext_hex"))
        if not (isinstance(samples, list) and len(samples) >= modern.MT_N and enc):
            continue
        vals = [_int(x) for x in samples[:modern.MT_N]]
        if any(x is None for x in vals):
            continue
        try:
            rng = modern.clone_mt19937(vals)
            plain = bytes(byte ^ (rng.next_u32() & 0xff) for byte in enc)
            out.append(("structured-mt19937-stream", plain))
        except (TypeError, ValueError):
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


def _playfair_results(text, prefix_hint=None):
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
    # the readable plaintext and only wrap it when the artifact explicitly
    # tells us the competition prefix. Never guess an event prefix for an
    # unknown challenge.
    marker = re.search(r"(?:THE)?SECRETFLAGIS([A-Z0-9_]{6,})", decoded)
    if marker:
        body = marker.group(1)
        prefixes = infer_prefixes(text)
        if prefix_hint:
            prefix = str(prefix_hint).split("{", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z0-9_-]{2,30}", prefix):
                marker = prefix + "{"
                if marker not in prefixes:
                    prefixes.append(marker)
        for prefix in prefixes:
            results.append(("structured-playfair-flag", prefix + body + "}"))
            # Playfair padding/formatting can leave a short terminal digraph;
            # expose bounded suffix-trim candidates for the flag scorer.
            for cut in range(1, min(4, len(body) - 5) + 1):
                results.append(("structured-playfair-flag-trim",
                                prefix + body[:-cut] + "}"))
    return results


def _ecdlp_results(obj):
    """Elliptic-curve artifacts: solve Q = d*G then derive the flag key.

    Tries the common key-derivation conventions CTFs use:
    sha256(str(d)), sha256(bytes(d)), sha256(str(x of d*Q)), etc.
    """
    out = []
    for mapping in _walk(obj):
        def gi(*names):
            for name in names:
                value = _int(_get(mapping, name))
                if value is not None:
                    return value
            return None
        p = gi("p", "field_prime")
        a = gi("a")
        b = gi("b")
        gx, gy = gi("gx", "g_x"), gi("gy", "g_y")
        qx = gi("qx", "q_x", "pubx", "public_x")
        qy = gi("qy", "q_y", "puby", "public_y")
        if not (p and a is not None and b is not None and gx and gy
                and qx and qy):
            continue
        G, Q = (gx % p, gy % p), (qx % p, qy % p)
        try:
            label, d = ecc.solve_ecdlp(G, Q, a % p, b % p, p)
        except Exception:
            continue
        if d is None:
            continue
        out.append(("ecc-" + label, f"d = {d}  (Q = d*G verified)"))
        enc = _bytes(_get(mapping, "encrypted_flag_hex", "ciphertext_hex",
                          "flag_ciphertext"))
        if not enc:
            continue
        import hashlib as _hashlib
        shared_x = (d * qx) % p  # common convention: k*Q shares x-coord

        def _int_bytes(v):
            return v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        key_candidates = [
            ("sha256(str(d))", _hashlib.sha256(str(d).encode()).digest()),
            ("sha256(be(d))", _hashlib.sha256(_int_bytes(d)).digest()),
            ("sha256(str(x_dQ))",
             _hashlib.sha256(str(shared_x).encode()).digest()),
            ("sha256(be(x_dQ))",
             _hashlib.sha256(_int_bytes(shared_x)).digest()),
            ("raw-d-be32", d.to_bytes(32, "big")),
        ]
        for key_label, key in key_candidates:
            if not key:
                continue
            plain = bytes(byte ^ key[i % len(key)]
                          for i, byte in enumerate(enc))
            out.append((f"ecc-{label}-flag[{key_label}]", plain))
    return out


def analyze(text, prefix_hint=None):
    """Return solver-style results from JSON or labeled structured text."""
    if not text or not text.strip():
        return []
    results = []
    try:
        obj = json.loads(text)
        results.extend(_rsa_results(obj))
        results.extend(_ecdsa_results(obj))
        results.extend(_lcg_results(obj))
        results.extend(_stream_reuse_results(obj))
        results.extend(_dh_results(obj))
        results.extend(_generic_dh_results(obj))
        results.extend(_aead_results(obj))
        results.extend(_autokey_results(obj))
        results.extend(_mt_results(obj))
        results.extend(_ecdlp_results(obj))
        # block cipher payloads shipped as JSON ({algorithm,key,ciphertext})
        results.extend(_blockcipher_results(obj))
    except (ValueError, TypeError, json.JSONDecodeError):
        pass
    results.extend(_playfair_results(text, prefix_hint=prefix_hint))
    return results


def _blockcipher_results(obj):
    """TEA/XTEA/XXTEA payloads declared inside structured artifacts."""
    out = []
    for mapping in _walk(obj):
        alg = _get(mapping, "algorithm", "cipher")
        key_field = _get(mapping, "key", "key_hex")
        ct = _bytes(_get(mapping, "ciphertext", "ct", "encrypted_flag",
                         "encrypted_flag_hex"))
        if not (isinstance(alg, str) and isinstance(key_field, str) and ct):
            continue
        alg_l = alg.lower()
        if alg_l not in ("tea", "xtea", "xxtea"):
            continue
        try:
            key_int = int(key_field.strip().replace("_", ""), 0)
        except ValueError:
            continue
        key = key_int.to_bytes(16, "big") or None
        if key is None or len(key) != 16:
            continue
        plain = None
        if alg_l == "xxtea":
            plain = blockciphers.xxtea_decrypt(ct, key)
        elif len(ct) % 8 == 0:
            kw = list(struct.unpack("<4I", key))
            fn = (blockciphers.tea_decrypt_block if alg_l == "tea"
                  else blockciphers.xtea_decrypt_block)
            plain = b"".join(
                struct.pack("<2I", *fn(*struct.unpack_from("<2I", ct, i), kw))
                for i in range(0, len(ct), 8))
        if plain:
            out.append((f"structured-{alg_l}", plain))
    return out
