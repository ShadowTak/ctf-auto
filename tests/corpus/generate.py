"""Generate synthetic CTF challenge corpus with known answers.

Creates realistic challenge artifacts across crypto, web, and network
categories with deterministic expected answers for automated verification.
"""
import base64
import hashlib
import json
import math
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from modules.crypto.common import invmod, iroot
from modules.crypto.factoring import _is_probable_prime

_RNG = random.Random(20260905)

def _prime(start):
    value = start | 1
    for _ in range(10000):
        if _is_probable_prime(value):
            return value
        value += 2
    raise RuntimeError("fixture prime search exhausted")


def _gen_rsa(e, bits=512):
    """Generate a proper RSA key pair."""
    for _ in range(64):
        p = _prime(_RNG.getrandbits(bits // 2) | (1 << (bits // 2 - 1)))
        q = _prime(_RNG.getrandbits(bits // 2) | (1 << (bits // 2 - 1)))
        n = p * q
        phi = (p - 1) * (q - 1)
        if p != q and math.gcd(e, phi) == 1:
            return n, e, invmod(e, phi), p, q, phi
    raise RuntimeError("fixture RSA generation exhausted")


# ---------------------------------------------------------------------------
# Crypto corpus
# ---------------------------------------------------------------------------

def generate_rsa_small_e():
    """RSA with small exponent where m^e < n."""
    flag = b"ctf{rsa_small_e_trivial}"
    m = int.from_bytes(flag, "big")
    e = 3
    # The old 512-bit cap could never exceed this 526-bit m**3.
    bits = max(512, (m**e).bit_length() + 4)
    n, _, _, _, _, _ = _gen_rsa(e, bits=bits + bits % 2)
    assert n > m**e
    c = pow(m, e, n)
    return {
        "category": "crypto",
        "type": "rsa_small_e",
        "inputs": {"n": n, "e": e, "c": c},
        "flag": flag.decode(),
        "description": "RSA with e=3 where m^e < n",
    }


def generate_rsa_fermat():
    """RSA with close p, q (Fermat factorable)."""
    flag = b"ctf{fermat_factor_ez}"
    m = int.from_bytes(flag, "big")
    e = 65537
    p = _prime((1 << 255) + 20260905)
    q = _prime(p + 128)
    n = p * q
    c = pow(m, e, n)
    return {
        "category": "crypto",
        "type": "rsa_fermat",
        "inputs": {"n": n, "e": e, "c": c},
        "flag": flag.decode(),
        "description": "RSA with Fermat-factorable modulus",
    }


def generate_rsa_wiener():
    """RSA with small d (Wiener attack)."""
    flag = b"ctf{wiener_small_d}"
    m = int.from_bytes(flag, "big")
    n, _, _, p, q, phi = _gen_rsa(65537, bits=256)
    d = _prime(1 << 32)
    while math.gcd(d, phi) != 1:
        d = _prime(d + 2)
    e = invmod(d, phi)
    assert d * 3 < iroot(n, 4)
    c = pow(m, e, n)
    return {
        "category": "crypto",
        "type": "rsa_wiener",
        "inputs": {"n": n, "e": e, "c": c},
        "flag": flag.decode(),
        "description": "RSA with small private exponent (Wiener)",
    }


def generate_rsa_broadcast():
    """RSA Hastad broadcast (e=3, same message, different moduli)."""
    flag = b"ctf{hastad_broadcast}"
    m = int.from_bytes(flag, "big")
    e = 3
    pairs = []
    for _ in range(e):
        for _attempt in range(64):
            n, _, _, _, _, _ = _gen_rsa(e, bits=max(256, m.bit_length() + 18))
            if n > m and all(math.gcd(n, item['n']) == 1 for item in pairs):
                break
        else:
            raise RuntimeError("fixture broadcast generation exhausted")
        c = pow(m, e, n)
        pairs.append({"n": n, "e": e, "c": c})
    return {
        "category": "crypto",
        "type": "rsa_broadcast",
        "inputs": {"pairs": pairs, "e": e},
        "flag": flag.decode(),
        "description": "RSA Hastad broadcast attack (e=3, coprime moduli)",
    }


def generate_rsa_common_modulus():
    """RSA with same n, two different exponents."""
    flag = b"ctf{common_modulus_leak}"
    m = int.from_bytes(flag, "big")
    n, e1 = None, None
    while True:
        p = random.getrandbits(256) | 1
        q = random.getrandbits(256) | 1
        n = p * q
        e1, e2 = 17, 65537
        if math.gcd(e1, e2) == 1 and n > m:
            phi = (p - 1) * (q - 1)
            if math.gcd(e1, phi) == 1 and math.gcd(e2, phi) == 1:
                break
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)
    return {
        "category": "crypto",
        "type": "rsa_common_modulus",
        "inputs": {"n": n, "e1": e1, "e2": e2, "c1": c1, "c2": c2},
        "flag": flag.decode(),
        "description": "RSA common modulus (same n, different e)",
    }


def generate_xor_single_byte():
    """Single-byte XOR encryption."""
    flag = b"ctf{xor_single_byte_cracked}"
    key = random.randint(1, 255)
    ct = bytes(b ^ key for b in flag)
    return {
        "category": "crypto",
        "type": "xor_single_byte",
        "inputs": {"ciphertext": ct.hex(), "key": key},
        "flag": flag.decode(),
        "description": "Single-byte XOR",
    }


def generate_xor_repeating_key():
    """Repeating-key XOR."""
    flag = b"ctf{repeating_key_xor_pwned}"
    key = b"SECRET"
    ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(flag))
    return {
        "category": "crypto",
        "type": "xor_repeating_key",
        "inputs": {"ciphertext": ct.hex(), "key": key.decode()},
        "flag": flag.decode(),
        "description": "Repeating-key XOR",
    }


def generate_base64_chain():
    """Multi-layer base64 encoding."""
    flag = b"ctf{base64_chain_3_layers}"
    data = flag
    layers = []
    for _ in range(3):
        data = base64.b64encode(data)
        layers.append("base64")
    return {
        "category": "crypto",
        "type": "encoding_chain",
        "inputs": {"encoded": data.decode(), "layers": layers},
        "flag": flag.decode(),
        "description": "Triple base64 encoding",
    }


def generate_caesar():
    """Caesar cipher."""
    flag = "ctf{caesar_shift_13}"
    shift = 13
    ct = ""
    for c in flag:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            ct += chr((ord(c) - base + shift) % 26 + base)
        else:
            ct += c
    return {
        "category": "crypto",
        "type": "caesar",
        "inputs": {"ciphertext": ct, "shift": shift},
        "flag": flag,
        "description": "Caesar cipher with shift 13 (ROT13)",
    }


def generate_vigenere():
    """Vigenere cipher."""
    flag = "ctf{vigenere_key_is_key}"
    key = "KEY"
    ct = ""
    ki = 0
    for c in flag:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            shift = ord(key[ki % len(key)].lower()) - ord('a')
            ct += chr((ord(c) - base + shift) % 26 + base)
            ki += 1
        else:
            ct += c
    return {
        "category": "crypto",
        "type": "vigenere",
        "inputs": {"ciphertext": ct, "key": key},
        "flag": flag,
        "description": "Vigenere cipher",
    }


def generate_md5_hash():
    """MD5 hash to crack with known plaintext."""
    flag = "password123"
    digest = hashlib.md5(flag.encode()).hexdigest()
    return {
        "category": "crypto",
        "type": "hash_crack",
        "inputs": {"hash": digest, "algorithm": "md5"},
        "flag": flag,
        "description": "MD5 hash (weak password)",
    }


def generate_rsa_broadcast_multi():
    """RSA broadcast with multiple recipients."""
    flag = b"ctf{broadcast_multi_recipient}"
    m = int.from_bytes(flag, "big")
    e = 3
    pairs = []
    for _ in range(5):
        for _attempt in range(64):
            n, _, _, _, _, _ = _gen_rsa(e, bits=max(256, m.bit_length() + 18))
            if n > m and all(math.gcd(n, item['n']) == 1 for item in pairs):
                break
        else:
            raise RuntimeError("fixture broadcast generation exhausted")
        c = pow(m, e, n)
        pairs.append({"n": n, "e": e, "c": c})
    return {
        "category": "crypto",
        "type": "rsa_broadcast",
        "inputs": {"pairs": pairs, "e": e},
        "flag": flag.decode(),
        "description": "RSA broadcast with 5 recipients",
    }


# ---------------------------------------------------------------------------
# Corpus generation
# ---------------------------------------------------------------------------

CRYPTO_GENERATORS = [
    generate_rsa_small_e,
    generate_rsa_fermat,
    generate_rsa_wiener,
    generate_rsa_broadcast,
    generate_rsa_common_modulus,
    generate_xor_single_byte,
    generate_xor_repeating_key,
    generate_base64_chain,
    generate_caesar,
    generate_vigenere,
    generate_md5_hash,
    generate_rsa_broadcast_multi,
]


def generate_corpus(output_dir=None):
    """Generate the full challenge corpus."""
    corpus = []
    for gen in CRYPTO_GENERATORS:
        try:
            challenge = gen()
            corpus.append(challenge)
        except Exception as e:
            corpus.append({
                "category": "crypto",
                "type": gen.__name__,
                "error": str(e),
            })

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "corpus.json")
        with open(path, "w") as f:
            json.dump(corpus, f, indent=2, default=str)

    return corpus


def get_expected_flags(corpus):
    """Extract expected flags from corpus."""
    return [c["flag"] for c in corpus if "flag" in c]


if __name__ == "__main__":
    corpus = generate_corpus()
    print(f"Generated {len(corpus)} challenges")
    for c in corpus:
        print(f"  [{c['type']}] {c.get('flag', 'ERROR')}")
