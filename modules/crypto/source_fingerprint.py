"""Static crypto challenge-source fingerprinting.

This intentionally uses lexical inspection only. It extracts clues for a
planner; it never imports, evaluates, or executes supplied source code.
"""
import re

_PATTERNS = {
    "rsa": r"(?:\bRSA\b|\bpow\s*\(|\bmodulus\b|\bpublic_exponent\b|\bprivate_exponent\b|\bn\s*=)",
    "ecdsa": r"\b(?:ECDSA|SigningKey|verify|r\s*=|s\s*=)\b",
    "dh": r"\b(?:Diffie|Hellman|shared_secret|pow\s*\([^)]*p)\b",
    "prng": r"\b(?:random|randint|rand\(|seed\s*\(|MT19937|xorshift)\b",
    "kdf": r"\b(?:PBKDF2|scrypt|argon2|bcrypt|HKDF)\b",
    "stream": r"\b(?:ChaCha|RC4|AES|CTR|GCM|Poly1305|nonce|iv)\b",
    "lattice": r"\b(?:LLL|fpylll|Coppersmith|lattice|small.?root|hidden.?number)\b",
    "oracle": r"\b(?:oracle|padding|parity|decrypt|encrypt)\b",
}


def fingerprint(source, max_chars=500_000):
    text = str(source or "")[:max_chars]
    lower = text.lower()
    hits = []
    for name, pattern in _PATTERNS.items():
        if re.search(pattern, text, re.I):
            hits.append(name)
    fields = sorted(set(re.findall(
        r"(?im)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[=:]", text)))
    numeric_constants = len(re.findall(r"\b(?:0x[0-9a-f]+|\d{3,})\b", lower))
    return {"families": hits, "fields": fields[:128],
            "numeric_constants": numeric_constants,
            "source_bytes": len(text.encode("utf-8", "replace")),
            "safe": True}
