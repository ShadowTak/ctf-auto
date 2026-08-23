"""Password KDF parsers and bounded PBKDF2 cracking for CTF hashes."""
import base64
import hashlib
import re


def _b64(value):
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except Exception:
        return None


def parse_kdf(value):
    """Parse common Django/PBKDF2 encodings into a normalized dictionary."""
    value = str(value).strip()
    parts = value.split("$")
    if len(parts) == 4 and parts[0].lower() == "pbkdf2_sha256":
        try:
            iterations = int(parts[1])
        except ValueError:
            return None
        digest = _b64(parts[3])
        if digest is None:
            return None
        return {"algorithm": "sha256", "iterations": iterations,
                "salt": parts[2].encode(), "digest": digest,
                "encoding": "django"}
    if len(parts) == 4 and parts[0].lower() in ("pbkdf2-sha256", "pbkdf2-sha512"):
        try:
            iterations = int(parts[2])
        except ValueError:
            return None
        digest = _b64(parts[3])
        return {"algorithm": parts[0].split("-")[-1],
                "iterations": iterations, "salt": parts[1].encode(),
                "digest": digest, "encoding": "modular"} if digest else None
    return None


def crack_kdf(value, words, max_iterations=5_000_000):
    parsed = parse_kdf(value)
    if not parsed or not (1 <= parsed["iterations"] <= max_iterations):
        return None
    for word in words or ():
        candidate = str(word).encode()
        digest = hashlib.pbkdf2_hmac(parsed["algorithm"], candidate,
                                     parsed["salt"], parsed["iterations"],
                                     dklen=len(parsed["digest"]))
        if digest == parsed["digest"]:
            return word
    return None


def identify_kdf(value):
    value = str(value).strip().lower()
    if value.startswith("pbkdf2_sha256$"):
        return "PBKDF2-HMAC-SHA256 (Django)"
    if value.startswith("pbkdf2-sha256$"):
        return "PBKDF2-HMAC-SHA256"
    if value.startswith("pbkdf2-sha512$"):
        return "PBKDF2-HMAC-SHA512"
    if value.startswith("$argon2"):
        return "Argon2"
    if value.startswith("$scrypt$"):
        return "scrypt"
    return None

