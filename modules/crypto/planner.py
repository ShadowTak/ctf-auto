"""Cheap crypto fingerprint planner; it only selects bounded jobs."""
import re


def plan(text):
    value = str(text or "")
    low = value.lower()
    jobs = ["encoding-chain", "flag-scan", "artifact-recursion"]
    reasons = []
    if re.search(r"(?im)^\s*(?:n|e|c|p|q|d)\s*[=:]", value) or re.search(r"[\"'](?:n|e|c|p|q|d)[\"']\s*:", value):
        jobs += ["rsa-attacks", "factorization", "rsa-broadcast", "rsa-common-modulus"]
        reasons.append("RSA-like named integer parameters")
    if "recipient" in low or "broadcast" in low:
        jobs.append("rsa-broadcast")
        reasons.append("broadcast/recipient fields")
    if "ecdsa" in low or re.search(r"(?i)\br\s*=.*\bs\s*=", value):
        jobs.append("signature-nonce-reuse")
        reasons.append("signature parameters")
    if "xorshift" in low or "mt19937" in low or "nextint" in low or "srand" in low:
        jobs.append("prng-recovery")
        reasons.append("PRNG metadata")
    if "pbkdf2" in low or "argon2" in low or "scrypt" in low:
        jobs.append("kdf-wordlist")
        reasons.append("KDF marker")
    if "nonce" in low or "iv" in low or "gcm" in low or "ctr" in low:
        jobs.append("nonce-reuse-and-aead")
        reasons.append("AEAD/nonce marker")
    if re.search(r"(?i)(?:cipher|payload|token|data)\s*[:=]", value):
        jobs.append("labeled-payload-recursion")
        reasons.append("labeled payload")
    return {"jobs": list(dict.fromkeys(jobs)), "reasons": reasons}
