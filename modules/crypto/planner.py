"""Explainable, bounded crypto fingerprint planner."""
import re

from .source_fingerprint import fingerprint as source_fingerprint


def plan(text):
    value = str(text or "")
    low = value.lower()
    jobs = ["encoding-chain", "flag-scan", "artifact-recursion"]
    reasons = []
    costs = {"encoding-chain": "cheap", "flag-scan": "cheap",
             "artifact-recursion": "bounded"}
    source = source_fingerprint(value)

    def add(job, reason, cost="targeted"):
        if job not in jobs:
            jobs.append(job)
        costs[job] = cost
        if reason not in reasons:
            reasons.append(reason)
    if re.search(r"(?im)^\s*(?:n|e|c|p|q|d)\s*[=:]", value) or re.search(r"[\"'](?:n|e|c|p|q|d)[\"']\s*:", value):
        for job in ("rsa-attacks", "factorization", "rsa-broadcast", "rsa-common-modulus"):
            add(job, "RSA-like named integer parameters", "expensive" if job == "factorization" else "targeted")
    if "recipient" in low or "broadcast" in low:
        add("rsa-broadcast", "broadcast/recipient fields")
    if "ecdsa" in low or re.search(r"(?i)\br\s*=.*\bs\s*=", value):
        add("signature-nonce-reuse", "signature parameters")
    if "xorshift" in low or "mt19937" in low or "nextint" in low or "srand" in low:
        add("prng-recovery", "PRNG metadata")
    if "pbkdf2" in low or "argon2" in low or "scrypt" in low:
        add("kdf-wordlist", "KDF marker", "expensive")
    if "nonce" in low or "iv" in low or "gcm" in low or "ctr" in low:
        add("nonce-reuse-and-aead", "AEAD/nonce marker")
    if re.search(r"(?i)(?:cipher|payload|token|data)\s*[:=]", value):
        add("labeled-payload-recursion", "labeled payload")
    for family in source["families"]:
        if family == "lattice":
            add("lattice-backend", "lattice/Coppersmith source marker", "expensive")
        elif family == "oracle":
            add("oracle-transcript-analysis", "oracle/padding source marker", "expensive")
    if source["families"]:
        add("source-safe-analysis", "crypto source markers found", "cheap")
    return {"jobs": list(dict.fromkeys(jobs)), "reasons": reasons,
            "costs": costs, "source_fingerprint": source}
