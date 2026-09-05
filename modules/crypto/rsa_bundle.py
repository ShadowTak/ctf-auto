"""Offline RSA relationships across challenge files, with equation checks.

No factoring service or generic per-key brute force runs here. Work is bounded
by record, integer-size, pair and broadcast-combination limits.
"""
import itertools
import json
import math
import re

from .rsa import common_modulus, hastad_broadcast, parse_pem

MAX_RECORDS = 64
MAX_BITS = 8192
MAX_COMBINATIONS = 256
ALIASES = {"modulus": "n", "exponent": "e", "ciphertext": "c",
           "encrypted_flag": "c", "n": "n", "e": "e", "c": "c"}
ASSIGNMENT = re.compile(
    r"(?im)^\s*[\"']?(n|e|c|modulus|exponent|ciphertext|encrypted_flag)"
    r"[\"']?\s*[=:]\s*[\"']?(0x[0-9a-f]+|[0-9]+)[\"']?\s*[,;]?\s*$")


def integer(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value.bit_length() <= MAX_BITS and value >= 0 else None
    if not isinstance(value, str) or len(value) > MAX_BITS:
        return None
    value = value.strip().replace("_", "")
    try:
        result = int(value, 16 if value.lower().startswith("0x") else 10)
        return result if result >= 0 and result.bit_length() <= MAX_BITS else None
    except ValueError:
        return None


def records_from_bytes(data, source):
    """Read inert JSON, assignment text, or a PEM key; never eval source code."""
    text = data.decode("utf-8", "replace")
    records = []

    def record(mapping, where, inherited_e=None):
        values = {ALIASES[k.lower()]: integer(v) for k, v in mapping.items()
                  if isinstance(k, str) and k.lower() in ALIASES}
        if values.get("e") is None and inherited_e is not None:
            values["e"] = inherited_e
        values = {k: v for k, v in values.items() if v is not None}
        if values.get("n", 0) > 2 and len(records) < MAX_RECORDS:
            records.append(dict(values, sources=[where]))

    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        obj = None
    stack = [(obj, source, None, 0)]
    visited = 0
    while stack and visited < 2048 and len(records) < MAX_RECORDS:
        item, where, inherited_e, depth = stack.pop()
        visited += 1
        if depth > 24:
            continue
        if isinstance(item, dict):
            inherited_e = integer(item.get("e", item.get("exponent"))) or inherited_e
            record(item, where, inherited_e)
            stack.extend((v, where + ":" + str(k), inherited_e, depth + 1)
                         for k, v in list(item.items())[:256]
                         if isinstance(v, (dict, list)))
        elif isinstance(item, list):
            stack.extend((v, where + ":" + str(i), inherited_e, depth + 1)
                         for i, v in enumerate(item[:256]))
    if obj is None:
        pairs = ASSIGNMENT.findall(text)
        # Repeated names represent ambiguous transcripts, not one merged key.
        if len({ALIASES[k.lower()] for k, _ in pairs}) == len(pairs):
            record(dict(pairs), source)
        if "-----BEGIN " in text:
            try:
                record(parse_pem(data), source)
            except (ValueError, IndexError):
                pass
    return records


def solve_records(records):
    records = [r for r in records[:MAX_RECORDS]
               if integer(r.get("n")) and r["n"] > 2]
    results = []
    seen = set()

    def add(method, message, checked):
        if message is None or message < 0:
            return
        # Verification is exact, and includes every record supporting a claim.
        if not all(0 <= message < r["n"] and
                   pow(message, r["e"], r["n"]) == r["c"] for r in checked):
            return
        sources = sorted({s for r in checked for s in r.get("sources", [])})
        raw = message.to_bytes(max(1, (message.bit_length() + 7) // 8), "big")
        key = (method, raw, tuple(sources))
        if key in seen:
            return
        seen.add(key)
        results.append({"method": method, "plaintext": raw.decode("utf-8", "replace"),
                        "plaintext_hex": raw.hex(), "sources": sources,
                        "verified": True,
                        "evidence": ["pow(m, e, n) == c for every supporting ciphertext"]})

    def usable(r):
        return (isinstance(r.get("e"), int) and 2 <= r["e"] <= 2**32 and
                isinstance(r.get("c"), int) and 0 <= r["c"] < r["n"])

    for left, right in itertools.combinations(records, 2):
        factor = math.gcd(left["n"], right["n"])
        if 1 < factor < min(left["n"], right["n"]):
            for current in (left, right):
                if not usable(current):
                    continue
                other = current["n"] // factor
                try:
                    private = pow(current["e"], -1, (factor - 1) * (other - 1))
                    add("rsa-shared-prime", pow(current["c"], private, current["n"]),
                        [dict(current, sources=left.get("sources", []) + right.get("sources", []))])
                except ValueError:
                    pass
        if left["n"] == right["n"] and usable(left) and usable(right):
            if math.gcd(left["e"], right["e"]) != 1:
                continue
            try:
                message = common_modulus(left["c"], right["c"], left["e"],
                                         right["e"], left["n"])
                add("rsa-common-modulus", message, [left, right])
            except (ValueError, ZeroDivisionError):
                pass

    attempts = 0
    for exponent in range(2, 8):
        group = [r for r in records if usable(r) and r["e"] == exponent]
        for subset in itertools.combinations(group, exponent):
            if attempts >= MAX_COMBINATIONS:
                break
            attempts += 1
            if len({r["n"] for r in subset}) != exponent:
                continue
            try:
                message = hastad_broadcast([(r["n"], r["e"], r["c"]) for r in subset])
                add("rsa-hastad-broadcast", message, subset)
            except (ValueError, ZeroDivisionError):
                pass
    return results


def solve_inventory(inventory):
    records = []
    for item in inventory:
        records.extend(records_from_bytes(item["data"], item["path"]))
        if len(records) >= MAX_RECORDS:
            break
    return solve_records(records[:MAX_RECORDS])
