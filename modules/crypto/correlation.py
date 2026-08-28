"""Bounded cross-artifact crypto correlation.

Files are read as bytes and never executed. The output contains candidates and
hints only; mathematical solvers must verify any result before promotion.
"""
import hashlib
import os
import re

_INTEGER_RE = re.compile(
    r"(?im)(?:[\"']?)(n|n1|n2|n3|e|e1|e2|c|c1|c2|p|q|d|r|s|z|nonce|iv|tag|seed)"
    r"(?:[\"']?)\s*[=:]\s*(0x[0-9a-f]+|\d{2,})"
)
_HEX_RE = re.compile(r"(?i)\b[0-9a-f]{16,512}\b")
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def collect(paths, max_files=256, max_bytes=8 * 1024 * 1024):
    """Return a deterministic, bounded recursive artifact inventory."""
    roots = paths if isinstance(paths, (list, tuple, set)) else [paths]
    candidates = []
    for root in roots:
        if os.path.isfile(root):
            candidates.append(root)
        elif os.path.isdir(root):
            for current, dirs, names in os.walk(root):
                dirs.sort()
                for name in sorted(names):
                    candidates.append(os.path.join(current, name))
    files = []
    seen = set()
    for path in candidates:
        if len(files) >= max_files or path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        try:
            size = os.path.getsize(path)
            if size > max_bytes:
                continue
            with open(path, "rb") as handle:
                data = handle.read(max_bytes + 1)
        except OSError:
            continue
        files.append({"path": path, "size": size,
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "data": data})
    return files


def _value_key(kind, value):
    return kind, str(value).lower()


def correlate(paths, max_files=256, max_bytes=8 * 1024 * 1024):
    """Find repeated parameters, nonces, blobs, and likely relationships."""
    inventory = collect(paths, max_files=max_files, max_bytes=max_bytes)
    values = {}
    records = []
    for item in inventory:
        text = item["data"].decode("utf-8", "replace")
        named = [(m.group(1).lower(), int(m.group(2), 0))
                 for m in _INTEGER_RE.finditer(text)]
        for name, value in named:
            key = _value_key(name, value)
            values.setdefault(key, set()).add(item["path"])
            records.append((name, value, item["path"]))
        for value in _HEX_RE.findall(text):
            values.setdefault(_value_key("hex", value), set()).add(item["path"])
        for value in _B64_RE.findall(text):
            values.setdefault(_value_key("base64", value), set()).add(item["path"])
    repeated = [{"kind": kind, "value": value,
                 "sources": sorted(sources)}
                for (kind, value), sources in values.items()
                if len(sources) > 1]
    repeated.sort(key=lambda x: (x["kind"], x["value"]))
    hints = _hints(repeated)
    # A shared RSA prime is stronger than a repeated label: calculate gcd for
    # pairs of sufficiently large n values and expose only the evidence.
    moduli = [(value, path) for kind, value, path in records
              if kind in {"n", "n1", "n2", "n3"} and value > 2]
    shared_factors = []
    for index, (left, left_path) in enumerate(moduli):
        for right, right_path in moduli[index + 1:]:
            common = __import__("math").gcd(left, right)
            if 1 < common < min(left, right):
                shared_factors.append({"gcd": common,
                                       "sources": sorted({left_path, right_path})})
    return {"files": [{k: v for k, v in item.items() if k != "data"}
                      for item in inventory],
            "repeated": repeated,
            "shared_factors": shared_factors,
            "hints": sorted(set(hints + (["shared RSA prime candidate"]
                                           if shared_factors else [])))}


def _hints(repeated):
    hints = []
    for item in repeated:
        kind = item["kind"]
        if kind in {"n", "n1", "n2", "n3"}:
            hints.append("repeated RSA modulus candidate")
        elif kind in {"nonce", "iv", "seed"}:
            hints.append("reused nonce/IV/seed candidate")
        elif kind in {"r", "s"}:
            hints.append("repeated signature component candidate")
        elif kind in {"hex", "base64"}:
            hints.append("repeated encoded payload candidate")
    return hints
