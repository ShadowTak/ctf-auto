"""Cross-artifact crypto correlation for challenge directories.

Only parses text/bytes and metadata; it never imports or executes challenge code.
"""
import hashlib
import os
import re


_INTEGER_RE = re.compile(r"(?im)\b(n|n1|n2|e|e1|e2|c|c1|c2|p|q|d|r|s|z|nonce|iv)\s*[=:]\s*(0x[0-9a-f]+|\d{2,})")
_HEX_RE = re.compile(r"(?i)\b[0-9a-f]{16,256}\b")


def collect(paths, max_files=256, max_bytes=8 * 1024 * 1024):
    """Return a normalized, bounded artifact inventory."""
    files = []
    for root in paths if isinstance(paths, (list, tuple, set)) else [paths]:
        if os.path.isfile(root):
            candidates = [root]
        elif os.path.isdir(root):
            candidates = [os.path.join(root, name) for name in os.listdir(root)]
        else:
            continue
        for path in candidates:
            if len(files) >= max_files or not os.path.isfile(path):
                break
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


def correlate(paths):
    """Find repeated modulus/nonce/hex values and likely related artifacts."""
    inventory = collect(paths)
    values = {}
    for item in inventory:
        text = item["data"].decode("utf-8", "replace")
        named = [(m.group(1).lower(), int(m.group(2), 0))
                 for m in _INTEGER_RE.finditer(text)]
        hexes = _HEX_RE.findall(text)
        for name, value in named:
            key = (name, str(value))
            values.setdefault(key, []).append(item["path"])
        for value in hexes:
            values.setdefault(("hex", value.lower()), []).append(item["path"])
    repeated = []
    for (kind, value), sources in values.items():
        if len(set(sources)) > 1:
            repeated.append({"kind": kind, "value": value,
                             "sources": sorted(set(sources))})
    return {"files": [{k: v for k, v in item.items() if k != "data"}
                      for item in inventory],
            "repeated": repeated,
            "hints": _hints(repeated)}


def _hints(repeated):
    hints = []
    for item in repeated:
        kind = item["kind"]
        if kind in {"n", "n1", "n2"}:
            hints.append("repeated RSA modulus candidate")
        elif kind in {"nonce", "iv"}:
            hints.append("reused nonce/IV candidate")
        elif kind in {"r", "s"}:
            hints.append("repeated signature component candidate")
        elif kind == "hex":
            hints.append("repeated hex payload candidate")
    return sorted(set(hints))
