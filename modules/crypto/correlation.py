"""Bounded cross-artifact crypto correlation.

Files are read as bytes and never executed. The output contains candidates and
hints only; mathematical solvers must verify any result before promotion.
"""
import hashlib
import os
import re

_INTEGER_RE = re.compile(
    r"(?im)(?:[\"']?)(n|n1|n2|n3|e|e1|e2|c|c1|c2|p|q|d|r|s|z|nonce|iv|tag|seed)"
    r"(?:[\"']?)\s*[=:]\s*[\"']?(0x[0-9a-f]+|\d+)"
)
_HEX_RE = re.compile(r"(?i)\b[0-9a-f]{16,512}\b")
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")

_ZIP_MAGIC = b"PK\x03\x04"
# Text-ish members worth reading out of a big archive (APK/Office/JAR).  A
# challenge answer often lives in AndroidManifest.xml or a resource table, and
# refusing the whole 30MB APK because of a size cap hides it completely.
_ARCHIVE_NAMES = {"androidmanifest.xml", "resources.arsc"}
_ARCHIVE_EXTS = (".xml", ".json", ".txt", ".properties", ".html", ".htm",
                 ".js", ".csv", ".md", ".yml", ".yaml", ".ini", ".conf")
_ARCHIVE_BUDGET = 12 * 1024 * 1024
_ARCHIVE_LIMIT = 40


def _archive_members(path, budget=_ARCHIVE_BUDGET, limit=_ARCHIVE_LIMIT):
    """Boundedly read text-ish members of a zip/apk without unpacking it all."""
    import zipfile
    out = []
    try:
        with zipfile.ZipFile(path) as archive:
            entries = sorted(archive.infolist(), key=lambda i: i.filename)
            for info in entries:
                if info.is_dir() or info.file_size > budget:
                    continue
                lower = info.filename.lower()
                if (os.path.basename(lower) not in _ARCHIVE_NAMES and
                        not lower.endswith(_ARCHIVE_EXTS)):
                    continue
                try:
                    data = archive.read(info)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    continue
                if not data:
                    continue
                out.append((info.filename, data))
                budget -= len(data)
                if budget <= 0 or len(out) >= limit:
                    break
    except (OSError, zipfile.BadZipFile):
        return []
    return out


def _is_zip(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == _ZIP_MAGIC
    except OSError:
        return False


def collect(paths, max_files=256, max_bytes=8 * 1024 * 1024):
    """Return a deterministic, bounded recursive artifact inventory."""
    roots = paths if isinstance(paths, (list, tuple, set)) else [paths]
    def candidates():
        for root in roots:
            if os.path.islink(root):
                continue
            if os.path.isfile(root):
                yield os.fspath(root)
            elif os.path.isdir(root):
                for current, dirs, names in os.walk(root):
                    dirs[:] = sorted(d for d in dirs if not d.startswith('.') and
                                     d not in {'node_modules', 'venv', '__pycache__'} and
                                     not os.path.islink(os.path.join(current, d)))
                    for name in sorted(names):
                        if not name.startswith('.'):
                            yield os.path.join(current, name)
    files = []
    seen = set()
    total = 0
    for index, path in enumerate(candidates()):
        if len(files) >= max_files or index >= max_files * 8:
            break
        if path in seen or os.path.islink(path) or not os.path.isfile(path):
            continue
        seen.add(path)
        try:
            size = os.path.getsize(path)
            if size > max_bytes or total + size > 64 * 1024 * 1024:
                # Oversized archives still get a look: read only their text-ish
                # members so a 30MB APK or Office document is not invisible.
                if size > max_bytes and len(files) + 1 < max_files and _is_zip(path):
                    for name, data in _archive_members(path):
                        files.append({"path": path + ":" + name, "size": len(data),
                                      "sha256": hashlib.sha256(data).hexdigest(),
                                      "data": data})
                        total += len(data)
                        if len(files) >= max_files:
                            break
                continue
            with open(path, "rb") as handle:
                data = handle.read(max_bytes + 1)
        except OSError:
            continue
        if len(data) > max_bytes:
            continue
        total += len(data)
        files.append({"path": path, "size": size,
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "data": data})
    return files


def _value_key(kind, value):
    return kind, str(value) if kind == "base64" else str(value).lower()


def correlate(paths, max_files=256, max_bytes=8 * 1024 * 1024):
    """Find repeated parameters, nonces, blobs, and likely relationships."""
    inventory = collect(paths, max_files=max_files, max_bytes=max_bytes)
    values = {}
    records = []
    for item in inventory:
        text = item["data"].decode("utf-8", "replace")
        named = [(m.group(1).lower(), int(m.group(2),
                  16 if m.group(2).lower().startswith('0x') else 10))
                 for m in list(_INTEGER_RE.finditer(text))[:256]
                 if len(m.group(2)) <= 2400]
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
    moduli = moduli[:64]
    for index, (left, left_path) in enumerate(moduli):
        for right, right_path in moduli[index + 1:]:
            common = __import__("math").gcd(left, right)
            if 1 < common < min(left, right):
                shared_factors.append({"gcd": common,
                                       "sources": sorted({left_path, right_path})})
    from .rsa_bundle import solve_inventory
    solutions = solve_inventory(inventory)
    return {"files": [{k: v for k, v in item.items() if k != "data"}
                      for item in inventory],
            "repeated": repeated,
            "shared_factors": shared_factors,
            "solutions": solutions,
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
