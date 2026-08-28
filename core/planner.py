"""Small deterministic planner for selecting relevant CTF pipelines."""
import os
import shutil


def capabilities():
    optional = {
        "nmap": shutil.which("nmap"),
        "file": shutil.which("file"),
        "binwalk": shutil.which("binwalk"),
        "tshark": shutil.which("tshark"),
        "7z": shutil.which("7z") or shutil.which("7zz"),
        "exiftool": shutil.which("exiftool"),
        "z3": _module("z3"),
        "sympy": _module("sympy"),
        "Pillow": _module("PIL"),
        "playwright": _module("playwright"),
        "pycryptodome": _module("Crypto"),
    }
    return {name: bool(value) for name, value in optional.items()}


def _module(name):
    try:
        __import__(name)
        return True
    except Exception:
        return False


def artifact_kind(path):
    if not path or not os.path.isfile(path):
        return "text"
    with open(path, "rb") as handle:
        head = handle.read(32)
    signatures = ((b"PK", "zip/office"), (b"\x1f\x8b", "gzip"),
                  (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"),
                  (b"\x89PNG", "image"), (b"\xff\xd8\xff", "image"),
                  (b"GIF8", "image"), (b"%PDF", "pdf"),
                  (b"\x7fELF", "elf"), (b"MZ", "pe"),
                  (b"SQLite format 3", "sqlite"), (b"\x0a\x0d\x0d\x0a", "pcapng"),
                  (b"\xd4\xc3\xb2\xa1", "pcap"), (b"\xa1\xb2\xc3\xd4", "pcap"))
    for signature, kind in signatures:
        if head.startswith(signature):
            return kind
    try:
        with open(path, "rb") as handle:
            sample = handle.read(65536)
        sample.decode("utf-8")
        return "text"
    except (OSError, UnicodeDecodeError):
        return "binary"


def plan(target):
    """Return a compact, explainable list of pipelines for a target."""
    if os.path.isfile(target):
        kind = artifact_kind(target)
        pipelines = ["artifact-magic", "strings", "crypto-decode"]
        if kind in {"zip/office", "gzip", "bzip2", "xz"}:
            pipelines.append("recursive-container")
        if kind in {"image"}:
            pipelines.append("image-forensics")
        if kind in {"pcap", "pcapng"}:
            pipelines.append("pcap-network")
        if kind in {"elf", "pe", "binary"}:
            pipelines.extend(["binary-triage", "embedded-blobs"])
        return {"kind": kind, "pipelines": pipelines}
    if str(target).startswith(("http://", "https://")):
        return {"kind": "url", "pipelines": ["web-recon", "route-discovery", "targeted-probes"]}
    return {"kind": "text", "pipelines": ["encoding-chain", "structured-crypto", "classic-and-xor"]}
