"""Small deterministic planner for selecting relevant CTF pipelines."""
import os
import shutil


def capabilities():
    optional = {
        "nmap": shutil.which("nmap"),
        "ffuf": shutil.which("ffuf"),
        "curl": shutil.which("curl"),
        "sqlmap": shutil.which("sqlmap"),
        "hashcat": shutil.which("hashcat"),
        "john": shutil.which("john"),
        "radare2": shutil.which("r2"),
        "file": shutil.which("file"),
        "binwalk": shutil.which("binwalk"),
        "tshark": shutil.which("tshark"),
        "7z": shutil.which("7z") or shutil.which("7zz"),
        "exiftool": shutil.which("exiftool"),
        "tesseract": shutil.which("tesseract"),
        "zbarimg": shutil.which("zbarimg"),
        "zsteg": shutil.which("zsteg"),
        "identify": shutil.which("identify"),
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
        head = handle.read(512)
    signatures = ((b"PK", "zip/office"), (b"\x1f\x8b", "gzip"),
                  (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"),
                  (b"\x89PNG", "image"), (b"\xff\xd8\xff", "image"),
                  (b"GIF8", "image"), (b"BM", "image"),
                  (b"II\x2a\x00", "image"), (b"MM\x00\x2a", "image"),
                  (b"%PDF", "pdf"),
                  (b"\x7fELF", "elf"), (b"MZ", "pe"),
                  (b"SQLite format 3", "sqlite"), (b"\x0a\x0d\x0d\x0a", "pcapng"),
                  (b"\xd4\xc3\xb2\xa1", "pcap"), (b"\xa1\xb2\xc3\xd4", "pcap"),
                  (b"\x4d\x3c\xb2\xa1", "pcap"), (b"\xa1\xb2\x3c\x4d", "pcap"))
    for signature, kind in signatures:
        if head.startswith(signature):
            return kind
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image"
    if head[257:262] == b"ustar":
        return "tar"
    try:
        with open(path, "rb") as handle:
            sample = handle.read(65536)
        text = sample.decode("utf-8")
        return "text" if not text or sum(c.isprintable() or c in '\r\n\t'
                                        for c in text) / len(text) >= 0.90 else "binary"
    except (OSError, UnicodeDecodeError):
        return "binary"


def plan(target):
    """Return a compact, explainable list of pipelines for a target."""
    if os.path.isfile(target):
        kind = artifact_kind(target)
        pipelines = ["artifact-magic", "strings", "crypto-decode"]
        if kind in {"zip/office", "gzip", "bzip2", "xz", "tar"}:
            pipelines.append("recursive-container")
        if kind in {"image"}:
            pipelines.append("image-forensics")
            pipelines.append("optional-image-tools")
        if kind in {"pcap", "pcapng"}:
            pipelines.append("pcap-network")
            if shutil.which("tshark"):
                pipelines.append("tshark-json-evidence")
        if kind == "text":
            try:
                from modules.logic.gpio import looks_like_logic_capture
                if looks_like_logic_capture(target):
                    pipelines.append("logic-analyzer")
            except Exception:
                pass
        if kind in {"elf", "pe", "binary"}:
            pipelines.extend(["binary-triage", "embedded-blobs"])
            if shutil.which("r2"):
                pipelines.append("radare2-static-summary")
            if shutil.which("7zz"):
                pipelines.append("7zz-archive-inventory")
        return {"kind": kind, "pipelines": pipelines}
    if str(target).startswith(("http://", "https://")):
        pipelines = ["web-recon", "route-discovery", "targeted-probes"]
        if shutil.which("ffuf"):
            pipelines.append("ffuf-bounded-directory-discovery")
        if shutil.which("curl"):
            pipelines.append("curl-raw-http-evidence")
        if shutil.which("sqlmap"):
            pipelines.append("sqlmap-low-risk-opt-in")
        return {"kind": "url", "pipelines": pipelines}
    return {"kind": "text", "pipelines": ["encoding-chain", "structured-crypto", "classic-and-xor"]}
