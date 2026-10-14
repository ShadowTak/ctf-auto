"""Static vulnerability triage for ELF/PE binaries — *what kind of pwn is this?*

This never runs or exploits the target. It only reads the file and reports the
facts an operator uses to pick an approach:

* the compiled-in mitigations (NX, PIE, RELRO, stack canary);
* the dangerous libc calls it imports (``gets``/``system``/``printf`` …);
* suspicious author functions (``win``/``backdoor``/``get_flag`` …) and their
  addresses;
* shell and flag strings carried in the binary.

From those it names the most likely attack shape (ret2win, ret2system, format
string, shellcode-on-stack). pyelftools/pwntools do the parsing when present;
without them it degrades to a printable-string heuristic so a binary never
hard-fails an auto run.
"""
from __future__ import annotations

import os
import re
import tempfile

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"

# name -> why it matters. Split into input sources, memory-unsafe copies and
# command/exec sinks so the classifier can reason about an input→sink path.
DANGEROUS = {
    "gets": "unbounded stack read — classic stack overflow",
    "scanf": "%s without a width is an unbounded read",
    "__isoc99_scanf": "%s without a width is an unbounded read",
    "fscanf": "%s without a width is an unbounded read",
    "strcpy": "no bounds check on the copy",
    "strcat": "no bounds check on the append",
    "sprintf": "no bounds check on the format output",
    "vsprintf": "no bounds check on the format output",
    "memcpy": "length is attacker-reachable in many bugs",
    "read": "verify the length against the buffer",
    "printf": "format-string sink if the format is user-controlled",
    "fprintf": "format-string sink if the format is user-controlled",
    "snprintf": "format-string sink if the format is user-controlled",
    "dprintf": "format-string sink if the format is user-controlled",
    "syslog": "format-string sink",
    "system": "command-execution sink",
    "execve": "command-execution sink",
    "execl": "command-execution sink",
    "execlp": "command-execution sink",
    "popen": "command-execution sink",
    "mprotect": "can mark memory RWX for injected shellcode",
}
_INPUT = {"gets", "scanf", "__isoc99_scanf", "fscanf", "read"}
_EXEC = {"system", "execve", "execl", "execlp", "popen"}
_FORMAT = {"printf", "fprintf", "snprintf", "sprintf", "vsprintf", "dprintf",
           "syslog"}

# Author functions that practically shout "jump here". Matched case-insensitively
# as whole words/segments so ``main``/``window`` are not false positives.
# The *target* you redirect execution to — not the vulnerable function itself.
_WIN_WORDS = ("win", "backdoor", "giveshell", "getshell", "get_shell",
              "spawnshell", "shell", "flag", "getflag", "get_flag", "printflag",
              "print_flag", "cat_flag", "secret", "magic", "unlock",
              "backd00r", "pwnme", "gift")
_WIN_RE = re.compile(
    r"(?i)(?:^|[^a-z])(" + "|".join(re.escape(w) for w in _WIN_WORDS) +
    r")(?:$|[^a-z])")

SHELL_STRINGS = (b"/bin/sh", b"/bin/bash", b"/bin/dash", b"cat flag",
                 b"cat /flag", b"/flag", b"flag.txt", b"sh -c", b"cat flag.txt")


def _fmt_addr(value) -> str:
    try:
        return hex(int(value))
    except (TypeError, ValueError):
        return "0x0"


def triage_binary(data: bytes, name: str = "") -> dict:
    """Return a triage report for the binary in *data* (never raises)."""
    data = bytes(data or b"")
    if data[:4] == ELF_MAGIC:
        fmt = "elf"
    elif data[:2] == PE_MAGIC:
        fmt = "pe"
    else:
        fmt = "unknown"
    report = {
        "format": fmt, "name": name, "arch": None, "bits": None,
        "mitigations": {}, "dangerous_calls": [], "win_functions": [],
        "shell_strings": [], "format_string_risk": False,
        "summary": [], "notes": [],
    }
    if fmt == "elf":
        if not _triage_elf_pwntools(data, report):
            _triage_raw(data, report)
    elif fmt == "pe":
        report["notes"].append("PE binary: reporting strings only; "
                               "use a Windows pwn workflow for mitigations")
        _triage_raw(data, report)
    else:
        report["notes"].append("not a recognized ELF/PE executable")
        _triage_raw(data, report)
    _scan_shell_strings(data, report)
    classify(report)
    return report


def _triage_elf_pwntools(data: bytes, report: dict) -> bool:
    """Parse with pwntools. Returns False to fall back to the raw heuristic."""
    os.environ.setdefault("PWNLIB_NOTERM", "1")
    os.environ.setdefault("PWNLIB_SILENT", "1")
    try:
        from pwnlib.context import context
        from pwnlib.elf import ELF
    except Exception:
        return False
    context.log_level = "error"
    path = None
    try:
        fd, path = tempfile.mkstemp(prefix="ctf-pwn-")
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        elf = ELF(path, checksec=False)
    except Exception:
        if path and os.path.exists(path):
            os.unlink(path)
        return False
    try:
        report["arch"] = elf.arch
        report["bits"] = elf.bits
        report["mitigations"] = _mitigations(elf)
        imported, defined = _elf_symbols(elf)
        for name in sorted(imported | defined):
            if name in DANGEROUS:
                report["dangerous_calls"].append(
                    {"name": name, "why": DANGEROUS[name]})
        report["format_string_risk"] = bool(
            (imported | defined) & _FORMAT and (imported | defined) & _INPUT)
        report["win_functions"] = _win_functions(elf)
        report["notes"].append(
            "parsed with pwntools (" + ("stripped" if elf.statically_linked
            else "dynamic") + " " + str(elf.elftype) + ")")
        return True
    except Exception as exc:  # pragma: no cover - defensive
        report["notes"].append("pwntools parse degraded: " + type(exc).__name__)
        return False
    finally:
        if path and os.path.exists(path):
            os.unlink(path)


def _mitigations(elf) -> dict:
    def _safe(attr):
        try:
            return getattr(elf, attr)
        except Exception:
            return None
    relro = _safe("relro")
    return {
        "nx": _safe("nx"),
        "pie": _safe("pie"),
        "canary": _safe("canary"),
        "relro": (str(relro).lower() if relro else ("no" if relro is False
                                                    else None)),
    }


def _elf_symbols(elf):
    """Return (undefined-import names, defined-symbol names)."""
    imported, defined = set(), set()
    for section_name in (".symtab", ".dynsym"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            name = symbol.name
            if not name:
                continue
            if symbol["st_shndx"] == "SHN_UNDEF":
                imported.add(name)
            else:
                defined.add(name)
    # PLT/GOT relocations name the real imports of a stripped-ish binary.
    try:
        for name in getattr(elf, "plt", {}) or {}:
            imported.add(name)
        for name in getattr(elf, "got", {}) or {}:
            imported.add(name)
    except Exception:
        pass
    return imported, defined


def _win_functions(elf):
    seen = {}
    try:
        functions = dict(getattr(elf, "functions", {}) or {})
    except Exception:
        functions = {}
    for name, function in functions.items():
        if _is_win_name(name):
            address = getattr(function, "address", None)
            seen.setdefault(name, {"name": name, "addr": _fmt_addr(address)})
    # Fall back to the symbol table for binaries pwntools did not resolve as
    # functions (relocatable objects, odd symbol types).
    try:
        for name, address in (elf.symbols or {}).items():
            if name in seen:
                continue
            if _is_win_name(name):
                seen[name] = {"name": name, "addr": _fmt_addr(address)}
    except Exception:
        pass
    return list(seen.values())


def _is_win_name(name: str) -> bool:
    # Skip main and pwntools' synthetic ``plt.x``/``got.x`` aliases.
    if not name or name.lower() == "main" or "." in name:
        return False
    return bool(_WIN_RE.search(name))


_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")


def _triage_raw(data: bytes, report: dict):
    """No parser available: recover dangerous/win names from printable runs."""
    strings = {m.group(0).decode("ascii") for m in _ASCII_RUN.finditer(data)}
    for token in strings:
        if token in DANGEROUS and not any(
                d["name"] == token for d in report["dangerous_calls"]):
            report["dangerous_calls"].append(
                {"name": token, "why": DANGEROUS[token]})
        if _is_win_name(token) and len(token) <= 64:
            if not any(w["name"] == token for w in report["win_functions"]):
                report["win_functions"].append({"name": token, "addr": "0x0"})
    report["format_string_risk"] = bool(
        {d["name"] for d in report["dangerous_calls"]} & _FORMAT and
        {d["name"] for d in report["dangerous_calls"]} & _INPUT)


def _scan_shell_strings(data: bytes, report: dict):
    for needle in SHELL_STRINGS:
        start = data.find(needle)
        if start != -1 and not any(s["value"] == needle.decode()
                                   for s in report["shell_strings"]):
            report["shell_strings"].append(
                {"value": needle.decode(), "offset": start})


def classify(report: dict):
    """Fill ``report['summary']`` with the likely attack shapes (heuristic)."""
    mit = report.get("mitigations") or {}
    dangerous = {d["name"] for d in report.get("dangerous_calls", [])}
    wins = report.get("win_functions", [])
    shells = report.get("shell_strings", [])
    summary = report["summary"]

    overflow = bool(dangerous & _INPUT)
    no_canary = mit.get("canary") is False
    if wins and (overflow or no_canary):
        names = ", ".join(f"{w['name']} ({w['addr']})" for w in wins[:4])
        summary.append(
            "ret2win likely — redirect execution to author function(s): "
            + names + (". No stack canary, so a stack overflow reaches the "
                       "saved return address directly." if no_canary else "."))
    if dangerous & _EXEC and shells:
        sink = ", ".join(sorted(dangerous & _EXEC))
        shell = shells[0]["value"]
        summary.append(
            f"ret2system — {sink} is imported and '{shell}' is in the binary; "
            "a ROP chain can call it with that string.")
    if report.get("format_string_risk"):
        summary.append(
            "format string — a printf-family call with a reachable user format; "
            "leak the stack / canary or get an arbitrary write.")
    if mit.get("nx") is False:
        summary.append(
            "NX is disabled — injected shellcode on the stack/heap is executable.")
    if mit.get("pie") is False and report["format"] == "elf":
        summary.append(
            "no PIE — code addresses are fixed, so ROP/ret2win gadgets need no leak.")
    if mit.get("relro") in ("no", "partial") and dangerous & _FORMAT:
        summary.append(
            f"{mit.get('relro')} RELRO with a format/write primitive — the GOT "
            "is a viable overwrite target.")

    if not summary:
        if report["format"] == "unknown":
            summary.append("no ELF/PE structure found — treat as data, not a "
                           "pwn target.")
        else:
            bits = _mitigation_line(mit)
            summary.append("no obvious memory-safety sink found." +
                           (" " + bits if bits else ""))
    else:
        bits = _mitigation_line(mit)
        if bits:
            report["notes"].append("mitigations: " + bits)


def _mitigation_line(mit: dict) -> str:
    parts = []
    for key in ("nx", "pie", "canary"):
        value = mit.get(key)
        if value is None:
            continue
        parts.append(f"{key.upper()}={'on' if value else 'off'}")
    if mit.get("relro"):
        parts.append("RELRO=" + str(mit["relro"]))
    return " ".join(parts)
