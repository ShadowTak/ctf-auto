"""Bounded adapters for optional command-line reconnaissance tools.

The adapters deliberately use argument lists (never a shell), hard timeouts,
and small JSON/XML parsers.  They are opt-in from the CLI/web scanner so a
normal scan keeps its existing fast, pure-Python behavior.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FFUF_WORDLIST = ROOT / "wordlists" / "common.txt"
TOOL_BINARIES = {
    "nmap": "nmap",
    "ffuf": "ffuf",
    "tshark": "tshark",
    "curl": "curl",
    "hashcat": "hashcat",
    "john": "john",
    "sqlmap": "sqlmap",
    "radare2": "r2",
    "exiftool": "exiftool",
    "tesseract": "tesseract",
    "zbarimg": "zbarimg",
    "zsteg": "zsteg",
    "binwalk": "binwalk",
    "identify": "identify",
    "7zz": "7zz",
}
TOOL_ALIASES = {"r2": "radare2", "7z": "7zz", "7zip": "7zz"}
KNOWN_TOOLS = tuple(TOOL_BINARIES)
MAX_OUTPUT = 2 * 1024 * 1024


def normalize_tools(value):
    """Return a stable, validated tuple of requested external tools."""
    if value is None:
        return ()
    if isinstance(value, str):
        values = re.split(r"[\s,]+", value)
    else:
        values = value
    out = []
    for item in values or ():
        name = str(item or "").strip().lower()
        name = TOOL_ALIASES.get(name, name)
        if name in KNOWN_TOOLS and name not in out:
            out.append(name)
    return tuple(out)


def available_tools():
    return {name: shutil.which(binary)
            for name, binary in TOOL_BINARIES.items()}


def _bounded(value, low, high, default):
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(low, min(high, number))


def _kill_process(process):
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


def _run(command, timeout):
    """Run one external command with a process-group deadline."""
    started = time.monotonic()
    timeout = max(1, float(timeout))
    try:
        process = subprocess.Popen(
            list(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, errors="replace",
            start_new_session=(os.name == "posix"),
        )
    except FileNotFoundError:
        return {"status": "missing", "command": list(command), "stdout": "",
                "stderr": "tool not found", "elapsed_ms": 0}
    except OSError as exc:
        return {"status": "error", "command": list(command), "stdout": "",
                "stderr": str(exc), "elapsed_ms": 0}
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        status = "completed" if process.returncode == 0 else "error"
    except subprocess.TimeoutExpired:
        _kill_process(process)
        stdout, stderr = process.communicate()
        status = "timeout"
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    return {
        "status": status,
        "returncode": process.returncode,
        "command": list(command),
        "stdout": (stdout or "")[:MAX_OUTPUT],
        "stderr": (stderr or "")[:MAX_OUTPUT],
        "elapsed_ms": elapsed_ms,
    }


def _port_spec(ports):
    if ports is None or ports == "":
        return None
    if isinstance(ports, str):
        raw = ports.strip()
        if not re.fullmatch(r"[0-9,\-]+", raw):
            raise ValueError("nmap ports must contain only numbers, commas, and ranges")
        parts = raw.split(",")
    else:
        parts = [str(item) for item in ports]
    normalized = []
    for part in parts:
        if "-" in part:
            left, right = part.split("-", 1)
            a, b = int(left), int(right)
            if not 1 <= a <= b <= 65535:
                raise ValueError("nmap port range must be between 1 and 65535")
            normalized.append(f"{a}-{b}")
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError("nmap port must be between 1 and 65535")
            normalized.append(str(port))
    return ",".join(normalized)


def run_nmap(target, *, ports=None, top_ports=1000, service=True,
             scripts=None, timeout=45):
    """Run nmap to XML stdout and return normalized service evidence."""
    binary = shutil.which("nmap")
    if not binary:
        return {"status": "missing", "tool": "nmap", "hosts": [],
                "services": {}, "raw_xml": "", "stderr": "nmap not found"}
    target = str(target or "").strip()
    if not target or any(ch in target for ch in ("\x00", "\n", "\r")):
        raise ValueError("nmap target must be a single non-empty host")
    command = [binary, "-Pn", "-T4", "--open", "-oX", "-"]
    if service:
        command.extend(("-sV", "--version-light"))
    port_spec = _port_spec(ports)
    if port_spec:
        command.extend(("-p", port_spec))
    else:
        command.extend(("--top-ports", str(_bounded(top_ports, 1, 10000, 1000))))
    if scripts:
        script_value = ",".join(
            name for name in re.split(r"[\s,]+", str(scripts))
            if re.fullmatch(r"[A-Za-z0-9_.+-]+", name or "")
        )
        if script_value:
            command.extend(("--script", script_value))
    command.append(target)
    result = _run(command, _bounded(timeout, 1, 600, 45))
    raw_xml = result.get("stdout", "")
    hosts, services = [], {}
    if raw_xml:
        try:
            from modules.network import nmap_xml
            hosts = nmap_xml.parse_xml(raw_xml.encode())
            services = nmap_xml.flatten_services(raw_xml.encode())
        except Exception as exc:  # preserve raw output for diagnostics
            result["parse_error"] = type(exc).__name__ + ": " + str(exc)
    result.update(tool="nmap", hosts=hosts, services=services, raw_xml=raw_xml)
    return result


def _ffuf_json(text):
    text = str(text or "").strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
        if isinstance(value, list):
            return {"results": value}
        return value
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
    records = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return {"results": records} if records else {}


def _ffuf_target(url):
    value = str(url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("ffuf target must be an http(s) URL")
    if "FUZZ" in value:
        return value
    return value.rstrip("/") + "/FUZZ"


def run_ffuf(url, *, wordlist=None, timeout=45, threads=40,
             status_codes="200,204,301,302,307,401,403,405,500"):
    """Run ffuf JSON output and return bounded, normalized hit evidence."""
    binary = shutil.which("ffuf")
    if not binary:
        return {"status": "missing", "tool": "ffuf", "hits": [],
                "stderr": "ffuf not found"}
    wordlist = Path(wordlist or DEFAULT_FFUF_WORDLIST).expanduser()
    if not wordlist.is_file():
        return {"status": "error", "tool": "ffuf", "hits": [],
                "stderr": f"wordlist not found: {wordlist}"}
    target = _ffuf_target(url)
    timeout = _bounded(timeout, 1, 600, 45)
    threads = _bounded(threads, 1, 128, 40)
    codes = ",".join(
        item for item in re.split(r"[\s,]+", str(status_codes))
        if item.isdigit() and 100 <= int(item) <= 599
    ) or "200,204,301,302,307,401,403,405,500"
    # Current ffuf releases expose newline-delimited JSON via ``-json``;
    # using ``-of json -o -`` only prints human-readable hits on some builds.
    command = [binary, "-u", target, "-w", str(wordlist), "-json", "-s",
               "-t", str(threads), "-timeout",
               str(min(15, timeout)), "-maxtime", str(timeout), "-mc", codes]
    result = _run(command, timeout + 5)
    payload = _ffuf_json(result.get("stdout", ""))
    hits = []
    for item in payload.get("results", []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        raw_input = item.get("input", {})
        if isinstance(raw_input, dict):
            path = raw_input.get("FUZZ", "")
        else:
            path = raw_input
        url_value = str(item.get("url", ""))
        # ffuf -json base64-encodes the input token on recent releases.  The
        # rendered URL is the authoritative, already-decoded value.
        if url_value:
            parsed_url = urlparse(url_value)
            path = parsed_url.path.lstrip("/") or path
        hit = {
            "path": str(path),
            "url": url_value,
            "status": int(item.get("status", 0) or 0),
            "size": int(item.get("length", item.get("size", 0)) or 0),
            "words": int(item.get("words", 0) or 0),
            "lines": int(item.get("lines", 0) or 0),
            "content_type": str(item.get("content-type", "")),
            "redirect": str(item.get("redirectlocation", "")),
        }
        if hit["path"] or hit["url"]:
            hits.append(hit)
    result.update(tool="ffuf", hits=hits, raw_json=payload)
    return result


def ffuf_dir_results(report):
    """Convert ffuf hits to the legacy DirBuster tuple shape."""
    out = []
    for hit in (report or {}).get("hits", []):
        path = hit.get("path") or hit.get("url")
        if not path:
            continue
        note = ""
        if hit.get("redirect"):
            note = " -> " + hit["redirect"][:100]
        out.append((str(path).lstrip("/"), int(hit.get("status", 0) or 0),
                    int(hit.get("size", 0) or 0), note))
    return out


def _binary_for(tool):
    names = normalize_tools(tool)
    if not names:
        return None, None
    name = names[0]
    return name, shutil.which(TOOL_BINARIES[name])


def _file_target(path):
    value = Path(path or "").expanduser()
    if not value.is_file():
        raise FileNotFoundError(str(value))
    return value


def _validate_url(url):
    value = str(url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("target must be an http(s) URL")
    if any(char in value for char in ("\x00", "\n", "\r")):
        raise ValueError("target contains a control character")
    return value


def run_curl(url, *, timeout=45, headers=(), method="GET"):
    """Fetch one URL with curl and preserve headers/body as raw evidence."""
    binary = shutil.which(TOOL_BINARIES["curl"])
    if not binary:
        return {"status": "missing", "tool": "curl", "stdout": "",
                "stderr": "curl not found"}
    target = _validate_url(url)
    method = str(method or "GET").upper()
    if not re.fullmatch(r"[A-Z]{1,12}", method):
        raise ValueError("curl method must be an uppercase HTTP token")
    command = [binary, "--silent", "--show-error", "--location",
               "--connect-timeout", str(min(15, _bounded(timeout, 1, 600, 45))),
               "--max-time", str(_bounded(timeout, 1, 600, 45)),
               "--dump-header", "-", "--request", method,
               "--user-agent", "ctf-auto/1.0", target]
    for key, value in (headers.items() if isinstance(headers, dict) else headers or ()):
        key, value = str(key), str(value)
        if not key or any(char in key + value for char in ("\x00", "\n", "\r")):
            raise ValueError("curl headers cannot contain control characters")
        command.extend(("--header", f"{key}: {value}"))
    result = _run(command, _bounded(timeout, 1, 600, 45))
    result.update(tool="curl", url=target, raw_output=result.get("stdout", ""))
    return result


def run_sqlmap(url, *, timeout=45, threads=4):
    """Run a low-risk, non-dumping sqlmap probe against an explicit URL."""
    binary = shutil.which(TOOL_BINARIES["sqlmap"])
    if not binary:
        return {"status": "missing", "tool": "sqlmap", "stdout": "",
                "stderr": "sqlmap not found"}
    target = _validate_url(url)
    threads = _bounded(threads, 1, 16, 4)
    timeout = _bounded(timeout, 1, 600, 45)
    with tempfile.TemporaryDirectory(prefix="ctf-auto-sqlmap-") as output_dir:
        command = [binary, "-u", target, "--batch", "--smart", "--level=1",
                   "--risk=1", "--threads", str(threads), "--timeout", "5",
                   "--retries", "0", "--time-sec", "1", "--disable-coloring",
                   "--output-dir", output_dir]
        result = _run(command, timeout)
    result.update(tool="sqlmap", url=target,
                  raw_output=(result.get("stdout", "") + "\n" + result.get("stderr", "")).strip())
    return result


def run_tshark(path, *, timeout=45, display_filter=None, packet_limit=200):
    """Read a bounded packet sample with tshark JSON output."""
    target = _file_target(path)
    binary = shutil.which(TOOL_BINARIES["tshark"])
    if not binary:
        return {"status": "missing", "tool": "tshark", "packets": [],
                "stderr": "tshark not found"}
    command = [binary, "-n", "-r", str(target), "-T", "json", "-c",
               str(_bounded(packet_limit, 1, 2000, 200))]
    if display_filter:
        value = str(display_filter)
        if any(char in value for char in ("\x00", "\n", "\r")):
            raise ValueError("tshark display filter contains a control character")
        command.extend(("-Y", value))
    result = _run(command, _bounded(timeout, 1, 600, 45))
    packets = []
    if result.get("stdout"):
        try:
            parsed = json.loads(result["stdout"])
            packets = parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError as exc:
            result["parse_error"] = str(exc)
    result.update(tool="tshark", path=str(target), packets=packets,
                  raw_json=result.get("stdout", ""))
    return result


def run_hash_cracker(tool, hash_file, wordlist, *, timeout=120, hash_mode=0):
    """Run hashcat or John with an isolated potfile and a hard deadline."""
    name, binary = _binary_for(tool)
    if name not in {"hashcat", "john"}:
        raise ValueError("hash cracker must be hashcat or john")
    target = _file_target(hash_file)
    if not wordlist:
        return {"status": "error", "tool": name, "hash_file": str(target),
                "stdout": "", "stderr": "wordlist is required"}
    words = _file_target(wordlist)
    if not binary:
        return {"status": "missing", "tool": name, "stdout": "",
                "stderr": f"{name} not found"}
    with tempfile.TemporaryDirectory(prefix="ctf-auto-cracker-") as state_dir:
        if name == "hashcat":
            command = [binary, "-m", str(_bounded(hash_mode, 0, 99999, 0)),
                       "-a", "0", str(target), str(words), "--quiet",
                       "--potfile-disable"]
        else:
            potfile = str(Path(state_dir) / "john.pot")
            command = [binary, f"--wordlist={words}", f"--pot={potfile}",
                       str(target)]
        result = _run(command, _bounded(timeout, 1, 600, 120))
    result.update(tool=name, hash_file=str(target), wordlist=str(words),
                  raw_output=(result.get("stdout", "") + "\n" + result.get("stderr", "")).strip())
    return result


FILE_TOOL_ARGS = {
    "exiftool": lambda binary, path: [binary, "-j", "--", str(path)],
    "identify": lambda binary, path: [binary, "-verbose", str(path)],
    "tesseract": lambda binary, path: [binary, str(path), "stdout", "--psm", "6"],
    "zbarimg": lambda binary, path: [binary, "--raw", "--quiet", "--", str(path)],
    "zsteg": lambda binary, path: [binary, "-a", str(path)],
    "binwalk": lambda binary, path: [binary, "--signature", "--quiet", str(path)],
    "radare2": lambda binary, path: [binary, "-q", "-2", "-e", "scr.color=false",
                                      "-c", "aaa;afl;izz;ii", str(path)],
    "7zz": lambda binary, path: [binary, "l", "-slt", str(path)],
}


def run_file_tool(tool, path, *, timeout=45):
    """Run one bounded file-analysis tool and preserve its raw output."""
    name, binary = _binary_for(tool)
    if name not in FILE_TOOL_ARGS:
        raise ValueError(f"unsupported file tool: {tool}")
    target = _file_target(path)
    if not binary:
        return {"status": "missing", "tool": name, "path": str(target),
                "stdout": "", "stderr": f"{name} not found"}
    result = _run(FILE_TOOL_ARGS[name](binary, target),
                  _bounded(timeout, 1, 600, 45))
    result.update(tool=name, path=str(target), raw_output=(
        result.get("stdout", "") + "\n" + result.get("stderr", "")).strip())
    return result


def run_external_tool(tool, target, *, wordlist=None, timeout=45, **kwargs):
    """Dispatch one allowlisted external tool without invoking a shell."""
    name = normalize_tools(tool)
    if not name:
        raise ValueError(f"unsupported external tool: {tool}")
    name = name[0]
    if name == "nmap":
        return run_nmap(target, ports=kwargs.get("ports"),
                        top_ports=kwargs.get("top_ports", 1000),
                        service=kwargs.get("service", True), timeout=timeout)
    if name == "ffuf":
        return run_ffuf(target, wordlist=wordlist, timeout=timeout,
                        threads=kwargs.get("threads", 40))
    if name == "curl":
        return run_curl(target, timeout=timeout, headers=kwargs.get("headers", ()))
    if name == "sqlmap":
        return run_sqlmap(target, timeout=timeout, threads=kwargs.get("threads", 4))
    if name == "tshark":
        return run_tshark(target, timeout=timeout,
                          display_filter=kwargs.get("display_filter"))
    if name in {"hashcat", "john"}:
        return run_hash_cracker(name, target, wordlist, timeout=timeout,
                                hash_mode=kwargs.get("hash_mode", 0))
    return run_file_tool(name, target, timeout=timeout)
