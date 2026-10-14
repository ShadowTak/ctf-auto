"""Static pwn triage: mitigations, dangerous imports, win funcs, shell strings.

The integration case compiles a real Linux ELF with clang's cross target. On a
host where clang cannot emit a linux object it is skipped — the pure
classification logic is still covered unconditionally.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.reverse import pwn_triage


def test_not_an_executable_is_graceful():
    report = pwn_triage.triage_binary(b"just some text, not a binary", "note.txt")
    assert report["format"] == "unknown"
    assert report["win_functions"] == []
    assert report["summary"]  # still explains why there's nothing to do


def test_shell_string_detection_on_raw_bytes():
    blob = b"\x7fELF" + b"\x00" * 40 + b"/bin/sh\x00padding cat /flag.txt here"
    report = pwn_triage.triage_binary(blob, "x")
    values = {s["value"] for s in report["shell_strings"]}
    assert "/bin/sh" in values


def test_classify_ret2win():
    report = {
        "format": "elf", "arch": "amd64", "bits": 64,
        "mitigations": {"nx": True, "pie": False, "canary": False, "relro": "partial"},
        "dangerous_calls": [{"name": "gets", "why": "unbounded"}],
        "win_functions": [{"name": "win", "addr": "0x401196"}],
        "shell_strings": [], "format_string_risk": False,
        "summary": [], "notes": [],
    }
    pwn_triage.classify(report)
    joined = " ".join(report["summary"]).lower()
    assert "ret2win" in joined
    assert "win" in joined and "0x401196" in joined
    assert "canary" in joined  # the missing-canary observation is surfaced


def test_classify_format_string_and_shell():
    report = {
        "format": "elf", "arch": "amd64", "bits": 64,
        "mitigations": {"nx": False, "pie": False, "canary": False, "relro": "no"},
        "dangerous_calls": [{"name": "printf", "why": "fmt"},
                            {"name": "system", "why": "exec"}],
        "win_functions": [],
        "shell_strings": [{"value": "/bin/sh", "offset": 16}],
        "format_string_risk": True, "summary": [], "notes": [],
    }
    pwn_triage.classify(report)
    joined = " ".join(report["summary"]).lower()
    assert "format string" in joined
    assert "nx" in joined  # NX-off shellcode path noted


def _clang_can_target_linux(tmp):
    clang = shutil.which("clang")
    if not clang:
        return None
    src = tmp / "t.c"
    src.write_text(
        "int printf(const char*,...);int system(const char*);char*gets(char*);\n"
        'char sh[]="/bin/sh";\n'
        "void win(void){system(sh);}\n"
        "int vuln(void){char b[64];gets(b);return 0;}\n"
        "int main(void){printf(\"hi\");vuln();return 0;}\n")
    obj = tmp / "t.o"
    proc = subprocess.run(
        [clang, "--target=x86_64-linux-gnu", "-c", "-fno-stack-protector",
         str(src), "-o", str(obj)],
        capture_output=True)
    return obj if proc.returncode == 0 and obj.exists() else None


def test_real_elf_triage(tmp_path):
    obj = _clang_can_target_linux(tmp_path)
    if obj is None:
        pytest.skip("clang cannot emit a linux ELF object on this host")
    report = pwn_triage.triage_binary(obj.read_bytes(), "t.o")
    assert report["format"] == "elf"
    assert report["arch"] == "amd64" and report["bits"] == 64
    wins = {w["name"] for w in report["win_functions"]}
    assert "win" in wins
    dangerous = {d["name"] for d in report["dangerous_calls"]}
    assert "gets" in dangerous and "system" in dangerous
    assert any(s["value"] == "/bin/sh" for s in report["shell_strings"])
