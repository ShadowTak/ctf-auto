"""Hard-mode crypto capability and adapter orchestration.

The module does not fabricate results: external tools are invoked only when
explicitly requested by the caller and all output remains candidate evidence.
"""
import shutil
import subprocess


def backend_status():
    status = {}
    for name, module in (("z3", "z3"), ("sympy", "sympy"),
                         ("fpylll", "fpylll"), ("sage", "sageall"),
                         ("Crypto", "Crypto")):
        try:
            __import__(module)
            status[name] = True
        except Exception:
            status[name] = False
    for name in ("hashcat", "john", "7z", "binwalk", "tshark"):
        status[name] = bool(shutil.which("7z") or shutil.which("7zz")) if name == "7z" else bool(shutil.which(name))
    return status


def choose_backends(requested="auto"):
    status = backend_status()
    if requested == "stdlib":
        return ["stdlib"]
    selected = ["stdlib"]
    if status.get("sympy"):
        selected.append("sympy")
    if status.get("z3"):
        selected.append("z3")
    if status.get("fpylll"):
        selected.append("fpylll")
    if status.get("sage"):
        selected.append("sage")
    return selected


def external_cracker_commands(hash_file, wordlist, tool="auto"):
    """Return an explicit command description; does not execute it."""
    if tool in ("auto", "hashcat") and shutil.which("hashcat"):
        return ["hashcat", "-m", "0", "-a", "0", hash_file, wordlist]
    if tool in ("auto", "john") and shutil.which("john"):
        return ["john", f"--wordlist={wordlist}", hash_file]
    return None


def run_external_cracker(hash_file, wordlist, tool="auto", timeout=120):
    """Run a user-requested local cracker with a hard timeout."""
    command = external_cracker_commands(hash_file, wordlist, tool)
    if command is None:
        return {"status": "unavailable", "command": None, "output": ""}
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=max(1, int(timeout)))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "command": command, "output": str(exc)}
    return {"status": "done" if result.returncode == 0 else "failed",
            "command": command,
            "output": (result.stdout + "\n" + result.stderr)[:20000]}
