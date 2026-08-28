"""Generic line-oriented TCP runner for authorized CTF services.

This is intentionally a transport/helper, not arbitrary remote code execution:
it connects, records a bounded transcript, optionally sends explicit lines,
and extracts flag-shaped output.
"""
import re
import socket
import time

from core.flag import extract_flags


def parse_target(target):
    value = str(target).strip()
    if ":" not in value:
        raise ValueError("service target must be host:port")
    host, port = value.rsplit(":", 1)
    return host.strip("[]"), int(port)


def run(target, lines=(), timeout=5, max_bytes=65536, prompt=None):
    host, port = parse_target(target)
    transcript = bytearray()
    sent = []
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        for line in lines or ():
            payload = str(line).encode() + b"\n"
            sock.sendall(payload)
            sent.append(str(line))
        deadline = time.monotonic() + timeout
        while len(transcript) < max_bytes and time.monotonic() < deadline:
            try:
                chunk = sock.recv(min(4096, max_bytes - len(transcript)))
            except socket.timeout:
                break
            if not chunk:
                break
            transcript.extend(chunk)
            text = transcript.decode("utf-8", "replace")
            if prompt and re.search(prompt, text):
                break
    text = transcript.decode("utf-8", "replace")
    known, candidates = extract_flags(text)
    return {"target": target, "sent": sent, "transcript": text,
            "flags": list(dict.fromkeys(known + candidates))}
