"""Bounded network intelligence helpers for CTF triage.

This module is intentionally passive: it extracts and ranks indicators from
already-collected content, leaving active probing to the existing scanner.
"""
import base64
import binascii
import ipaddress
import re
import urllib.parse

from core.flag import extract_flags

_URL_RE = re.compile(r"https?://[^\s\"'<>`]+", re.I)
_ROUTE_RE = re.compile(r"(?<![\w])/(?:[A-Za-z0-9._~:@%+\-]+/)*[A-Za-z0-9._~:@%+\-]*(?:\?[A-Za-z0-9._~:@%+\-&=/%]*)?", re.I)
_SECRET_RE = re.compile(r"(?i)\b(?:token|secret|api[_-]?key|password|passwd|authorization|bearer)\b\s*[:=]\s*([^\s,;\"']{4,160})")
_SUSPICIOUS_WORDS = {
    "admin", "administrator", "debug", "internal", "private", "backup",
    "config", "graphql", "swagger", "openapi", "actuator", "metrics",
    "health", "status", "upload", "download", "shell", "console", "flag",
    "secret", "token", "login", "auth", "api", "dev", "staging", "test",
    "jenkins", "kibana", "elasticsearch", "redis", "mongodb", "docker",
}


def _clean(value):
    return value.rstrip(".,);]}")


def _score(url, source=""):
    parsed = urllib.parse.urlsplit(url)
    text = (parsed.path + "?" + parsed.query).lower()
    score = 0
    reasons = []
    words = set(re.findall(r"[a-z0-9]+", text))
    hits = sorted(words & _SUSPICIOUS_WORDS)
    if hits:
        score += min(60, 15 * len(hits))
        reasons.append("sensitive path words: " + ", ".join(hits[:5]))
    if parsed.query:
        score += 10
        reasons.append("has query parameters")
    if any(x in text for x in (".env", ".git", ".bak", ".old", ".zip", ".sql")):
        score += 35
        reasons.append("possible backup/config artifact")
    if source:
        reasons.append("source: " + source)
    return min(score, 100), reasons


def extract_links(text, source="page", base_url=None, limit=200):
    """Return deterministic, deduplicated link records with suspicion scores."""
    text = str(text or "")
    values = []
    for value in _URL_RE.findall(text):
        values.append(_clean(value))
    for value in _ROUTE_RE.findall(text):
        if value != "/":
            if base_url:
                values.append(urllib.parse.urljoin(base_url, value))
            else:
                values.append(value)
    records = []
    seen = set()
    for value in values:
        value = _clean(value)
        if value in seen or len(value) > 2048:
            continue
        seen.add(value)
        score, reasons = _score(value, source)
        records.append({"url": value, "score": score, "reasons": reasons})
        if len(records) >= limit:
            break
    return sorted(records, key=lambda item: (-item["score"], item["url"]))


def extract_indicators(text, source="artifact", base_url=None):
    """Extract suspicious links, flags, secrets, IPs and encoded blobs."""
    text = str(text or "")
    links = extract_links(text, source=source, base_url=base_url)
    known, candidates = extract_flags(text)
    secrets = [{"kind": "credential-like", "value": m.group(1), "source": source}
               for m in _SECRET_RE.finditer(text)]
    ips = []
    for value in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?", text):
        host = value.rsplit(":", 1)[0] if ":" in value else value
        try:
            ipaddress.ip_address(host)
            ips.append(value)
        except ValueError:
            pass
    decoded_blobs = []
    for blob in re.findall(r"[A-Za-z0-9+/]{7,}={0,2}", text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            readable = raw.decode("utf-8")
            if any(ch.isalnum() for ch in readable):
                decoded_blobs.append({"encoded": blob[:120], "decoded": readable[:500], "source": source})
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
    return {
        "links": links,
        "flags": list(dict.fromkeys(known + candidates)),
        "secrets": secrets[:50],
        "ips": list(dict.fromkeys(ips))[:100],
        "decoded_blobs": decoded_blobs[:50],
    }
