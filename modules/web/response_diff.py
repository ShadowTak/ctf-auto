"""Response differential heuristics used by authorized CTF Web scans."""
import hashlib
import re


def fingerprint(response):
    if response is None:
        return None
    body = response.text or ""
    normalized = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", body, flags=re.I)
    normalized = re.sub(r"\b\d{2,}\b", "<num>", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return {
        "status": int(response.status),
        "length": len(response.body),
        "type": response.headers.get("content-type", "").split(";", 1)[0].lower(),
        "hash": hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()[:16],
        "title": (re.search(r"(?is)<title[^>]*>(.*?)</title>", body) or ["", ""])[1].strip()[:120],
    }


def differs(left, right):
    """Meaningful response difference, tolerant of dynamic numbers/hashes."""
    if left is None or right is None:
        return left is not right
    a, b = fingerprint(left), fingerprint(right)
    return (a["status"], a["hash"], a["type"]) != (b["status"], b["hash"], b["type"])


def method_matrix(url, methods=("OPTIONS", "TRACE", "PUT", "PATCH", "DELETE")):
    """Probe methods and return evidence records; no request body is sent."""
    from core import httpx
    records = []
    for method in methods:
        response = httpx.request(method, url, timeout=6, allow_redirects=False)
        if response is None:
            continue
        records.append({"method": method, "status": response.status,
                        "allow": response.headers.get("allow", ""),
                        "fingerprint": fingerprint(response)})
    return records
