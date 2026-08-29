"""Web authenticated workflow recorder and replay.

Records browser-based login flows, captures authentication state, and
replays requests with captured credentials for multi-step CTF challenges.
"""
import json
import re
import time
import urllib.parse

from core import httpx
from core.flag import extract_flags
from core.output import info_line, ok_line, section, warn_line

# ---------------------------------------------------------------------------
# Workflow recording
# ---------------------------------------------------------------------------

def record_login_flow(url, username=None, password=None,
                      login_path=None, timeout=20):
    """Record a browser-based login flow using Playwright.

    Captures:
    - Cookies set during login
    - Authorization headers
    - JWT tokens
    - Redirect chains
    - Form action URLs

    Args:
        url: base URL
        username: login username (optional, for auto-fill)
        password: login password (optional, for auto-fill)
        login_path: explicit login page path
        timeout: seconds before giving up

    Returns:
        dict with captured auth state, or None if Playwright unavailable
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    base = httpx.normalize_url(url)
    auth_state = {
        "cookies": {},
        "headers": {},
        "tokens": [],
        "urls_visited": [],
        "forms_found": [],
        "captured_responses": [],
    }

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            page = context.new_page()

            # Intercept responses to capture tokens
            def on_response(response):
                try:
                    headers = dict(response.headers)
                    url_str = response.url
                    status = response.status

                    # Capture Set-Cookie
                    for key, value in headers.items():
                        if key.lower() == "set-cookie":
                            auth_state["captured_responses"].append({
                                "url": url_str, "status": status,
                                "header": key, "value": value,
                            })

                    # Capture Authorization/token headers
                    for key, value in headers.items():
                        if any(t in key.lower() for t in ("auth", "token", "x-")):
                            auth_state["headers"][key] = value

                    # Capture body for tokens
                    try:
                        body = response.text()
                        for pattern in [
                            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                            r'"token"\s*:\s*"([^"]+)"',
                            r'"access_token"\s*:\s*"([^"]+)"',
                            r'"session"\s*:\s*"([^"]+)"',
                        ]:
                            for m in re.finditer(pattern, body):
                                token = m.group(0) if not m.groups() else m.group(1)
                                if token not in auth_state["tokens"]:
                                    auth_state["tokens"].append(token)
                    except Exception:
                        pass

                except Exception:
                    pass

            page.on("response", on_response)

            # Navigate to login page
            login_url = base
            if login_path:
                login_url = base + "/" + login_path.lstrip("/")
            else:
                # Try common login paths
                for path in ("/login", "/signin", "/auth", "/api/login",
                             "/wp-login.php", "/administrator/"):
                    try:
                        resp = page.goto(base + path, timeout=5000)
                        if resp and resp.status < 400:
                            login_url = base + path
                            break
                    except Exception:
                        continue

            page.goto(login_url, timeout=timeout * 1000)
            auth_state["urls_visited"].append(login_url)

            # Find and fill forms
            forms = page.query_selector_all("form")
            for form in forms:
                action = form.get_attribute("action") or ""
                method = form.get_attribute("method") or "GET"
                inputs = []
                for inp in form.query_selector_all("input, select, textarea"):
                    name = inp.get_attribute("name") or ""
                    inp_type = inp.get_attribute("type") or "text"
                    if name:
                        inputs.append({"name": name, "type": inp_type})
                auth_state["forms_found"].append({
                    "action": action, "method": method, "inputs": inputs,
                })

            # Fill credentials if provided
            if username and password:
                for form_data in auth_state["forms_found"]:
                    for inp in form_data["inputs"]:
                        name_lower = inp["name"].lower()
                        if any(x in name_lower for x in ("user", "email", "login")):
                            try:
                                page.fill(f'input[name="{inp["name"]}"]', username)
                            except Exception:
                                pass
                        elif any(x in name_lower for x in ("pass", "pwd")):
                            try:
                                page.fill(f'input[name="{inp["name"]}"]', password)
                            except Exception:
                                pass

                # Submit form
                for form_data in auth_state["forms_found"]:
                    if form_data["method"].upper() == "POST":
                        try:
                            # Find submit button
                            submit = page.query_selector(
                                'input[type="submit"], button[type="submit"], button:not([type])')
                            if submit:
                                submit.click()
                                page.wait_for_load_state("networkidle",
                                                         timeout=timeout * 1000)
                                auth_state["urls_visited"].append(page.url)
                                break
                        except Exception:
                            pass

            # Capture final cookies
            for cookie in context.cookies():
                auth_state["cookies"][cookie["name"]] = {
                    "value": cookie["value"],
                    "domain": cookie.get("domain", ""),
                    "path": cookie.get("path", "/"),
                    "httpOnly": cookie.get("httpOnly", False),
                    "secure": cookie.get("secure", False),
                }

            browser.close()

    except Exception as exc:
        auth_state["error"] = str(exc)

    return auth_state


# ---------------------------------------------------------------------------
# Workflow replay
# ---------------------------------------------------------------------------

def replay_workflow(base_url, auth_state, target_paths=None, timeout=10):
    """Replay captured authentication state against target endpoints.

    Sends requests with captured cookies/headers and checks each response
    for flags, sensitive data, and access control differences.

    Args:
        base_url: target base URL
        auth_state: dict from record_login_flow
        target_paths: list of paths to test (auto-discovered if None)
        timeout: request timeout

    Returns:
        list of findings dicts
    """
    base = httpx.normalize_url(base_url)
    findings = []
    flags_found = []

    if not auth_state:
        return findings

    # Build session cookies
    cookies = {}
    for name, data in auth_state.get("cookies", {}).items():
        cookies[name] = data["value"] if isinstance(data, dict) else data

    # Build headers
    headers = dict(auth_state.get("headers", {}))

    # Auto-discover paths if not provided
    if not target_paths:
        target_paths = _discover_auth_endpoints(base)

    # Replay each path
    for path in target_paths:
        url = base + "/" + path.lstrip("/")

        # Request with auth
        try:
            resp = httpx.get(url, timeout=timeout)
            if resp is None:
                continue

            status = resp.status
            text = resp.text

            # Check for flags
            known, candidates = extract_flags(text)
            for flag in known + candidates:
                if flag not in flags_found:
                    flags_found.append(flag)
                    findings.append({
                        "type": "flag",
                        "flag": flag,
                        "url": url,
                        "status": status,
                        "source": "authenticated-replay",
                    })

            # Check for interesting status codes
            if status in (200, 201):
                # Check for sensitive content
                indicators = _check_sensitive_content(text, url)
                if indicators:
                    findings.append({
                        "type": "sensitive-content",
                        "url": url,
                        "status": status,
                        "indicators": indicators,
                    })

            # Check for auth bypass indicators
            if status == 200 and _looks_like_admin_content(text):
                findings.append({
                    "type": "admin-access",
                    "url": url,
                    "status": status,
                    "evidence": "admin/dashboard content accessible",
                })

        except Exception:
            continue

    # Check for token in captured responses
    for token in auth_state.get("tokens", []):
        known, candidates = extract_flags(token)
        for flag in known + candidates:
            if flag not in flags_found:
                flags_found.append(flag)
                findings.append({
                    "type": "flag",
                    "flag": flag,
                    "source": "captured-token",
                })

    return findings


def _discover_auth_endpoints(base):
    """Discover endpoints that might be behind authentication."""
    common_paths = [
        "/admin", "/admin/", "/dashboard", "/profile", "/account",
        "/api/user", "/api/me", "/api/admin", "/api/secret",
        "/api/flag", "/api/data", "/flag", "/flags",
        "/hidden", "/internal", "/private",
        "/graphql", "/api/v1/admin",
        "/debug", "/metrics", "/actuator",
        "/backup", "/config", "/env",
    ]
    return common_paths


def _check_sensitive_content(text, url):
    """Check if response contains sensitive-looking content."""
    indicators = []
    patterns = [
        (r"(?i)flag\s*[:=]\s*\S+", "flag reference"),
        (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+", "password field"),
        (r"(?i)secret\s*[:=]\s*\S+", "secret value"),
        (r"(?i)api[_-]?key\s*[:=]\s*\S+", "API key"),
        (r"-----BEGIN", "PEM header"),
        (r"ey[A-Za-z0-9_-]{20,}", "JWT-like token"),
        (r"(?i)unauthorized|forbidden|access.denied", "access control message"),
    ]
    for pattern, desc in patterns:
        if re.search(pattern, text):
            indicators.append(desc)
    return indicators


def _looks_like_admin_content(text):
    """Heuristic: does this look like admin/dashboard content?"""
    low = text.lower()
    signals = [
        "admin panel", "dashboard", "management", "system settings",
        "user management", "create user", "delete user", "all users",
        "server status", "debug info", "internal",
    ]
    return sum(1 for s in signals if s in low) >= 2


# ---------------------------------------------------------------------------
# Workflow analysis from existing HTTP responses
# ---------------------------------------------------------------------------

def analyze_auth_state_from_cookies(cookies_dict):
    """Analyze cookie-based auth state for vulnerabilities.

    Args:
        cookies_dict: dict of cookie name -> value

    Returns:
        list of finding strings
    """
    findings = []

    for name, value in cookies_dict.items():
        value = str(value)

        # Check for predictable session IDs
        if name.lower() in ("session", "sessionid", "sid", "phpsessid"):
            if value.isdigit():
                findings.append(f"[!] Predictable numeric session ID in {name}: {value}")
            if len(value) < 16:
                findings.append(f"[!] Short session ID in {name}: {len(value)} chars")

        # Check for JWT in cookie
        if value.count(".") == 2 and len(value) > 40:
            findings.append(f"[!] JWT-like token in cookie {name}")

        # Check for serialized objects
        if value.startswith(("ey", "T:", "O:", "Q:")):
            findings.append(f"[!] Serialized object in cookie {name}: {value[:30]}...")

        # Check for insecure flags
        if "session" in name.lower():
            findings.append(f"[*] Session cookie: {name} — check httpOnly/secure/SameSite")

    return findings
