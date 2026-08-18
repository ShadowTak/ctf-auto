"""Helper to drive the local Aegis API: register/login, start labs, fetch
static challenge files, and report instance URLs. Used for auto-testing."""
import json
import os
import time
import urllib.request

API = os.environ.get("AEGIS_API", "http://localhost:3001")
PUBLIC_HOST = os.environ.get("LAB_PUBLIC_HOST", "localhost")

CJ = os.path.join(os.path.dirname(__file__), ".lab_cookies.txt")


def _req(method, path, body=None, cookie=None):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            resp_cookie = r.headers.get("Set-Cookie", "").split(";")[0]
            raw = r.read().decode()
            return r.status, json.loads(raw) if raw else {}, resp_cookie
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw) if raw else {}, ""
        except Exception:
            return e.code, {"raw": raw[:300]}, ""


def ensure_user():
    """Login or register a throwaway player; returns session cookie."""
    if os.path.exists(CJ):
        with open(CJ) as f:
            c = f.read().strip()
        st, data, _ = _req("GET", "/api/users/me", cookie=c)
        if st == 200:
            return c
    import random
    import string
    name = "auto" + "".join(random.choices(string.ascii_lowercase, k=8))
    pw = "AutoPass123!"
    st, data, c = _req("POST", "/api/auth/register",
                      {"username": name, "email": f"{name}@example.com", "password": pw})
    if st not in (201, 409):
        raise RuntimeError(f"register failed: {st} {data}")
    if not c:
        st, data, c = _req("POST", "/api/auth/login",
                           {"username": name, "password": pw})
    if not c:
        # try the well-known seeded admin/dev accounts
        for u, p in (("admin", "admin123"), ("dev", "dev12345")):
            st, data, c = _req("POST", "/api/auth/login", {"username": u, "password": p})
            if c:
                break
    if not c:
        raise RuntimeError("cannot get a session cookie")
    with open(CJ, "w") as f:
        f.write(c)
    return c


def list_challenges(cookie):
    st, data, _ = _req("GET", "/api/challenges", cookie=cookie)
    return data.get("items", [])


def start_lab(cookie, challenge_id, wait=180):
    """Start a lab and wait until RUNNING. Returns instance dict."""
    st, data, _ = _req("POST", f"/api/challenges/{challenge_id}/start", body={},
                       cookie=cookie)
    if st != 200:
        raise RuntimeError(f"start failed: {st} {data}")
    inst = data.get("instance")
    if not inst:
        raise RuntimeError(f"no instance in response: {data}")
    iid = inst["id"]
    t0 = time.time()
    while time.time() - t0 < wait:
        st, data, _ = _req("GET", f"/api/challenge-instances/{iid}", cookie=cookie)
        inst = data.get("instance") or inst
        status = inst.get("status")
        if status == "RUNNING":
            return inst
        if status in ("STOPPED", "ERROR", "FAILED"):
            raise RuntimeError(f"lab failed: {status}")
        time.sleep(3)
    raise RuntimeError("lab start timeout")


def stop_lab(cookie, instance_id):
    """Stop a running lab instance."""
    return _req("POST", f"/api/challenge-instances/{instance_id}/stop", body={},
                cookie=cookie)


def active_instance_for(cookie, slug):
    """Return the user's active instance (if any) for a challenge slug."""
    st, data, _ = _req("GET", f"/api/challenges/{slug}", cookie=cookie)
    if st != 200:
        return None
    ch = data.get("challenge") or {}
    inst = ch.get("activeInstance")
    if inst and inst.get("status") in ("CREATING", "RUNNING"):
        return inst
    return None


def stop_all_labs(cookie):
    """Stop every active instance for this user (frees the LAB_LIMIT quota).
    There is no user-facing instance list route, so we walk challenge details
    (each exposes activeInstance) and stop what we find."""
    stopped = 0
    for ch in list_challenges(cookie):
        inst = active_instance_for(cookie, ch["slug"])
        if inst:
            stop_lab(cookie, inst["id"])
            stopped += 1
    if stopped:
        time.sleep(2)
    return stopped


def instance_url(inst):
    """Build the player-facing URL for a lab instance.
    Endpoint DTO shape: {url, host, ports: [{name, internal, external, protocol}]}"""
    ep = inst.get("endpoint") or {}
    if ep.get("url"):
        return ep["url"]
    host = ep.get("host") or PUBLIC_HOST
    for p in ep.get("ports", []):
        if p.get("protocol") == "http" and p.get("external"):
            return f"http://{host}:{p['external']}"
    return None
