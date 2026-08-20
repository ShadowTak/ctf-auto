#!/usr/bin/env python3
"""Fast web challenge test - all 9 challenges with smart rate limiting."""
import json, ssl, sys, os, time, traceback, urllib.request

ssl._create_default_https_context = ssl._create_unverified_context
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

API = "https://ctf.shadowtak.icu"
RESULTS = []

def login():
    resp = urllib.request.urlopen(urllib.request.Request(
        f"{API}/api/auth/login",
        data=json.dumps({"username": "admin", "password": "T@kBlLlugvJtSsqj7!"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST"), timeout=30)
    return resp.headers.get("Set-Cookie", "").split(";")[0]

def api(method, path, data=None, cookie=""):
    headers = {"Cookie": cookie}
    body = json.dumps(data).encode() if data else None
    if body: headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{API}{path}", data=body, headers=headers, method=method)
    resp = urllib.request.urlopen(req, timeout=60)
    return json.loads(resp.read())

def cleanup_all(cookie):
    """Stop all running lab instances - fast version."""
    data = api("GET", "/api/challenges", cookie=cookie)
    count = 0
    for c in data["items"]:
        if c.get("challengeType", "").lower() != "web":
            continue
        try:
            det = api("GET", f"/api/challenges/{c['slug']}", cookie=cookie)
            inst = det.get("challenge", {}).get("activeInstance")
            if inst and inst.get("status") == "RUNNING":
                api("POST", f"/api/challenge-instances/{inst['id']}/stop", {}, cookie)
                count += 1
                print(f"  Stopped: {c['slug']}")
        except: pass
    return count

def test_one(slug, cookie):
    """Start lab, scan, submit, stop. Returns (status, flag, time)."""
    data = api("GET", "/api/challenges", cookie=cookie)
    ch = next((c for c in data["items"] if c["slug"] == slug), None)
    if not ch:
        return "SKIP", "not found", 0
    uuid = ch["id"]

    # start lab
    lab_url, lab_id = "", ""
    for attempt in range(3):
        try:
            r = api("POST", f"/api/challenges/{uuid}/start", {}, cookie)
            lab_url = r["instance"]["endpoint"]["url"]
            lab_id = r["instance"]["id"]
            break
        except Exception as e:
            if "429" in str(e) or "LAB_LIMIT" in str(e):
                cleanup_all(cookie)
                time.sleep(10 * (attempt + 1))
            else:
                return "ERROR", str(e), 0
    if not lab_url:
        return "ERROR", "Could not start lab", 0

    print(f"    URL: {lab_url}")
    time.sleep(3)

    # quick health check
    from core import httpx
    probe = httpx.get(lab_url + "/", timeout=10)
    if probe is None or probe.status >= 500:
        time.sleep(5)
        probe = httpx.get(lab_url + "/", timeout=10)
        if probe is None or probe.status >= 500:
            api("POST", f"/api/challenge-instances/{lab_id}/stop", {}, cookie)
            return "ERROR", f"Lab unhealthy", 0

    # scan with alarm timeout
    import signal
    class Timeout(Exception): pass
    def handler(s, f): raise Timeout()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(90)
    t0 = time.time()
    flags = []
    try:
        from modules.web.scanner import run_web
        flags = run_web(lab_url)
        signal.alarm(0)
    except Timeout:
        print("    ⏰ Scan timeout (90s)")
        signal.alarm(0)
    except Exception as e:
        signal.alarm(0)
        print(f"    ❌ Scan error: {e}")
        traceback.print_exc()
    elapsed = time.time() - t0

    # submit best flag
    submitted = False
    best = ""
    for f in flags:
        if "{" in f and "}" in f:
            best = f
            try:
                r = api("POST", f"/api/challenges/{uuid}/submit", {"flag": f}, cookie)
                if r.get("correct"):
                    submitted = True
                    print(f"    ✅ CORRECT: {f}")
                else:
                    print(f"    ❌ Wrong: {f} → {r.get('message', '')}")
                time.sleep(3)
            except Exception as e:
                print(f"    ⚠️  {e}")
            break

    api("POST", f"/api/challenge-instances/{lab_id}/stop", {}, cookie)
    status = "PASS" if submitted else ("FOUND" if best else "FAIL")
    return status, best or "No flag", elapsed

def main():
    print("=" * 60)
    print("🌐 WEB CHALLENGE AUTO-TEST")
    print("=" * 60)

    cookie = login()
    print("[+] Logged in\n")

    # cleanup stale labs
    stopped = cleanup_all(cookie)
    if stopped:
        print(f"  Cleaned {stopped} stale labs")
        time.sleep(10)

    slugs = [
        "path-traversal",
        "sqli-101",
        "xss-reflected",
        "command-injection-basic",
        "idor-101",
        "mass-assignment",
        "graphql-introspection",
        "cookie-manipulation",
        "file-upload-basic",
    ]

    for i, slug in enumerate(slugs, 1):
        print(f"\n[{i}/{len(slugs)}] {slug}")
        try:
            status, flag, elapsed = test_one(slug, cookie)
        except Exception as e:
            traceback.print_exc()
            status, flag, elapsed = "ERROR", str(e), 0
        RESULTS.append((slug, status, flag, elapsed))
        print(f"    → {status} | {flag[:50]} | {elapsed:.1f}s")
        time.sleep(8)

    # summary
    print("\n" + "=" * 60)
    print("📊 RESULTS")
    print("=" * 60)
    passed = sum(1 for _, s, _, _ in RESULTS if s == "PASS")
    print(f"\n  ✅ Solved: {passed}/{len(RESULTS)}\n")
    for slug, status, flag, elapsed in RESULTS:
        icon = {"PASS": "✅", "FAIL": "❌", "FOUND": "🏁", "ERROR": "⚠️", "SKIP": "⏭️"}.get(status, "?")
        print(f"  {icon} {slug:35s} {flag[:50]:50s} {elapsed:.1f}s")

if __name__ == "__main__":
    main()
