#!/usr/bin/env python3
"""Test a single web challenge. Usage: python3 test_web_one.py <slug>"""
import json, ssl, sys, os, time, urllib.request

ssl._create_default_https_context = ssl._create_unverified_context
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

API = "https://ctf.shadowtak.icu"

def login():
    resp = urllib.request.urlopen(urllib.request.Request(
        f"{API}/api/auth/login",
        data=json.dumps({"username": "admin", "password": "T@kBlLlugvJtSsqj7!"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST"), timeout=30)
    return resp.headers.get("Set-Cookie", "").split(";")[0]

def api(method, path, data=None, cookie=""):
    headers = {"Cookie": cookie}
    body = json.dumps(data).encode() if data else None
    if body:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{API}{path}", data=body, headers=headers, method=method)
    resp = urllib.request.urlopen(req, timeout=60)
    return json.loads(resp.read())

def main():
    slug = sys.argv[1] if len(sys.argv) > 1 else "path-traversal"
    cookie = login()
    print(f"[*] Testing: {slug}")

    # get challenge UUID
    data = api("GET", "/api/challenges", cookie=cookie)
    ch = next((c for c in data["items"] if c["slug"] == slug), None)
    if not ch:
        print(f"[-] Challenge {slug} not found")
        return
    uuid = ch["id"]

    # start lab
    try:
        r = api("POST", f"/api/challenges/{uuid}/start", {}, cookie)
        lab_url = r["instance"]["endpoint"]["url"]
        lab_id = r["instance"]["id"]
        print(f"[+] Lab: {lab_url}")
    except Exception as e:
        print(f"[-] Start failed: {e}")
        return

    time.sleep(3)

    # scan
    from modules.web.scanner import run_web
    t0 = time.time()
    flags = run_web(lab_url)
    elapsed = time.time() - t0

    # submit first valid flag
    submitted = False
    for f in flags:
        if "{" in f and "}" in f:
            try:
                r = api("POST", f"/api/challenges/{uuid}/submit", {"flag": f}, cookie)
                if r.get("correct"):
                    print(f"\n✅ CORRECT: {f}")
                    submitted = True
                else:
                    print(f"❌ Wrong: {f} → {r.get('message','')}")
                time.sleep(3)
                break
            except Exception as e:
                print(f"⚠️  Submit error: {e}")

    # stop
    try:
        api("POST", f"/api/challenge-instances/{lab_id}/stop", {}, cookie)
    except: pass

    print(f"\n{'✅ PASS' if submitted else '❌ FAIL'} | {elapsed:.1f}s | flags: {flags}")

if __name__ == "__main__":
    main()
