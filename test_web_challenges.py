#!/usr/bin/env python3
"""Test auto_web against all web challenges on ctf.shadowtak.icu.
Starts each lab, runs auto scan, submits flags, reports results."""
import json
import ssl
import sys
import time
import traceback
import urllib.request

ssl._create_default_https_context = ssl._create_unverified_context
API = "https://ctf.shadowtak.icu"
USER = "admin"
PASS = "T@kBlLlugvJtSsqj7!"

def api_call(method, path, data=None, cookie=""):
    headers = {"Cookie": cookie}
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{API}{path}", data=body, headers=headers, method=method)
    resp = urllib.request.urlopen(req, timeout=60)
    return json.loads(resp.read())

def login():
    resp = urllib.request.urlopen(urllib.request.Request(
        f"{API}/api/auth/login",
        data=json.dumps({"username": USER, "password": PASS}).encode(),
        headers={"Content-Type": "application/json"}, method="POST"), timeout=30)
    return resp.headers.get("Set-Cookie", "").split(";")[0]

def start_lab(uuid, cookie):
    r = api_call("POST", f"/api/challenges/{uuid}/start", {}, cookie)
    inst = r.get("instance", r)
    return inst.get("endpoint", {}).get("url", ""), inst.get("id", "")

def stop_lab(lab_id, cookie):
    try:
        api_call("POST", f"/api/challenge-instances/{lab_id}/stop", {}, cookie)
    except Exception:
        pass

def submit_flag(uuid, flag, cookie):
    try:
        return api_call("POST", f"/api/challenges/{uuid}/submit", {"flag": flag}, cookie)
    except Exception as e:
        return {"error": str(e)}

def main():
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    print("=" * 60)
    print("🌐 WEB CHALLENGE AUTO-TEST")
    print("=" * 60)

    cookie = login()
    print("[+] Logged in")

    data = api_call("GET", "/api/challenges", cookie=cookie)
    web = [c for c in data.get("items", []) if c.get("challengeType", "").lower() == "web"]
    print(f"[+] {len(web)} web challenges\n")

    results = []

    for i, ch in enumerate(web, 1):
        slug, title, uuid = ch["slug"], ch["title"], ch["id"]
        print(f"\n{'='*60}")
        print(f"  [{i}/{len(web)}] {title} ({slug})")
        print(f"{'='*60}")

        # start lab with retry
        lab_url, lab_id = "", ""
        for attempt in range(3):
            try:
                lab_url, lab_id = start_lab(uuid, cookie)
                print(f"  [+] Lab: {lab_url}")
                time.sleep(3)
                break
            except Exception as e:
                if "429" in str(e):
                    wait = 15 * (attempt + 1)
                    print(f"  [!] Rate limited, waiting {wait}s...")
                    time.sleep(wait)
                else:
                    print(f"  [-] Start failed: {e}")
                    break

        if not lab_url:
            results.append((slug, title, "ERROR", "Could not start lab"))
            continue

        # run auto_web
        flags = []
        try:
            from modules.web.scanner import run_web
            flags = run_web(lab_url)
        except Exception as e:
            print(f"  [-] Scan error: {e}")
            traceback.print_exc()

        # submit best flag
        submitted = False
        if flags:
            # clean flags - only keep valid format
            clean = [f for f in flags if "{" in f and "}" in f and len(f) > 10]
            if clean:
                best = clean[0]
                print(f"\n  🏁 Flag: {best}")
                try:
                    r = submit_flag(uuid, best, cookie)
                    correct = r.get("correct", r.get("success", False))
                    msg = r.get("message", "")
                    if correct:
                        print(f"  ✅ SUBMITTED CORRECTLY! {msg}")
                        submitted = True
                    else:
                        print(f"  ❌ Wrong: {msg}")
                except Exception as e:
                    print(f"  ⚠️  Submit error: {e}")
                time.sleep(2)  # rate limit
        else:
            print(f"\n  ❌ No flags found")

        # stop lab
        stop_lab(lab_id, cookie)
        print(f"  [+] Lab stopped")

        status = "PASS" if submitted else ("FOUND" if flags else "FAIL")
        detail = flags[0] if flags else ("Flags found but wrong" if flags else "No flag found")
        results.append((slug, title, status, detail))
        time.sleep(3)  # rate limit between labs

    # summary
    print("\n" + "=" * 60)
    print("📊 RESULTS")
    print("=" * 60)
    passed = sum(1 for _, _, s, _ in results if s == "PASS")
    found = sum(1 for _, _, s, _ in results if s == "FOUND")
    print(f"\n  ✅ Solved: {passed}/{len(results)}")
    print(f"  🏁 Flag found (not submitted): {found}")
    print()
    for slug, title, status, detail in results:
        icon = {"PASS": "✅", "FAIL": "❌", "FOUND": "🏁", "ERROR": "⚠️"}.get(status, "?")
        print(f"  {icon} {title:35s} {detail[:50]}")

if __name__ == "__main__":
    main()
