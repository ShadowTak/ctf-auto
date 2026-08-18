"""Auto-lab mode: drive the local Aegis stack end-to-end.

Starts every published lab (or only web / crypto), downloads static
challenge files, runs the matching auto scanner on each target and
summarizes which challenges yielded flags. Fully automatic:

    python3 run.py --auto-lab web        # ทุกแลป web (challengeType=web)
    python3 run.py --auto-lab crypto     # หมวด crypto: static files + web lab
    python3 run.py --auto-lab all        # ทั้งหมดที่ publish
    python3 run.py --auto-lab web --limit 2   # แค่ 2 แลป (เทสเร็ว)
"""
import os
import sys
import tempfile
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lab_session as ls
from core.output import flag_line, head, info_line, ok_line, section, warn_line


def _download_file(cookie, file_id, file_name):
    """GET /api/files/{fileId} with auth cookie -> bytes or None.
    (The public /files/{challengeId}/{name} route 404s on seeded files;
    the legacy /api/files/{fileId} endpoint works.)"""
    import urllib.request
    url = f"{ls.API}/api/files/{file_id}"
    req = urllib.request.Request(url, headers={"Cookie": cookie})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read()
    except Exception as e:
        warn_line(f"  download {file_name} failed: {e}")
        return None


def _crypto_static(cookie, ch):
    """Download all files of a static crypto challenge and run auto-detect."""
    slug, cid = ch["slug"], ch["id"]
    section(f"🔐 {slug} ({ch.get('title', '')}) — static files")
    # challenge detail returns the file list
    st, detail, _ = ls._req("GET", f"/api/challenges/{slug}", cookie=cookie)
    files = (detail.get("challenge") or detail).get("files", []) if st == 200 else []
    if isinstance(detail, dict):
        files = detail.get("files") or files
    if not files:
        warn_line("  ไม่มีไฟล์ใน challenge นี้")
        return []
    flags = []
    for f in files:
        fname = f.get("name") or f
        fid = f.get("id")
        info_line(f"  download: {fname} ({f.get('size', '?')} bytes)")
        if not fid:
            warn_line("    file id หาย — ข้าม")
            continue
        data = _download_file(cookie, fid, fname)
        if not data:
            continue
        tmp = os.path.join(tempfile.gettempdir(), f"autolab_{slug}_{os.path.basename(fname)}")
        with open(tmp, "wb") as fh:
            fh.write(data)
        from modules.crypto.autodetect import run_crypto
        flags.extend(run_crypto(tmp))
    return list(dict.fromkeys(flags))


_START_TIMES = []  # lab start timestamps for the API's 4/min limiter


def _throttle_start():
    """The API allows max 4 lab starts per 60s (labLimiter). Space us out."""
    global _START_TIMES
    now = time.time()
    _START_TIMES = [t for t in _START_TIMES if now - t < 60]
    while len(_START_TIMES) >= 4:
        sleep_for = 60 - (now - _START_TIMES[0]) + 1
        info_line(f"  รอ {sleep_for:.0f}s (API จำกัด start 4/นาที)")
        time.sleep(sleep_for)
        now = time.time()
        _START_TIMES = [t for t in _START_TIMES if now - t < 60]
    _START_TIMES.append(time.time())


def _web_lab(cookie, ch, wait=300):
    """Start a lab instance and run the full web auto scan against it."""
    slug = ch["slug"]
    section(f"🌐 {slug} ({ch.get('title', '')}) — starting lab")
    _throttle_start()
    inst = None
    for attempt in range(4):
        try:
            inst = ls.start_lab(cookie, ch["id"], wait=wait)
            break
        except Exception as e:
            msg = str(e)
            if "LAB_LIMIT" in msg and attempt < 3:
                warn_line(f"  LAB_LIMIT (attempt {attempt + 1}) — รอ 5s แล้วลองใหม่")
                time.sleep(5)
                continue
            if "RATE_LIMITED" in msg and attempt < 3:
                warn_line(f"  RATE_LIMITED (attempt {attempt + 1}) — รอ 20s แล้วลองใหม่")
                time.sleep(20)
                continue
            warn_line(f"  start lab failed: {e}")
            return []
    url = ls.instance_url(inst)
    if not url:
        warn_line("  instance URL ไม่ได้ — ข้าม")
        return []
    ok_line(f"  lab RUNNING: {url}")
    # give the app a moment to accept connections
    from core import httpx
    up = False
    for _ in range(30):
        if httpx.get(url + "/", timeout=3) is not None:
            up = True
            break
        time.sleep(2)
    if not up:
        warn_line("  ยังเชื่อมต่อไม่ได้ — รอเพิ่ม 15s แล้วลองอีกครั้ง")
        time.sleep(15)
        if httpx.get(url + "/", timeout=3) is None:
            warn_line("  lab ยังไม่ตอบสนอง — ข้าม")
            return []
    from modules.web.scanner import run_web
    flags = run_web(url)
    # stop the lab so the next one can start (LAB_LIMIT quota)
    try:
        ls.stop_lab(cookie, inst["id"])
        info_line("  lab stopped")
    except Exception:
        pass
    return list(dict.fromkeys(flags))


def auto_lab(category=None, limit=None):
    """Main entry. category in {web, crypto, all, None}. Returns summary dict."""
    section("⚡ AUTO LAB — สแกนแลปใน stack อัตโนมัติ")
    cookie = ls.ensure_user()
    # free the LAB_LIMIT quota so we can start labs one after another
    freed = ls.stop_all_labs(cookie)
    if freed:
        info_line(f"stopped {freed} แลปเก่าที่ค้างอยู่")
    challenges = ls.list_challenges(cookie)
    if not challenges:
        warn_line("ไม่พบ challenge ที่ publish — ตรวจว่า stack รันแล้ว (docker compose up)")
        return []

    selected = []
    for ch in challenges:
        cat = (ch.get("category") or {}).get("slug", "")
        ctype = ch.get("challengeType", "")
        if category == "web":
            if ctype != "web":
                continue
        elif category == "crypto":
            if cat != "crypto":
                continue
        selected.append(ch)
    if not selected:
        warn_line(f"ไม่พบ challenge หมวด {category}")
        return []
    if limit:
        selected = selected[:limit]

    ok_line(f"พบ {len(selected)} challenge: " +
            ", ".join(f"{c['slug']}({c.get('challengeType')})" for c in selected))
    print()

    results = []
    t_total = time.time()
    for i, ch in enumerate(selected, 1):
        ctype = ch.get("challengeType", "")
        info_line(f"[{i}/{len(selected)}] === {ch['slug']} ===")
        t0 = time.time()
        try:
            if ctype == "static":
                flags = _crypto_static(cookie, ch)
            else:
                flags = _web_lab(cookie, ch)
        except KeyboardInterrupt:
            warn_line("ถูกขัดจังหวะ — หยุดที่ตรงนี้")
            break
        except Exception as e:
            warn_line(f"  error: {e}")
            flags = []
        elapsed = time.time() - t0
        results.append((ch["slug"], ch.get("title", ""), ctype, flags, elapsed))
        print()

    # summary (show at most 3 flags per challenge — decode noise is real,
    # and real known-prefix flags are shown first)
    def real_first(flist):
        from core.flag import FLAG_RE
        real = [f for f in flist if FLAG_RE.fullmatch(f.strip())]
        rest = [f for f in flist if f not in real]
        return real + rest

    print()
    section("🏁 AUTO LAB SUMMARY")
    solved = 0
    for slug, title, ctype, flags, elapsed in results:
        if flags:
            solved += 1
            ordered = real_first(flags)
            shown = ordered[:3]
            more = len(ordered) - len(shown)
            print(f"  ✅ {slug:<34} {len(flags)} flag(s)  ({elapsed:.0f}s)")
            for f in shown:
                flag_line(f"     {f}")
            if more > 0:
                info_line(f"     ... อีก {more} flag")
        else:
            print(f"  ❌ {slug:<34} ยังไม่เจอ flag      ({elapsed:.0f}s)")
    ok_line(f"เจอ flag: {solved}/{len(results)} challenges  (total {time.time()-t_total:.0f}s)")
    return results
