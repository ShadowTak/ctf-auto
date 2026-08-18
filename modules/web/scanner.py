"""Web category orchestrator: recon -> dirbust -> leaks -> injections ->
JWT/cookies -> flag collection."""
from core import httpx
from core.flag import extract_flags
from core.output import flag_line, info_line, ok_line, section, warn_line
from . import assets as assets_mod
from . import backups as backups_mod
from . import cookies as cookies_mod
from . import ctr_bitflip as ctr_mod
from . import directories as dirs_mod
from . import errors as errors_mod
from . import graphql as graphql_mod
from . import interact as interact_mod
from . import injections as inj_mod
from . import jwt as jwt_mod
from . import login as login_mod
from . import recon as recon_mod


def run_web(target, interactive=False):
    """Public entry. target = URL. Returns list of flags found."""
    section("🌐 WEB SCAN")
    base = httpx.normalize_url(target)
    info_line(f"target: {base}")
    flags = []

    # sanity check
    probe = httpx.get(base + "/", timeout=10)
    if probe is None:
        warn_line(f"เชื่อมต่อ {base} ไม่ได้ — ตรวจ URL หรือลอง http/https")
        return flags
    ok_line(f"เชื่อมต่อได้ (HTTP {probe.status})")

    # 1) recon
    extra_paths, recon_flags = recon_mod.run_recon(base)
    flags.extend(recon_flags)

    # 2) asset / JS crawl: links, scripts, secrets, extra endpoints
    print()
    print("── Asset & JS crawl ──")
    page = httpx.get(base + "/", timeout=10)
    if page is not None:
        asset_findings, asset_flags, js_paths = assets_mod.scan_assets(
            base + "/", page.text)
        for line in asset_findings:
            print(line)
        flags.extend(asset_flags)
        if js_paths:
            ok_line(f"JS เผย endpoint เพิ่ม {len(js_paths)} path")
            extra_paths.extend(js_paths)

    # 3) directory brute force
    print()
    print("── Directory brute force ──")
    buster = dirs_mod.DirBuster(base)
    found = buster.run(extra_paths=extra_paths)
    if found:
        ok_line(f"พบ {len(found)} path น่าสนใจ:")
        for line in dirs_mod.format_results(found):
            print(line)
        flags.extend(dirs_mod.scan_for_flags(found, base))
        # scan any discovered .js files for flags/secrets
        js_found = [p for p, _, _, _ in found if p.endswith(".js")]
        for p in js_found[:15]:
            r = httpx.get(base + "/" + p, timeout=8)
            if r is not None:
                f2, fl2 = assets_mod.scan_js_blob(p, r.text)
                for line in f2:
                    print(line)
                flags.extend(fl2)
    else:
        warn_line("ไม่พบ path เพิ่มเติม")

    # 3a) deep interaction: IDOR enum + form POST/render + fuzz every endpoint
    print()
    print("── Deep interact (IDOR / form POST / endpoint fuzz) ──")
    deep_flags = []
    home = httpx.get(base + "/", timeout=10)
    if home is not None:
        idor_find, idor_flags = interact_mod.idor_enum(base, home.text)
        for line in idor_find:
            print(line)
        deep_flags.extend(idor_flags)
        form_find, form_flags = interact_mod.form_post(base, home.text)
        for line in form_find:
            print(line)
        deep_flags.extend(form_flags)
    ep_200 = [base + "/" + p for p, s, _, _ in found if s == 200]
    ep_200 = ep_200[:40]
    fuzz_hits, fuzz_flags = interact_mod.fuzz_discovered(base, ep_200)
    for target, param, kind, ev in fuzz_hits:
        print(f"  [!] {kind}: {target} param={param} — {ev}")
    deep_flags.extend(fuzz_flags)
    # fuzz query params on links found in the homepage (/view?file=, /fetch?url=)
    link_hits, link_flags = interact_mod.fuzz_link_params(base, home.text) if home else ([], [])
    for target, param, kind, ev in link_hits:
        print(f"  [!] {kind}: {target} param={param} — {ev}")
    deep_flags.extend(link_flags)
    # AES-CTR bit-flip: services with POST /encrypt + /decrypt (JSON)
    ctr_endpoints = ep_200 + [
        base + "/encrypt", base + "/decrypt",
        base + "/api/encrypt", base + "/api/decrypt",
        base + "/api/v1/encrypt", base + "/api/v1/decrypt",
    ]
    ctr_find, ctr_flags = ctr_mod.scan_ctr_bitflip(base, ctr_endpoints)
    for line in ctr_find:
        print(line)
    deep_flags.extend(ctr_flags)
    # GraphQL introspection hunting
    gql_find, gql_flags = graphql_mod.scan_graphql(base, ctr_endpoints)
    for line in gql_find:
        print(line)
    deep_flags.extend(gql_flags)
    # JSON body probes: mass assignment + NoSQL $ne/$gt auth bypass
    json_find, json_flags = interact_mod.json_probe(base, ctr_endpoints)
    for line in json_find:
        print(line)
    deep_flags.extend(json_flags)
    flags.extend(dict.fromkeys(deep_flags))

    # 3b) error-trigger info disclosure
    print()
    print("── Error trigger (500 leak hunt) ──")
    endpoints = [base + "/"] + [base + "/" + p for p, s, _, _ in found if s == 200]
    err_hits, err_flags = errors_mod.trigger_errors(base, endpoints)
    if err_hits:
        for endpoint, name, leaks in err_hits:
            print(f"  [!] {endpoint} (payload={name}) → 500, leak: {', '.join(leaks)}")
        flags.extend(err_flags)
    else:
        warn_line("ไม่พบ 500 ที่รั่วข้อมูล")

    # 3) backup / source / config leaks
    print()
    print("── Backup / config leak checks ──")
    leak_findings, leak_flags = backups_mod.run_backup_checks(base)
    for path, desc, status, size in leak_findings:
        print(f"  {status:<4} {path:<28} {desc} ({size} bytes)")
    flags.extend(leak_flags)
    if not leak_findings:
        warn_line("ไม่พบไฟล์ leak")

    # 4) injection fuzzing on homepage (GET params + form fields)
    print()
    print("── Injection fuzz (GET params / form fields) ──")
    page = httpx.get(base + "/", timeout=10)
    if page is not None:
        hits = inj_mod.fuzz_params(base + "/", page.text)
        if hits:
            for target, param, kind, evidence in hits:
                print(f"  [!] {kind}: {target} param={param} — {evidence}")
        else:
            warn_line("ไม่พบสัญญาณ injection บนหน้าแรก (ลองเพิ่มพารามิเตอร์เองใน URL)")
        # also scan the homepage body + linked endpoints for flags
        known, cands = extract_flags(page.text)
        flags.extend(known + cands)

    # 4a) login brute force (default creds / PIN / wordlist)
    print()
    print("── Login brute force ──")
    page = httpx.get(base + "/", timeout=10)
    if page is not None:
        login_find, login_flags = login_mod.run_login_brute(base, page.text)
        for line in login_find:
            print(line)
        flags.extend(login_flags)
        if not login_find:
            warn_line("ไม่พบฟอร์ม login / ยังไม่เจอ credential ที่ใช้ได้")

    # 5) JWT + cookies
    print()
    print("── Cookies & JWT ──")
    set_cookies = probe.headers.get_all("set-cookie") if hasattr(probe.headers, "get_all") else []
    if not set_cookies:
        sc = probe.headers.get("set-cookie")
        if sc:
            set_cookies = [sc]
    if set_cookies:
        cookies = cookies_mod.parse_cookies(set_cookies)
        findings, cookie_flags = cookies_mod.analyze_cookies(cookies)
        for line in findings:
            print(line)
        flags.extend(cookie_flags)
        # forge unsigned base64-JSON cookies (role -> admin) and replay
        forge_find, forge_flags = cookies_mod.forge_cookies(cookies, base)
        for line in forge_find:
            print(line)
        flags.extend(forge_flags)
        for c in cookies:
            if c["value"].count(".") == 2 and len(c["value"]) > 40:
                info_line(f"วิเคราะห์ JWT ใน cookie {c['name']} ...")
                res = jwt_mod.analyze_jwt(c["value"])
                if res["header"]:
                    print(f"    header : {res['header']}")
                    print(f"    payload: {res['payload']}")
                for issue in res["issues"]:
                    print(f"    [!] {issue}")
                if res.get("secret"):
                    info_line(f"    token ที่ forge ได้: {res['forged'][:60]}...")
    else:
        warn_line("ไม่พบ cookie")

    # dedupe flags
    flags = list(dict.fromkeys(flags))
    print()
    if flags:
        section("🏁 FLAGS ที่พบ")
        for f in flags:
            flag_line(f)
    else:
        warn_line("ยังไม่เจอ flag — ลองรัน injections กับ endpoint อื่น หรือดู source")
    return flags
