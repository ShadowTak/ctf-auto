"""Web category orchestrator: recon -> dirbust -> leaks -> injections ->
JWT/cookies -> flag collection. The independent deep phases (deep interact,
error trigger, backups, injection fuzz, login brute, cookies) run CONCURRENTLY
after dirbust — each is internally threaded already, so wall time drops from
the sum of phases to the slowest phase."""
from core import httpx
from core.flag import extract_flags
from core.output import flag_line, info_line, ok_line, section, warn_line
from . import assets as assets_mod
from . import backups as backups_mod
from . import blind_sqli as blind_mod
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

    # 3a-5) deep phases run CONCURRENTLY — each is internally threaded, so the
    # wall time is max(phase) instead of the sum. Every phase returns
    # (print_lines, flags) and the outputs are printed in order afterwards.
    print()
    home = httpx.get(base + "/", timeout=10)
    ep_200 = [base + "/" + p for p, s, _, _ in found if s == 200][:40]

    def phase_deep():
        """IDOR enum + form POST + fuzz every endpoint + CTR/GraphQL/JSON."""
        lines, fl = [], []
        if home is not None:
            idor_find, idor_flags = interact_mod.idor_enum(base, home.text)
            lines += idor_find
            fl += idor_flags
            form_find, form_flags = interact_mod.form_post(base, home.text)
            lines += form_find
            fl += form_flags
        fuzz_hits, fuzz_flags = interact_mod.fuzz_discovered(base, ep_200)
        for tgt, param, kind, ev in fuzz_hits:
            lines.append(f"  [!] {kind}: {tgt} param={param} — {ev}")
        fl += fuzz_flags
        link_hits, link_flags = interact_mod.fuzz_link_params(base, home.text) if home else ([], [])
        for tgt, param, kind, ev in link_hits:
            lines.append(f"  [!] {kind}: {tgt} param={param} — {ev}")
        fl += link_flags
        ctr_endpoints = ep_200 + [
            base + "/encrypt", base + "/decrypt",
            base + "/api/encrypt", base + "/api/decrypt",
            base + "/api/v1/encrypt", base + "/api/v1/decrypt",
        ]
        ctr_find, ctr_flags = ctr_mod.scan_ctr_bitflip(base, ctr_endpoints)
        lines += ctr_find
        fl += ctr_flags
        gql_find, gql_flags = graphql_mod.scan_graphql(base, ctr_endpoints)
        lines += gql_find
        fl += gql_flags
        json_find, json_flags = interact_mod.json_probe(base, ctr_endpoints)
        lines += json_find
        fl += json_flags
        return lines, list(dict.fromkeys(fl))

    def phase_errors():
        endpoints = [base + "/"] + [base + "/" + p for p, s, _, _ in found if s == 200]
        hits, fl = errors_mod.trigger_errors(base, endpoints)
        lines = [f"  [!] {ep} (payload={name}) → 500, leak: {', '.join(leaks)}"
                 for ep, name, leaks in hits]
        if not hits:
            lines = ["  [!] ไม่พบ 500 ที่รั่วข้อมูล"]
        return lines, fl

    def phase_backups():
        findings, fl = backups_mod.run_backup_checks(base)
        lines = [f"  {st:<4} {p:<28} {desc} ({size} bytes)"
                 for p, desc, st, size in findings]
        if not findings:
            lines = ["  [!] ไม่พบไฟล์ leak"]
        return lines, fl

    def phase_injections():
        lines, fl = [], []
        if home is not None:
            hits = inj_mod.fuzz_params(base + "/", home.text)
            if hits:
                for tgt, param, kind, ev in hits:
                    lines.append(f"  [!] {kind}: {tgt} param={param} — {ev}")
                    # evidence like "SSRF อ่าน flag ได้ผ่าน url: ['AegisCTF{...}']"
                    # carries the flag itself — don't drop it
                    known, cands = extract_flags(ev)
                    fl += known + cands
            else:
                lines.append("  [!] ไม่พบสัญญาณ injection บนหน้าแรก (ลองเพิ่มพารามิเตอร์เองใน URL)")
            known, cands = extract_flags(home.text)
            fl += known + cands
            # blind boolean-based SQLi: extract the flag char-by-char via
            # the found/no-match oracle (needs AND payloads inside LIKE)
            try:
                blind_lines, blind_flags = blind_mod.blind_extract(
                    base, home.text, ep_200)
                lines += blind_lines
                fl += blind_flags
            except Exception as e:
                lines.append(f"  [!] blind-sqli error: {e}")
        return lines, fl

    def phase_login():
        lines, fl = [], []
        if home is not None:
            login_find, login_flags = login_mod.run_login_brute(base, home.text)
            lines += login_find
            fl += login_flags
            if not login_find:
                lines.append("  [!] ไม่พบฟอร์ม login / ยังไม่เจอ credential ที่ใช้ได้")
        return lines, fl

    def phase_cookies():
        lines, fl = [], []
        set_cookies = probe.headers.get_all("set-cookie") if hasattr(probe.headers, "get_all") else []
        if not set_cookies:
            sc = probe.headers.get("set-cookie")
            if sc:
                set_cookies = [sc]
        if not set_cookies:
            return ["  [!] ไม่พบ cookie"], []
        cookies = cookies_mod.parse_cookies(set_cookies)
        findings, cookie_flags = cookies_mod.analyze_cookies(cookies)
        lines += findings
        fl += cookie_flags
        forge_find, forge_flags = cookies_mod.forge_cookies(cookies, base)
        lines += forge_find
        fl += forge_flags
        for c in cookies:
            if c["value"].count(".") == 2 and len(c["value"]) > 40:
                lines.append(f"  [*] วิเคราะห์ JWT ใน cookie {c['name']} ...")
                res = jwt_mod.analyze_jwt(c["value"])
                if res["header"]:
                    lines.append(f"    header : {res['header']}")
                    lines.append(f"    payload: {res['payload']}")
                for issue in res["issues"]:
                    lines.append(f"    [!] {issue}")
                if res.get("secret"):
                    lines.append(f"    [*] token ที่ forge ได้: {res['forged'][:60]}...")
        return lines, list(dict.fromkeys(fl))

    from core.parallel import run_concurrent
    phase_names = [
        ("── Deep interact (IDOR / form POST / endpoint fuzz) ──", phase_deep),
        ("── Error trigger (500 leak hunt) ──", phase_errors),
        ("── Backup / config leak checks ──", phase_backups),
        ("── Injection fuzz (GET params / form fields) ──", phase_injections),
        ("── Login brute force ──", phase_login),
        ("── Cookies & JWT ──", phase_cookies),
    ]
    results = run_concurrent(
        [fn for _, fn in phase_names], workers=len(phase_names),
        desc="web deep scan")
    for (title, _), res in zip(phase_names, results):
        print()
        print(title)
        if isinstance(res, Exception):
            warn_line(f"  phase error: {res}")
            continue
        lines, fl = res
        for line in lines:
            print(line)
        flags.extend(fl)

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
