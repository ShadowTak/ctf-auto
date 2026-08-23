"""Web category orchestrator: recon -> dirbust -> leaks -> injections ->
JWT/cookies -> flag collection. The independent deep phases (deep interact,
error trigger, backups, injection fuzz, login brute, cookies) run CONCURRENTLY
after dirbust — each is internally threaded already, so wall time drops from
the sum of phases to the slowest phase."""
from core import httpx
from core.evidence import findings_from_flags
from core.flag import extract_flags
from core.output import flag_line, info_line, ok_line, section, warn_line
from . import assets as assets_mod
from . import advanced as advanced_mod
from . import backups as backups_mod
from . import blind_sqli as blind_mod
from . import browser as browser_mod
from . import cookies as cookies_mod
from . import ctr_bitflip as ctr_mod
from . import discovery as discovery_mod
from . import deser as deser_mod
from . import directories as dirs_mod
from . import errors as errors_mod
from . import graphql as graphql_mod
from . import interact as interact_mod
from . import injections as inj_mod
from . import jwt as jwt_mod
from . import login as login_mod
from . import recon as recon_mod


def _cookie_headers(response):
    """Return Set-Cookie values, including cookies learned across redirects."""
    if response is None:
        return []
    headers = response.headers
    values = headers.get_all("set-cookie") if hasattr(headers, "get_all") else []
    if not values:
        value = headers.get("set-cookie")
        if value:
            values = [value]
    if not values:
        values = [f"{name}={value}"
                  for name, value in httpx.cookie_snapshot().items()]
    return values


def _response_flags(response):
    """Extract flags from body and metadata, including redirect headers."""
    if response is None:
        return []
    values = [response.text, response.headers.get("location", "")]
    for key, value in response.headers.items():
        if "flag" in key.lower() or key.lower() in {
                "x-debug", "x-internal-response", "x-secret"}:
            values.append(str(value))
    found = []
    for value in values:
        known, candidates = extract_flags(value)
        for item in known + candidates:
            if item not in found:
                found.append(item)
    return found


def _unique_urls(base, values, limit=100):
    """Normalize discovered paths/URLs and keep deterministic scan order."""
    out, seen = [], set()
    for value in values:
        raw = str(value or "").strip()
        if not raw:
            continue
        url = raw if raw.startswith(("http://", "https://")) else \
            base.rstrip("/") + "/" + raw.lstrip("/")
        url = url.rstrip("/") or base.rstrip("/")
        if url not in seen:
            seen.add(url)
            out.append(url)
        if len(out) >= limit:
            break
    return out


def run_web(target, interactive=False, use_browser=False, reset_session=True):
    """Public entry. target = URL. Returns list of flags found.

    A scan owns its cookie/auth state by default. This prevents a batch such
    as auto-lab from carrying a flag cookie or bearer token from target A into
    target B. Callers running an intentional authenticated multi-target flow
    can opt out with ``reset_session=False``.
    """
    if reset_session:
        httpx.reset_session()
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
    flags.extend(_response_flags(probe))

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

    # 2b) bounded recursive discovery: navigation/forms/JS/source maps and
    # OpenAPI/Swagger JSON are often the only place a challenge exposes its
    # real API routes. Keep it bounded so the exploit phases stay predictable.
    print()
    print("── Recursive route / API discovery ──")
    discovery_findings, discovery_flags, discovered_paths, discovered_pages = \
        discovery_mod.crawl(base, max_pages=36, max_depth=2, workers=12)
    for line in discovery_findings:
        print(line)
    flags.extend(discovery_flags)
    extra_paths.extend(discovered_paths)
    if discovered_pages:
        ok_line(f"ค้นหน้า/endpoint เพิ่ม {len(discovered_pages)} รายการ, route {len(discovered_paths)} รายการ")
    if use_browser:
        print()
        print("── Dynamic browser/API discovery (read-only) ──")
        browser_findings, browser_flags, browser_paths, browser_error = \
            browser_mod.crawl_dynamic(base)
        for line in browser_findings:
            print(line)
        if browser_error:
            warn_line(f"browser discovery: {browser_error}")
        flags.extend(browser_flags)
        extra_paths.extend(browser_paths)

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
    interesting_statuses = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}
    discovered_endpoints = [
        base + "/" + p for p, s, _, _ in found
        if s in interesting_statuses
    ] + list(extra_paths) + list(discovered_paths)
    ep_200 = _unique_urls(base, discovered_endpoints, limit=100)

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
                    # evidence like "SSRF อ่าน flag ได้ผ่าน url: ['redactedCTF{...}']"
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
        # httpx follows redirects and stores Set-Cookie in its session jar;
        # _cookie_headers recovers it when the final response has no header.
        set_cookies = _cookie_headers(probe)
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
        # deserialization probes over every cookie value (pickle/PHP blobs)
        try:
            samples = {c["name"]: c["value"] for c in cookies}
            deser_find, deser_flags = deser_mod.scan_deserialization(
                base, None, [base], sample_values=samples)
            lines += deser_find
            fl += deser_flags
        except Exception as exc:
            lines.append(f"  [!] deser probe error: {exc}")
        return lines, list(dict.fromkeys(fl))

    def phase_advanced():
        endpoints = _unique_urls(
            base,
            ep_200 + [base + "/" + p for p, _, _, _ in found],
            limit=140,
        )
        findings, fl = advanced_mod.scan_advanced(base, endpoints)
        return findings or ["  [!] ไม่พบ multi-step web exploit ที่ตอบ flag"], fl

    from core.parallel import run_concurrent
    phase_names = [
        ("── Deep interact (IDOR / form POST / endpoint fuzz) ──", phase_deep),
        ("── Error trigger (500 leak hunt) ──", phase_errors),
        ("── Backup / config leak checks ──", phase_backups),
        ("── Injection fuzz (GET params / form fields) ──", phase_injections),
        ("── Login brute force ──", phase_login),
        ("── Cookies & JWT ──", phase_cookies),
        ("── Advanced flows (JWT / GraphQL / SSRF / upload / race) ──", phase_advanced),
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
    # filter: only keep proper CTF flags (known prefix + braces, alnum body)
    from core.flag import FLAG_RE, _body_ratio, _has_code_artifacts
    filtered = []
    for f in flags:
        s = f.strip()
        if FLAG_RE.fullmatch(s):
            filtered.append(s)  # known prefix — always keep
        elif ("{" in s and "}" in s and
              _body_ratio(s) >= 0.85 and
              not _has_code_artifacts(s) and
              len(s) < 200):
            filtered.append(s)  # looks like a real flag
    flags = filtered
    print()
    if flags:
        section("🏁 FLAGS ที่พบ")
        for f in flags:
            flag_line(f)
    else:
        warn_line("ยังไม่เจอ flag — ลองรัน injections กับ endpoint อื่น หรือดู source")
    return flags


def run_web_evidence(target, interactive=False):
    """Run the legacy web scanner and classify returned values as candidates.

    A scanner finding is not scoreboard proof by itself, so callers receive
    evidence-aware candidates while ``run_web`` keeps returning ``list[str]``.
    """
    flags = run_web(target, interactive=interactive)
    return findings_from_flags(
        flags,
        source="web:scanner",
        verified=False,
        confidence=0.78,
        evidence=("flag-shaped value returned by scanner",),
    )
