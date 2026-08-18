#!/usr/bin/env python3
"""CTF Auto Recon & Solver — menu-driven auto flag hunter.

Usage:
    python3 run.py                          # interactive menu
    python3 run.py --category web --target http://host:8080
    python3 run.py --category crypto --target "encoded text or /path/file"
    python3 run.py --category network --target 10.10.10.5|capture.pcap
    python3 run.py --category full --target 10.10.10.5
    python3 run.py --module jwt --target <token>
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import flag as flaglib
from core.output import (Report, bold, dim, flag_line, head, info_line,
                         ok_line, section, warn_line)

BANNER = r"""
  ╔══════════════════════════════════════════════════════════════╗
  ║   🚩  CTF AUTO RECON & SOLVER  v1.0                          ║
  ║   web · crypto · network — auto flag hunter (multi-threaded) ║
  ╚══════════════════════════════════════════════════════════════╝
"""


def print_menu(title, items):
    print()
    print(head(f"── {title} ──"))
    for num, (label, desc) in items.items():
        print(f"  [{num}] {label:<34} {dim(desc)}")
    print(f"  [0] กลับเมนูหลัก")


def ask(prompt, default=None):
    try:
        val = input(f"  {prompt} ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return val or default


def input_target(hint="URL (เช่น http://10.10.10.5:8080 / path ไฟล์ / ข้อความ)"):
    return ask(hint)


# ---------------------------------------------------------------------------
# Category runners
# ---------------------------------------------------------------------------
def run_web(target):
    from modules.web.scanner import run_web as _run
    return _run(target)


def run_crypto(target):
    from modules.crypto.autodetect import run_crypto as _run
    return _run(target)


def run_network(target):
    from modules.network.scanner import run_network as _run
    return _run(target, chain_to_web=run_web)


def run_full(target):
    """Auto chain: network scan -> auto web scan on discovered services."""
    section("⚡ AUTO FULL (network -> web chain)")
    info_line(f"target: {target}")
    flags = run_network(target, chain_to_web=run_web)
    if not flags:
        # maybe the target is a web app directly
        info_line("ไม่พบ web service จาก network scan — ลองรัน web scan ตรงๆ")
        from core import httpx
        flags = run_web(httpx.normalize_url(target))
    return flags


def run_crypto_module(choice, target):
    from modules.crypto import autodetect, classic, encodings, hashes, modern, rsa, xor
    from core.output import ok_line

    if choice == "1":
        return autodetect.run_crypto(target)
    if choice == "2":
        section("🔢 ENCODINGS")
        text = _read_target(target)
        for label, out in encodings.try_all_encodings(text)[:20]:
            if out != text:
                ok_line(f"{label}: {out[:150]}")
        return []
    if choice == "3":
        section("🏛️ CLASSIC CIPHERS")
        text = _read_target(target)
        for label, out in classic.try_all_classic(text)[:15]:
            if out != text:
                ok_line(f"{label}: {out[:150]}")
        return []
    if choice == "4":
        section("🔑 RSA ATTACKS")
        key = ask("ป้อน PEM path / n,e,c (คั่นด้วยช่องว่าง):")
        if os.path.isfile(key):
            with open(key, encoding="utf-8", errors="ignore") as f:
                pem = f.read()
            info_line(f"อ่าน key จาก {key}")
            results = rsa.crack_rsa(pem=pem, c=_ask_big("c (ciphertext int / hex / file):"))
        else:
            parts = key.split()
            vals = {}
            for p in parts:
                k, _, v = p.partition("=")
                vals[k.strip().lower()] = v.strip()
            results = rsa.crack_rsa(
                n=int(vals.get("n", 0) or 0) or None,
                e=int(vals.get("e", 0) or 0) or None,
                c=_ask_big("c:"),
            )
        if results:
            for label, pt in results:
                ok_line(f"[{label}] {pt[:200]}")
        else:
            warn_line("RSA attack ไม่สำเร็จ — ลองให้ n,e,c ครบ หรือ file PEM")
        return []
    if choice == "5":
        section("➰ XOR")
        text = _read_target(target)
        for label, out in xor.crack_xor(text)[:15]:
            ok_line(f"{label}: {out[:150]}")
        return []
    if choice == "6":
        section("🔓 HASH CRACK")
        h = target.strip()
        names = hashes.identify_hash(h)
        ok_line(f"ประเภทที่เป็นไปได้: {', '.join(names)}")
        cracked = hashes.crack_hash(h)
        if cracked:
            flag_line(f"CRACKED: {cracked}")
        else:
            warn_line("ยัง crack ไม่ได้ (wordlist ยังไม่ตรง) — ลอง ROCKYOU env: ROCKYOU=/path/rockyou.txt")
        return [cracked] if cracked else []
    if choice == "7":
        section("⛓️ CHAIN DECODE")
        text = _read_target(target)
        stages = encodings.chain_decode(text)
        if stages:
            for name, out in stages:
                ok_line(f"{name}: {out[:200]}")
        else:
            warn_line("ไม่พบ layer ต่อ")
        return []
    return []


def _read_target(target):
    import os
    if os.path.isfile(target):
        with open(target, encoding="utf-8", errors="ignore") as f:
            return f.read()
    return target


def _ask_big(prompt):
    val = ask(prompt)
    if not val:
        return None
    val = val.strip()
    if os.path.isfile(val):
        with open(val, encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
        if content.startswith("-----BEGIN"):
            return None
        val = content
    import re
    try:
        if val.lower().startswith(("0x", "-0x")):
            return int(val, 16)
        if re.search(r"[a-fA-F]", val) and re.fullmatch(r"[0-9a-fA-F]+", val):
            return int(val, 16)
        return int(val)
    except ValueError:
        return None


def run_web_module(choice, target):
    from modules.web import backups, cookies, directories, injections, jwt, recon
    from core import httpx
    from core.output import ok_line

    base = httpx.normalize_url(target)

    if choice == "1":
        from modules.web.scanner import run_web as _run
        return _run(base)
    if choice == "2":
        section("🧭 RECON")
        paths, flags = recon.run_recon(base)
        for f in flags:
            flag_line(f)
        return flags
    if choice == "3":
        section("📂 DIRECTORY BRUTE")
        buster = directories.DirBuster(base)
        found = buster.run()
        for line in directories.format_results(found):
            print(line)
        return directories.scan_for_flags(found, base)
    if choice == "4":
        section("💉 INJECTIONS")
        page = httpx.get(base + "/", timeout=10)
        if page is None:
            warn_line("เชื่อมต่อไม่ได้")
            return []
        hits = injections.fuzz_params(base + "/", page.text)
        for target, param, kind, evidence in hits:
            ok_line(f"[{kind}] {target} param={param} — {evidence}")
        if not hits:
            warn_line("ไม่พบสัญญาณ injection")
        return []
    if choice == "5":
        section("🍪 COOKIES & JWT")
        r = httpx.get(base + "/", timeout=10)
        if r is None:
            return []
        sc = r.headers.get("set-cookie")
        set_cookies = [sc] if sc else []
        cookies_list = cookies.parse_cookies(set_cookies)
        findings, flags = cookies.analyze_cookies(cookies_list)
        for line in findings:
            print(line)
        for c in cookies_list:
            if c["value"].count(".") == 2 and len(c["value"]) > 40:
                res = jwt.analyze_jwt(c["value"])
                if res["header"]:
                    print(f"    payload: {res['payload']}")
                for issue in res["issues"]:
                    print(f"    [!] {issue}")
                flags.extend(flaglib.extract_flags(str(res["payload"]))[0])
        return flags
    if choice == "6":
        section("🗄️ BACKUP / LEAK CHECKS")
        findings, flags = backups.run_backup_checks(base)
        for path, desc, status, size in findings:
            print(f"  {status:<4} {path:<28} {desc}")
        for f in flags:
            flag_line(f)
        return flags
    return []


def run_network_module(choice, target):
    from modules.network import dns, nmap, pcap, services
    from core.output import ok_line

    if choice == "1":
        return run_network(target)
    if choice == "2":
        section("🔎 PORT SCAN")
        results = nmap.scan_host(target)
        for line in nmap.format_results(results):
            print(line)
        return []
    if choice == "3":
        section("📡 BANNER GRAB")
        results = nmap.scan_host(target)
        for port, banner in services.probe_services(target, list(results.keys())):
            print(f"  [{port}] {banner[:160]}")
        return []
    if choice == "4":
        section("💾 PCAP ANALYSIS")
        info = pcap.analyze_pcap(target)
        for line in pcap.format_pcap_report(info):
            print("  " + line)
        for f in info["flags"]:
            flag_line(f)
        return info["flags"]
    if choice == "5":
        section("🌐 DNS RECON")
        records = dns.enum_records(target)
        for _, rec in records:
            print(f"  {rec}")
        ns = [v.split()[0] for _, r in records if r.startswith("NS") and " " in r]
        if ns:
            xfer = dns.zone_transfer(target, ns)
            if xfer:
                ok_line("zone transfer สำเร็จ:")
                for name, rtype, value in xfer:
                    print(f"  {name} {rtype} {value}")
        found = dns.subdomain_brute(target)
        for name, ips in found:
            print(f"  {name}.{target} -> {','.join(ips)}")
        return []
    return []


# ---------------------------------------------------------------------------
# Menus
# ---------------------------------------------------------------------------
def main_menu():
    items = {
        "1": ("Web scan", "สแกนเว็บ: recon / dirbust / inject / JWT / leaks"),
        "2": ("Crypto auto-decode", "decode ทุกวิธี + crack hash / RSA / XOR"),
        "3": ("Network recon", "nmap / banner / pcap / DNS"),
        "4": ("⚡ Auto Full", "network -> web chain อัตโนมัติทั้งสาย"),
        "5": ("⚡ Auto Lab", "สแกนแลปใน stack อัตโนมัติ (web/crypto)"),
        "6": ("โหมดละเอียด (เลือกโมดูล)", "เลือกโมดูลย่อยทีละตัว"),
        "9": ("About / วิธีใช้", "รายละเอียดการใช้งาน"),
    }
    print_menu("MAIN MENU", items)
    choice = ask("เลือก:")
    return choice


def submenu_crypto():
    items = {
        "1": ("Auto-detect ทั้งหมด", "รันทุกวิธี parallel + จัดอันดับ"),
        "2": ("Encodings", "base*/hex/binary/morse/brainfuck..."),
        "3": ("Classic ciphers", "caesar/vigenere/affine/substitution..."),
        "4": ("RSA attacks", "small-e / wiener / fermat / pem"),
        "5": ("XOR", "single/repeating/crib"),
        "6": ("Hash crack", "identify + wordlist"),
        "7": ("Chain decode", "ถอด layer ซ้อนกัน"),
    }
    print_menu("CRYPTO", items)
    choice = ask("เลือก:")
    if choice == "0":
        return None
    if choice == "4":  # RSA has its own prompts (pem / n,e,c)
        target = None
    else:
        target = input_target("ข้อความ หรือ path ไฟล์:")
    run_crypto_module(choice, target)


def submenu_web():
    items = {
        "1": ("รันทุกอย่าง (full web scan)", "recon+dirbust+inject+jwt+leak"),
        "2": ("Recon เท่านั้น", "headers / robots / tech / flags"),
        "3": ("Directory brute", "หา endpoint กับ wordlist 450+"),
        "4": ("Injection fuzz", "SQLi/XSS/LFI/SSTI/CMDi/redirect/SSRF"),
        "5": ("Cookies & JWT", "วิเคราะห์ + crack secret + forge"),
        "6": ("Backup / config leak", ".git/.env/.bak/config"),
    }
    print_menu("WEB", items)
    choice = ask("เลือก:")
    if choice == "0":
        return None
    target = input_target("URL (เช่น http://10.10.10.5:8080):")
    run_web_module(choice, target)


def submenu_network():
    items = {
        "1": ("รันทุกอย่าง (full network)", "scan+banner+dns+web discovery"),
        "2": ("Port scan", "nmap (หรือ socket fallback)"),
        "3": ("Banner grab", "ดึง banner จาก service"),
        "4": ("PCAP analyze", "reassemble TCP / HTTP / หา flag"),
        "5": ("DNS recon", "records / zone transfer / subdomain brute"),
    }
    print_menu("NETWORK", items)
    choice = ask("เลือก:")
    if choice == "0":
        return None
    target = input_target("host/IP หรือ path pcap:")
    run_network_module(choice, target)


def about():
    section("ABOUT")
    print("""
  CTF Auto Recon & Solver v1.0 — Python stdlib เท่านั้น (ไม่มี dependency)
  หมวด: web / crypto / network + auto chain
  ตัวอย่าง:
    python3 run.py --category crypto --target "VlFTeFFSeVdSUmlCQlFTeVNCU0JDQVJRQUFJ"
    python3 run.py --category crypto --target cipher.txt
    python3 run.py --category web --target http://target:8080
    python3 run.py --category network --target 10.10.10.5
    python3 run.py --category network --target capture.pcap
    python3 run.py --category full --target 10.10.10.5
    python3 run.py --module jwt --target <token>
  environment:
    ROCKYOU=/path/rockyou.txt   # wordlist เพิ่มสำหรับ hash crack
  รายงานถูกบันทึกที่ reports/<timestamp>.txt
""")


# ---------------------------------------------------------------------------
# CLI dispatch
# ---------------------------------------------------------------------------
def dispatch(args):
    report = Report()
    flags = []
    if args.category == "web":
        flags = run_web(args.target)
    elif args.category == "crypto":
        flags = run_crypto(args.target)
    elif args.category == "network":
        flags = run_network(args.target)
    elif args.category == "full":
        flags = run_full(args.target)
    elif args.module == "jwt":
        from modules.web import jwt
        res = jwt.analyze_jwt(args.target)
        if res["header"]:
            print(f"  header : {res['header']}")
            print(f"  payload: {res['payload']}")
        for issue in res["issues"]:
            print(f"  [!] {issue}")
        if res.get("secret"):
            info_line(f"  token ที่ forge ได้: {res['forged'][:80]}...")
        flags = flaglib.extract_flags(str(res.get("payload", "")))[0]
    else:
        print(BANNER)
        print(dim("พิมพ์ python3 run.py --help เพื่อดู CLI usage"))
        while True:
            try:
                choice = main_menu()
            except (EOFError, KeyboardInterrupt):
                break
            if choice in (None, "0"):
                break
            if choice == "1":
                submenu_web()
            elif choice == "2":
                submenu_crypto()
            elif choice == "3":
                submenu_network()
            elif choice == "4":
                target = input_target("host/IP (จะ auto chain ไปหาเว็บ):")
                if target:
                    flags = run_full(target)
            elif choice == "5":
                cat = ask("หมวดแลป [w]eb / [c]rypto / [a]ll (default all):") or "all"
                cat = {"w": "web", "c": "crypto", "a": "all"}.get(cat.lower(), "all")
                import autolab
                autolab.auto_lab(category=None if cat == "all" else cat)
            elif choice == "6":
                sub = ask("เลือกหมวดละเอียด [w]eb / [c]rypto / [n]etwork:")
                if sub.lower() in ("w", "web"):
                    submenu_web()
                elif sub.lower() in ("c", "crypto"):
                    submenu_crypto()
                elif sub.lower() in ("n", "network"):
                    submenu_network()
            elif choice == "9":
                about()
            else:
                warn_line("ตัวเลือกไม่ถูกต้อง")
        print()
        print(dim("จบการทำงาน — ขอบคุณที่ใช้ CTF Auto Recon & Solver"))

    path = report.save()
    if flags:
        print()
        section("🏁 SUMMARY")
        for f in flags:
            flag_line(f)
    info_line(f"บันทึกรายงาน: {path}")
    return flags


def main():
    parser = argparse.ArgumentParser(description="CTF Auto Recon & Solver")
    parser.add_argument("--category", choices=["web", "crypto", "network", "full"],
                        help="หมวดที่ต้องการรัน")
    parser.add_argument("--module", help="โมดูลเดี่ยว (เช่น jwt)")
    parser.add_argument("--target", help="URL / host / path ไฟล์ / ข้อความ")
    parser.add_argument("--auto-lab", nargs="?", const="all", default=None,
                        choices=["web", "crypto", "all"],
                        help="สแกนแลปใน stack อัตโนมัติ (web / crypto / all)")
    parser.add_argument("--limit", type=int, default=None,
                        help="จำกัดจำนวนแลปที่สแกน (ใช้กับ --auto-lab)")
    args = parser.parse_args()
    if args.auto_lab:
        import autolab
        autolab.auto_lab(category=args.auto_lab, limit=args.limit)
        return
    if (args.category or args.module) and not args.target:
        parser.error("ต้องระบุ --target ด้วยเมื่อใช้ --category/--module")
    dispatch(args)


if __name__ == "__main__":
    main()
