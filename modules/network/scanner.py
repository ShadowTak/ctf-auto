"""Network category orchestrator: port scan -> banners -> web discovery,
and pcap / DNS analysis."""
import ipaddress
import os
import re

from core import httpx
from core.flag import extract_flags
from core.output import info_line, ok_line, section, warn_line
from . import dns as dns_mod
from . import nmap as nmap_mod
from . import pcap as pcap_mod
from . import services as services_mod
from . import intelligence as intelligence_mod


def _is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _is_pcap(path):
    return os.path.isfile(path) and os.path.getsize(path) > 0


def run_network(target, chain_to_web=None, interactive=False):
    """Public entry. chain_to_web: callable(url) invoked for found web services."""
    section("🌍 NETWORK RECON")
    info_line(f"target: {target}")

    if _is_pcap(target):
        return _analyze_pcap(target)

    if not _is_ip(target) and not re.match(r"^[a-zA-Z0-9.\-]+$", target):
        warn_line("เป้าหมายดูไม่ใช่ host/IP — ถ้าเป็นไฟล์ pcap ควรลงท้าย .pcap/.pcapng")
        return []

    flags_found = []
    host = target
    indicators = {"links": [], "secrets": [], "ips": [], "decoded_blobs": []}

    # 1) port scan
    print()
    info_line("ขั้น 1: สแกนพอร์ต ...")
    results = nmap_mod.scan_host(host)
    if not results:
        warn_line("ไม่พบพอร์ตเปิด (หรือ host ไม่ออนไลน์)")
        return []
    ok_line(f"พบ {len(results)} พอร์ตเปิด:")
    for line in nmap_mod.format_results(results):
        print(line)

    open_ports = list(results.keys())

    # 2) banner grab
    print()
    info_line("ขั้น 2: เก็บ banner ...")
    banners = services_mod.probe_services(host, open_ports)
    for port, banner in banners:
        b = banner if len(banner) < 160 else banner[:157] + "..."
        print(f"  [{port}] {b}")
        extracted = intelligence_mod.extract_indicators(banner, source=f"banner:{port}")
        indicators["links"].extend(extracted["links"])
        indicators["secrets"].extend(extracted["secrets"])
        indicators["ips"].extend(extracted["ips"])
        indicators["decoded_blobs"].extend(extracted["decoded_blobs"])
        flags_found.extend(extracted["flags"])
        if "FLAG IN BANNER" in banner:
            flags_found.append(banner)

    # 3) DNS recon if domain
    if not _is_ip(host):
        print()
        info_line("ขั้น 3: DNS recon ...")
        records = dns_mod.enum_records(host)
        shown = set()
        for _, rec in records:
            if rec not in shown:
                shown.add(rec)
                print(f"  {rec}")
                for _, f in extract_flags(rec):
                    if f not in flags_found:
                        flags_found.append(f)
        ns_servers = [v.split()[0] for _, r in records if r.startswith("NS") and " " in r]
        if ns_servers:
            info_line("ลอง zone transfer (AXFR) ...")
            xfer = dns_mod.zone_transfer(host, ns_servers)
            if xfer:
                ok_line("✅ Zone transfer สำเร็จ! บันทึก:")
                for name, rtype, value in xfer:
                    line = f"{name}  {rtype}  {value}"
                    print(f"  {line}")
                    extracted = intelligence_mod.extract_indicators(line, source="dns")
                    indicators["links"].extend(extracted["links"])
                    indicators["secrets"].extend(extracted["secrets"])
            else:
                warn_line("zone transfer ถูกปฏิเสธ")
        found = dns_mod.subdomain_brute(host)
        if found:
            ok_line(f"พบ subdomain ({len(found)}):")
            for name, ips in found:
                print(f"  {name}.{host} -> {','.join(ips)}")
                for ip in ips:
                    if ip not in flags_found:
                        pass
        else:
            warn_line("ไม่พบ subdomain เพิ่มเติม")

    # 4) web service discovery -> chain
    print()
    info_line("ขั้น 4: ค้นหา web service ...")
    web_services = services_mod.find_web_services(host, open_ports)
    if web_services:
        for port, url in web_services:
            ok_line(f"พบ web service: {url}")
        if chain_to_web:
            print()
            info_line("เรียกใช้ web scanner อัตโนมัติกับบริการที่พบ ...")
            for _, url in web_services:
                try:
                    flags_found.extend(chain_to_web(url))
                except Exception as exc:  # noqa: BLE001
                    warn_line(f"web scan {url} ล้มเหลว: {exc}")
    else:
        warn_line("ไม่พบ web service — ลองใช้โหมด web ตรงๆ")

    links = {item["url"]: item for item in indicators["links"]}
    if links:
        section("🔗 SUSPICIOUS LINKS / NETWORK INDICATORS")
        for item in sorted(links.values(), key=lambda x: (-x["score"], x["url"]))[:100]:
            marker = "!!!" if item["score"] >= 50 else "!" if item["score"] >= 25 else "*"
            reason = "; ".join(item["reasons"])
            print(f"  [{marker}] score={item['score']:>3} {item['url']} — {reason}")
    for secret in indicators["secrets"][:50]:
        print(f"  [!] credential-like value in {secret['source']}: {secret['value'][:120]}")
    return list(dict.fromkeys(flags_found))


def _analyze_pcap(path):
    info_line("วิเคราะห์ไฟล์ pcap/pcapng ...")
    info = pcap_mod.analyze_pcap(path)
    for line in pcap_mod.format_pcap_report(info):
        print("  " + line)
    indicators = {"links": [], "secrets": [], "ips": [], "decoded_blobs": []}
    for _, _, req, resp in info.get("http", []):
        for blob, source in ((req, "pcap:http-request"), (resp, "pcap:http-response")):
            extracted = intelligence_mod.extract_indicators(
                blob.decode("latin-1", "replace"), source=source)
            for key in indicators:
                indicators[key].extend(extracted[key])
    for _, _, _, _, payload in info.get("udp", []):
        extracted = intelligence_mod.extract_indicators(payload.decode("latin-1", "replace"), source="pcap:udp")
        for key in indicators:
            indicators[key].extend(extracted[key])
    for _, _, payload in info.get("icmp", []):
        extracted = intelligence_mod.extract_indicators(payload.decode("latin-1", "replace"), source="pcap:icmp")
        for key in indicators:
            indicators[key].extend(extracted[key])
    for item in indicators["links"][:100]:
        print(f"  [link score={item['score']}] {item['url']} — {'; '.join(item['reasons'])}")
    for item in indicators["decoded_blobs"][:20]:
        print(f"  [decoded blob] {item['decoded'][:180]}")
    flags = info["flags"]
    if flags:
        ok_line("FLAG ที่พบใน traffic:")
        for f in flags:
            print("  🏁 " + f)
    else:
        warn_line("ไม่พบ flag ใน traffic — ลองโหมด crypto กับไฟล์ที่ extract")
    return flags
