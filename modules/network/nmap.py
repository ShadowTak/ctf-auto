"""Nmap wrapper: uses the nmap binary when present, falls back to a
multi-threaded socket scanner. Returns a list of open ports with
service guesses."""
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from . import nmap_xml

from core.output import info_line

NMAP_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 631,
    993, 995, 1025, 1080, 1433, 1521, 1723, 2049, 2121, 2222, 2375, 2376,
    3000, 3128, 3306, 3389, 4000, 4444, 5000, 5432, 5555, 5601, 5900, 5984,
    6000, 6379, 7001, 7070, 8000, 8008, 8009, 8080, 8081, 8088, 8090, 8181,
    8443, 8500, 8888, 9000, 9001, 9042, 9090, 9092, 9200, 9300, 10000, 11211,
    15672, 27017, 27018, 28017, 50000, 50070, 50090, 55554, 40000, 40001,
    40002, 40010, 40020, 40030, 40040, 40050, 40100, 40110, 50001, 50010,
    50020, 50030, 50040, 50050, 50100, 50110,
]

SERVICE_GUESS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "smtp",
    631: "ipp", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2222: "ssh", 2375: "docker",
    2376: "docker-tls", 3000: "http-alt", 3128: "squid", 3306: "mysql",
    3389: "rdp", 4000: "http", 4444: "http", 5000: "http", 5432: "postgresql",
    5555: "adb", 5601: "kibana", 5900: "vnc", 5984: "couchdb", 6000: "x11",
    6379: "redis", 7001: "weblogic", 7070: "http", 8000: "http-alt",
    8008: "http", 8009: "ajp", 8080: "http-proxy", 8081: "http", 8088: "http",
    8090: "http", 8181: "http", 8443: "https-alt", 8500: "http", 8888: "http",
    9000: "http", 9001: "http", 9042: "cassandra", 9090: "http", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch", 10000: "webmin",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongod",
    27018: "mongod", 28017: "mongod-http", 50000: "sap", 50070: "hdfs",
    50090: "hdfs", 40000: "lab-http", 50000: "lab-http",
}


def _run_nmap(host, ports=None, fast=True):
    """Run nmap; returns dict: {port: {service, version, banner, extra}}."""
    if ports:
        port_arg = ",".join(str(p) for p in ports)
    else:
        port_arg = "--top-ports 1000"
    cmd = ["nmap", "-Pn", "-T4", "-sV", "--open", "-p", port_arg, host]
    if fast:
        cmd = ["nmap", "-Pn", "-T4", "--open", "-p", port_arg, host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}
    text = out.stdout
    results = {}
    current = None
    for line in text.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$", line.strip())
        if m:
            port = int(m.group(1))
            state = m.group(3)
            if state != "open":
                continue
            service = m.group(4)
            extra = (m.group(5) or "").strip()
            results[port] = {"service": service, "info": extra}
    return results


def _socket_scan(host, ports, timeout=1.2, workers=256):
    """Multi-threaded TCP connect scan (fallback when nmap is missing)."""
    def try_port(port):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except OSError:
            return None

    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for p in pool.map(try_port, ports):
            if p:
                open_ports.append(p)
    return {p: {"service": SERVICE_GUESS.get(p, "unknown"), "info": ""}
            for p in sorted(open_ports)}


def scan_xml(source):
    """Parse an existing Nmap XML report without invoking external commands."""
    return nmap_xml.flatten_services(source)


def scan_host(host, ports=None, workers=256):
    """Public: scan host, return {port: {service, info}}."""
    if shutil.which("nmap"):
        try:
            res = _run_nmap(host, ports=ports)
            if res:
                return res
        except Exception:
            pass
    # fallback socket scan
    port_list = ports or NMAP_TOP_PORTS
    info_line(f"nmap ไม่พร้อมใช้งาน — ใช้ socket scan แบบเบาๆ ({len(port_list)} ports)")
    return _socket_scan(host, port_list, workers=workers)


def format_results(results):
    lines = []
    for port in sorted(results):
        svc = results[port].get("service", "?")
        info = results[port].get("info", "")
        lines.append(f"  {port:<6} {svc:<22} {info}")
    return lines
