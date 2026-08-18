"""Banner grabbing and light service probing for common CTF services."""
import socket
import ssl

from core import httpx
from core.flag import extract_flags

BANNER_PROBES = {
    21: b"",
    22: b"",
    23: b"",
    25: b"EHLO localhost\r\n",
    110: b"",
    143: b"",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
    11211: b"stats\r\n",
    5900: b"",
    111: b"",
    2049: b"",
}

SERVICE_COMMANDS = {
    "ftp": ("USER anonymous\r\n",),
    "smtp": ("HELO test\r\n", "EHLO test\r\n"),
    "pop3": ("USER test\r\n",),
    "imap": (b"a001 CAPABILITY\r\n",),
    "redis": ("PING\r\n", "INFO\r\n", "CONFIG GET dir\r\n"),
    "mysql": (),
    "mongodb": (),
}


def grab_banner(host, port, timeout=5):
    """Return banner string or None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # TLS first if it looks like TLS port or https-ish
            if port in (443, 8443, 993, 995, 465, 2376):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=host)
                except ssl.SSLError:
                    pass
            data = s.recv(2048)
            for probe in SERVICE_COMMANDS.get(port, ()) or BANNER_PROBES.get(port, b""):
                if isinstance(probe, str):
                    probe = probe.encode()
                try:
                    s.sendall(probe)
                    chunk = s.recv(2048)
                    if chunk:
                        data = data + chunk
                        break
                except OSError:
                    break
            if isinstance(s, ssl.SSLSocket):
                s.unwrap()
            return data.decode("latin-1", "replace").strip() or None
    except OSError:
        return None


def probe_services(host, ports):
    """Grab banners for interesting ports in parallel."""
    from core.parallel import pmap

    results = []
    items = [(p, grab_banner(host, p)) for p in ports]
    # keep it sequential-ish but each grab has its own timeout; parallel helps
    # for many ports so use the thread pool when > 5 ports
    if len(items) > 5:
        def do(p):
            return p, grab_banner(host, p)
        items = [r for r in pmap(do, ports, workers=16, desc="banner grab") if r[1]]
    for port, banner in items:
        if banner:
            results.append((port, banner))
            known, _ = extract_flags(banner)
            if known:
                results.append((port, f"FLAG IN BANNER: {known}"))
    return results


def find_web_services(host, ports):
    """Return list of (port, base_url) for ports that speak HTTP."""
    urls = []
    for port in ports:
        r = httpx.try_http(host, port, timeout=4)
        if r is not None and r.status < 500:
            scheme = "https" if port in (443, 8443) else "http"
            urls.append((port, f"{scheme}://{host}:{port}"))
    return urls
