"""DNS recon: record enumeration, zone-transfer attempt, subdomain brute
(socket-based so no dnspython dependency)."""
import os
import random
import socket
import struct

from core.parallel import pmap

WORDLISTS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "wordlists"))

# ---------------------------------------------------------------------------
# Minimal DNS query builder (no dnspython needed)
# ---------------------------------------------------------------------------
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
          "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255}
RTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
          16: "TXT", 28: "AAAA", 33: "SRV"}


def _build_query(name, qtype, txid=None):
    txid = txid or random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(part)]) + part.encode() for part in name.split(".") if part
    ) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)


def _parse_name(data, off):
    labels = []
    jumped = False
    end = off
    while True:
        if off >= len(data):
            break
        ln = data[off]
        if ln == 0:
            if not jumped:
                end = off + 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            off = ptr
            jumped = True
            continue
        off += 1
        if off + ln > len(data):
            break
        labels.append(data[off:off + ln].decode("latin-1", "replace"))
        off += ln
    return ".".join(labels), end


def _parse_response(resp):
    if len(resp) < 12:
        return []
    qdcount = struct.unpack(">H", resp[4:6])[0]
    ancount = struct.unpack(">H", resp[6:8])[0]
    nscount = struct.unpack(">H", resp[8:10])[0]
    off = 12
    for _ in range(qdcount):
        _, off = _parse_name(resp, off)
        off += 4
    answers = []
    for _ in range(ancount + nscount):
        if off >= len(resp):
            break
        name, off = _parse_name(resp, off)
        if off + 10 > len(resp):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", resp[off:off + 10])
        off += 10
        if off + rdlen > len(resp):
            break
        rdata = resp[off:off + rdlen]
        off += rdlen
        answers.append((name, RTYPES.get(rtype, str(rtype)), _format_rdata(rtype, rdata, resp)))
    return answers


def _format_rdata(rtype, rdata, resp):
    if rtype == 1 and len(rdata) == 4:
        return ".".join(str(b) for b in rdata)
    if rtype == 28 and len(rdata) == 16:
        return ":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2))
    if rtype in (5, 2, 12):
        name, _ = _parse_name(rdata, 0)
        return name
    if rtype == 15 and len(rdata) >= 3:
        pref = struct.unpack(">H", rdata[:2])[0]
        name, _ = _parse_name(rdata, 2)
        return f"{pref} {name}"
    if rtype == 16:
        txt = rdata.decode("latin-1", "replace")
        if len(rdata) and rdata[0] <= len(rdata) - 1:
            txt = rdata[1:1 + rdata[0]].decode("latin-1", "replace")
        return txt.replace('"', "")
    if rtype == 6:
        try:
            mname, off = _parse_name(rdata, 0)
            rname, off = _parse_name(rdata, off)
            return f"{mname} {rname}"
        except Exception:
            return rdata.hex()
    return rdata.hex()


def query(domain, qtype="A", server="8.8.8.8", timeout=4):
    """Query a DNS server; returns list of (name, type, value)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_query(domain, QTYPES.get(qtype, 1)), (server, 53))
        resp, _ = sock.recvfrom(4096)
        return _parse_response(resp)
    except OSError:
        return []


def enum_records(domain, server="8.8.8.8"):
    out = []
    for qtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
        ans = query(domain, qtype, server)
        for name, rtype, value in ans:
            out.append((qtype, f"{name}  {rtype}  {value}"))
    return out


def zone_transfer(domain, nameservers):
    """Try AXFR against each NS. Returns records or None."""
    for ns in nameservers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((ns, 53))
            req = _build_query(domain, 252)
            sock.sendall(struct.pack(">H", len(req)) + req)
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 1_000_000:
                    break
            records = _parse_response(data[2:]) if len(data) > 2 else []
            if records:
                return records
        except OSError:
            continue
    return None


def subdomain_brute(domain, wordlist=None, server="8.8.8.8", workers=64):
    """Brute-force subdomains in parallel."""
    path = wordlist or os.path.join(WORDLISTS, "subdomains.txt")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        names = [line.strip() for line in f if line.strip()]

    def check(name):
        ans = query(f"{name}.{domain}", "A", server, timeout=2)
        ips = [v for n, t, v in ans if t == "A"]
        return (name, ips) if ips else None

    found = []
    for r in pmap(check, names, workers=workers, desc="subdomain brute"):
        if r[1]:
            found.append(r[1])
    return sorted(found)
