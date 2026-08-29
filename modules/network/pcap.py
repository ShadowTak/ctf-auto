"""Pure-Python pcap/pcapng parser: extracts connections, reassembles TCP
streams, pulls HTTP requests/responses and hunts for flags & secrets.
No third-party deps (dpkt/scapy not required)."""
import base64
import re
import struct
import time
from collections import defaultdict

from core import flag as flaglib
from . import intelligence as intelligence_mod
from . import protocol_parsers as proto_mod

MAX_STREAM = 8 * 1024 * 1024  # 8MB cap per TCP stream

# ---------------------------------------------------------------------------
# Low-level parsing
# ---------------------------------------------------------------------------
LINKTYPE = {
    1: "ETHERNET", 101: "RAW_IP", 108: "LOOP", 113: "LINUX_SLL", 0: "BSD_LOOP",
}


class Packet:
    __slots__ = ("ts", "src", "dst", "proto", "sport", "dport", "payload", "flags")

    def __init__(self):
        self.ts = 0.0
        self.src = ""
        self.dst = ""
        self.proto = ""
        self.sport = 0
        self.dport = 0
        self.payload = b""
        self.flags = ""


def _parse_ethernet(data, pkt):
    if len(data) < 14:
        return
    ethertype = int.from_bytes(data[12:14], "big")
    payload = data[14:]
    if ethertype == 0x0800:
        _parse_ipv4(payload, pkt)
    elif ethertype == 0x86DD:
        _parse_ipv6(payload, pkt)


def _parse_ipv4(data, pkt):
    if len(data) < 20:
        return
    ihl = (data[0] & 0x0F) * 4
    proto = data[9]
    pkt.src = ".".join(str(b) for b in data[12:16])
    pkt.dst = ".".join(str(b) for b in data[16:20])
    payload = data[ihl:]
    if proto == 6:
        pkt.proto = "TCP"
        _parse_tcp(payload, pkt)
    elif proto == 17:
        pkt.proto = "UDP"
        _parse_udp(payload, pkt)
    elif proto == 1:
        pkt.proto = "ICMP"
        pkt.payload = payload[4:] if len(payload) > 4 else b""


def _parse_ipv6(data, pkt):
    if len(data) < 40:
        return
    nxt = data[6]
    src = data[8:24]
    dst = data[24:40]
    pkt.src = ":".join(f"{src[i]:02x}{src[i+1]:02x}" for i in range(0, 16, 2))
    pkt.dst = ":".join(f"{dst[i]:02x}{dst[i+1]:02x}" for i in range(0, 16, 2))
    payload = data[40:]
    if nxt == 6:
        pkt.proto = "TCP"
        _parse_tcp(payload, pkt)
    elif nxt == 17:
        pkt.proto = "UDP"
        _parse_udp(payload, pkt)
    elif nxt == 58:
        pkt.proto = "ICMPv6"
        pkt.payload = payload[4:] if len(payload) > 4 else b""


def _parse_tcp(data, pkt):
    if len(data) < 20:
        return
    pkt.sport = int.from_bytes(data[0:2], "big")
    pkt.dport = int.from_bytes(data[2:4], "big")
    doff = (data[12] >> 4) * 4
    fl = data[13]
    fstr = ""
    for bit, name in ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "A")):
        if fl & bit:
            fstr += name
    pkt.flags = fstr
    pkt.payload = data[doff:] if doff <= len(data) else b""


def _parse_udp(data, pkt):
    if len(data) < 8:
        return
    pkt.sport = int.from_bytes(data[0:2], "big")
    pkt.dport = int.from_bytes(data[2:4], "big")
    pkt.payload = data[8:]


def _iter_pcap(data):
    """Yield Packet from classic pcap bytes."""
    if len(data) < 24:
        return
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    elif magic == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    else:
        return
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl_len > len(data):
            break
        raw = data[off:off + incl_len]
        off += incl_len
        pkt = Packet()
        pkt.ts = ts_sec + ts_usec / 1e6
        if linktype == 1:
            _parse_ethernet(raw, pkt)
        elif linktype in (101,):
            _parse_ipv4(raw, pkt)
        elif linktype in (0, 108):
            if len(raw) >= 4:
                _parse_ipv4(raw[4:], pkt)
        elif linktype == 113:
            # Linux cooked v1: pkttype(2) arphrd(2) addrlen(2) addr(8) proto(2)
            if len(raw) >= 16:
                proto = int.from_bytes(raw[14:16], "big")
                payload = raw[16:]
                if proto == 0x0800:
                    _parse_ipv4(payload, pkt)
                elif proto == 0x86DD:
                    _parse_ipv6(payload, pkt)
        yield pkt


def _iter_pcapng(data):
    """Yield Packet from pcapng bytes (basic SHB/IDB/EPB/SPB support)."""
    if len(data) < 12:
        return
    endian = "<" if data[:4] == b"\x0a\x0d\x0d\x0a" else ">"
    if data[:4] not in (b"\x0a\x0d\x0d\x0a", b"\x0d\x0a\x0d\x0a"):
        return
    off = 0
    linktype = 1
    while off + 12 <= len(data):
        btype = int.from_bytes(data[off:off + 4], endian)
        blen = int.from_bytes(data[off + 4:off + 8], endian)
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x0A0D0D0A:
            pass  # SHB
        elif btype == 0x00000001:  # IDB
            if len(body) >= 8:
                linktype = int.from_bytes(body[:4], endian)
        elif btype == 0x00000006:  # EPB
            if len(body) >= 20:
                caplen = int.from_bytes(body[12:16], endian)
                ts_high = int.from_bytes(body[4:8], endian)
                ts_low = int.from_bytes(body[8:12], endian)
                raw = body[20:20 + caplen]
                pkt = Packet()
                pkt.ts = (ts_high << 32 | ts_low) / 1e6
                if linktype == 1:
                    _parse_ethernet(raw, pkt)
                elif linktype in (101,):
                    _parse_ipv4(raw, pkt)
                elif linktype in (0, 108):
                    _parse_ipv4(raw[4:], pkt)
                yield pkt
        elif btype == 0x00000003:  # SPB
            if len(body) >= 4:
                caplen = int.from_bytes(body[:4], endian)
                raw = body[4:4 + caplen]
                pkt = Packet()
                if linktype == 1:
                    _parse_ethernet(raw, pkt)
                elif linktype in (101,):
                    _parse_ipv4(raw, pkt)
                yield pkt
        off += blen


def read_packets(path):
    """Read packets from a pcap or pcapng file."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] in (b"\x0a\x0d\x0d\x0a", b"\x0d\x0a\x0d\x0a"):
        return list(_iter_pcapng(data))
    return list(_iter_pcap(data))


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def _stream_key(src, sport, dst, dport):
    # sort endpoints so both directions share a key
    a = (src, sport)
    b = (dst, dport)
    return (a, b) if a <= b else (b, a)


def analyze_pcap(path):
    """Full analysis: streams, HTTP, UDP/ICMP payloads, flags."""
    packets = read_packets(path)
    info = {
        "packets": len(packets),
        "indicators": {"links": [], "secrets": [], "ips": [], "decoded_blobs": []},
        "streams": defaultdict(lambda: {b"c2s": b"", b"s2c": b""}),
        "http": [],
        "udp": [],
        "icmp": [],
        "conns": set(),
        "flags": [],
    }

    for pkt in packets:
        if pkt.proto == "TCP" and pkt.payload:
            key = _stream_key(pkt.src, pkt.sport, pkt.dst, pkt.dport)
            if pkt.sport > pkt.dport:  # heuristic: higher port = client side
                stream = info["streams"][key][b"c2s"]
                if len(stream) < MAX_STREAM:
                    info["streams"][key][b"c2s"] += pkt.payload
            else:
                stream = info["streams"][key][b"s2c"]
                if len(stream) < MAX_STREAM:
                    info["streams"][key][b"s2c"] += pkt.payload
            info["conns"].add((pkt.src, pkt.sport, pkt.dst, pkt.dport))
        elif pkt.proto == "UDP" and pkt.payload:
            info["udp"].append((pkt.src, pkt.sport, pkt.dst, pkt.dport, pkt.payload))
        elif pkt.proto in ("ICMP", "ICMPv6") and pkt.payload:
            info["icmp"].append((pkt.src, pkt.dst, pkt.payload))

    # HTTP extraction from reassembled streams
    for (a, b), streams in info["streams"].items():
        req = streams[b"c2s"]
        resp = streams[b"s2c"]
        if b"HTTP/" in resp or b"GET " in req or b"POST " in req:
            info["http"].append((a, b, req, resp))

    # flag hunting
    def scan_blob(label, blob):
        for m in re.finditer(rb"[A-Za-z0-9+/=]{24,}", blob):
            try:
                dec = base64.b64decode(m.group(0), validate=True)
                blob += b"\n" + dec
            except Exception:
                pass
        text = blob.decode("latin-1")
        known, cands = flaglib.extract_flags(text)
        for f in known + cands:
            if f not in info["flags"]:
                info["flags"].append(f)
        return text

    for (a, b), streams in info["streams"].items():
        scan_blob("stream", streams[b"c2s"])
        scan_blob("stream", streams[b"s2c"])
    for src, sport, dst, dport, payload in info["udp"]:
        scan_blob("udp", payload)
    for src, dst, payload in info["icmp"]:
        scan_blob("icmp", payload)

    # Protocol-specific analysis (FTP, SMTP, IRC, Telnet, Redis, MySQL, DNS tunnel)
    proto_streams = {}
    for (a, b), streams in info["streams"].items():
        proto_streams[(a[0], a[1], b[0], b[1])] = {
            b"c2s": streams[b"c2s"], b"s2c": streams[b"s2c"]
        }
    info["protocols"] = proto_mod.parse_all_protocols(
        proto_streams,
        udp_payloads=info["udp"],
    )
    # Collect credentials and protocol findings into flags/indicators
    for cred in info["protocols"].get("credentials", []):
        for val in cred.values():
            if isinstance(val, str) and len(val) > 2:
                known, cands = flaglib.extract_flags(val)
                for f in known + cands:
                    if f not in info["flags"]:
                        info["flags"].append(f)
    for f in info["protocols"].get("findings", []):
        val = f.get("value", "")
        if isinstance(val, str):
            known, cands = flaglib.extract_flags(val)
            for flag in known + cands:
                if flag not in info["flags"]:
                    info["flags"].append(flag)
    # DNS tunnel reassembly → flags
    dns = info["protocols"].get("dns_tunnel")
    if dns and dns.get("reassembled"):
        known, cands = flaglib.extract_flags(dns["reassembled"])
        for f in known + cands:
            if f not in info["flags"]:
                info["flags"].append(f)

    # Passive indicator extraction from all reconstructed and datagram data.
    blobs = []
    for streams in info["streams"].values():
        blobs.extend(("pcap:tcp-c2s", streams[b"c2s"]), ("pcap:tcp-s2c", streams[b"s2c"]))
    blobs.extend(("pcap:udp", item[4]) for item in info["udp"])
    blobs.extend(("pcap:icmp", item[2]) for item in info["icmp"])
    for source, blob in blobs:
        extracted = intelligence_mod.extract_indicators(blob.decode("latin-1", "replace"), source=source)
        for key in info["indicators"]:
            info["indicators"][key].extend(extracted[key])
    for key in info["indicators"]:
        if key == "links":
            unique = {item["url"]: item for item in info["indicators"][key]}
            info["indicators"][key] = sorted(unique.values(), key=lambda x: (-x["score"], x["url"]))[:200]
        else:
            info["indicators"][key] = list(dict.fromkeys(info["indicators"][key]))[:200]
    return info


def format_pcap_report(info):
    """Turn the analysis dict into printable lines."""
    lines = []
    lines.append(f"Packets: {info['packets']}")
    if info["conns"]:
        lines.append("Connections (TCP):")
        for src, sport, dst, dport in sorted(info["conns"]):
            lines.append(f"  {src}:{sport} -> {dst}:{dport}")
    if info["http"]:
        lines.append("HTTP sessions:")
        for a, b, req, resp in info["http"]:
            host = b""
            m = re.search(rb"(?im)^Host:\s*([^\r\n]+)", req)
            if m:
                host = m.group(1).strip()
            m2 = re.search(rb"(?m)^(GET|POST|PUT|HEAD|OPTIONS) ([^ ]+) HTTP", req)
            path = m2.group(2).decode("latin-1") if m2 else "?"
            code = ""
            m3 = re.search(rb"HTTP/1\.[01] (\d{3})", resp)
            if m3:
                code = m3.group(1).decode()
            lines.append(
                f"  {a[0]}:{a[1]} -> {b[0]}:{b[1]}  [{code}] {path} "
                f"host={host.decode('latin-1', 'replace')}")
    if info["udp"]:
        lines.append("UDP payloads (first 80 bytes shown):")
        for src, sport, dst, dport, payload in info["udp"][:20]:
            lines.append(
                f"  {src}:{sport} -> {dst}:{dport}  "
                f"{payload[:80].decode('latin-1', 'replace')!r}")
    if info["icmp"]:
        lines.append("ICMP payloads (possible exfil!):")
        for src, dst, payload in info["icmp"][:20]:
            lines.append(
                f"  {src} -> {dst}  {payload[:80].decode('latin-1', 'replace')!r}")
    # Protocol-specific findings
    proto = info.get("protocols")
    if proto:
        proto_lines = proto_mod.format_protocol_report(proto)
        lines.extend(proto_lines)
    return lines
