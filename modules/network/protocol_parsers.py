"""Protocol-specific parsers for CTF network challenges.

Extracts credentials, flags, commands, and data from:
- FTP (USER/PASS/RETR/LIST)
- SMTP (AUTH LOGIN/PLAIN, mail data)
- IRC (PRIVMSG/NICK/JOIN with hidden data)
- DNS tunneling (subdomain chunk reassembly)
- Telnet sessions (keystroke extraction)
- Redis/MySQL protocol (inline commands)
- Generic TCP banner grabbing
"""
import base64
import re
import struct

from core.flag import extract_flags


# ---------------------------------------------------------------------------
# FTP parser
# ---------------------------------------------------------------------------
_FTP_USER_RE = re.compile(rb"(?i)^USER\s+(.+)", re.M)
_FTP_PASS_RE = re.compile(rb"(?i)^PASS\s+(.+)", re.M)
_FTP_PATH_RE = re.compile(rb"(?i)^(?:RETR|STOR|LIST|CWD|PWD|MKD)\s+(.+)", re.M)
_FTP_REPLY_RE = re.compile(rb"^\d{3}\s+(.*)", re.M)
_FTP_CMD_RE = re.compile(rb"(?i)^(USER|PASS|RETR|STOR|LIST|CWD|PWD|MKD|RNFR|RNTO|DELE|QUIT|TYPE|PASV|PORT|EPSV|EPRT|SYST|FEAT|OPTS|AUTH|PBSZ|PROT|CONF)\b", re.M)


def parse_ftp(stream_bytes):
    """Parse an FTP session and return findings."""
    findings = []
    credentials = []
    commands = []
    data_chunks = []

    for m in _FTP_USER_RE.finditer(stream_bytes):
        user = m.group(1).strip().decode("latin-1", "replace")
        credentials.append({"user": user, "source": "FTP/USER"})

    for m in _FTP_PASS_RE.finditer(stream_bytes):
        passwd = m.group(1).strip().decode("latin-1", "replace")
        credentials.append({"password": passwd, "source": "FTP/PASS"})

    for m in _FTP_PATH_RE.finditer(stream_bytes):
        path = m.group(1).strip().decode("latin-1", "replace")
        commands.append({"cmd": m.group(0).split()[0].decode().upper(), "arg": path})

    for m in _FTP_REPLY_RE.finditer(stream_bytes):
        reply = m.group(1).strip().decode("latin-1", "replace")
        if any(w in reply.lower() for w in ("flag", "secret", "password", "key")):
            findings.append({"type": "ftp-reply-leak", "value": reply})

    # Check for file contents after RETR (data channel heuristic)
    for m in re.finditer(rb"(?i)^226\s+Transfer", stream_bytes):
        # look at data after transfer complete
        pos = m.end()
        chunk = stream_bytes[pos:pos + 4096]
        if chunk:
            data_chunks.append(chunk.decode("latin-1", "replace"))

    return {
        "protocol": "FTP",
        "credentials": credentials,
        "commands": commands,
        "findings": findings,
        "data_chunks": data_chunks,
    }


# ---------------------------------------------------------------------------
# SMTP parser
# ---------------------------------------------------------------------------
_SMTP_AUTH_RE = re.compile(rb"(?i)^AUTH\s+(LOGIN|PLAIN|CRAM-MD5)\s*(.*)", re.M)
_SMTP_MAIL_RE = re.compile(rb"(?i)^(?:MAIL FROM|RCPT TO|DATA|QUIT|STARTTLS)\s*:?\\s*(.*)", re.M)
_SMTP_BANNER_RE = re.compile(rb"^220\s+(.+)", re.M)
_SMTP_DATA_END = re.compile(rb"\r\n\.\r\n")


def parse_smtp(stream_bytes):
    """Parse an SMTP session."""
    findings = []
    credentials = []

    for m in _SMTP_BANNER_RE.finditer(stream_bytes):
        banner = m.group(1).strip().decode("latin-1", "replace")
        findings.append({"type": "smtp-banner", "value": banner})

    for m in _SMTP_AUTH_RE.finditer(stream_bytes):
        method = m.group(1).decode().upper()
        extra = m.group(2).strip()
        if method == "LOGIN" and extra:
            try:
                decoded = base64.b64decode(extra).decode("latin-1", "replace")
                credentials.append({"user": decoded, "source": "SMTP/AUTH LOGIN"})
            except Exception:
                pass
        elif method == "PLAIN" and extra:
            try:
                decoded = base64.b64decode(extra).decode("latin-1", "replace")
                parts = decoded.split("\x00")
                if len(parts) >= 2:
                    credentials.append({
                        "user": parts[1] if len(parts) > 1 else "",
                        "password": parts[2] if len(parts) > 2 else "",
                        "source": "SMTP/AUTH PLAIN",
                    })
            except Exception:
                pass

    # SMTP AUTH LOGIN sends credentials as separate base64 lines after 334
    auth_state = 0
    for line in stream_bytes.split(b"\r\n"):
        line = line.strip()
        if line.startswith(b"334"):
            auth_state += 1
            if auth_state == 1:
                continue  # username prompt
        elif auth_state == 1:
            try:
                decoded = base64.b64decode(line).decode("latin-1", "replace")
                credentials.append({"user": decoded, "source": "SMTP/AUTH-LOGIN-user"})
            except Exception:
                pass
            auth_state = 2
        elif auth_state == 2:
            try:
                decoded = base64.b64decode(line).decode("latin-1", "replace")
                credentials.append({"password": decoded, "source": "SMTP/AUTH-LOGIN-pass"})
            except Exception:
                pass
            auth_state = 0

    # Extract mail body content
    data_sections = []
    in_data = False
    body = []
    for line in stream_bytes.split(b"\r\n"):
        if line.strip() == b"DATA":
            in_data = True
            continue
        if in_data:
            if line.strip() == b".":
                in_data = False
                data_sections.append(b"\r\n".join(body).decode("latin-1", "replace"))
                body = []
            else:
                body.append(line)

    return {
        "protocol": "SMTP",
        "credentials": credentials,
        "findings": findings,
        "data_sections": data_sections,
    }


# ---------------------------------------------------------------------------
# IRC parser
# ---------------------------------------------------------------------------
_IRC_MSG_RE = re.compile(rb"^:(\S+)!(\S+)@(\S+)\s+(\S+)\s+(.+)", re.M)
_IRC_PRIVMSG_RE = re.compile(rb"^:.+ PRIVMSG (\S+) :(.+)", re.M)
_IRC_NOTICE_RE = re.compile(rb"^:.+ NOTICE \S+ :(.+)", re.M)
_IRC_TOPIC_RE = re.compile(rb"^:.+ TOPIC \S+ :(.+)", re.M)
_IRC_NICK_RE = re.compile(rb"(?i)^NICK\s+(.+)", re.M)
_IRC_PASS_RE = re.compile(rb"(?i)^PASS\s+(.+)", re.M)
_IRC_JOIN_RE = re.compile(rb"(?i)^JOIN\s+(.+)", re.M)


def parse_irc(stream_bytes):
    """Parse IRC session for hidden data, credentials, and CTF flags."""
    findings = []
    channels = []
    messages = []

    for m in _IRC_NICK_RE.finditer(stream_bytes):
        nick = m.group(1).strip().decode("latin-1", "replace")
        findings.append({"type": "irc-nick", "value": nick})

    for m in _IRC_PASS_RE.finditer(stream_bytes):
        passwd = m.group(1).strip().decode("latin-1", "replace")
        findings.append({"type": "irc-password", "value": passwd})

    for m in _IRC_JOIN_RE.finditer(stream_bytes):
        chan = m.group(1).strip().decode("latin-1", "replace")
        channels.append(chan)

    for m in _IRC_PRIVMSG_RE.finditer(stream_bytes):
        target = m.group(1).decode("latin-1", "replace")
        msg = m.group(2).decode("latin-1", "replace")
        messages.append({"target": target, "message": msg})

    for m in _IRC_NOTICE_RE.finditer(stream_bytes):
        msg = m.group(1).decode("latin-1", "replace")
        findings.append({"type": "irc-notice", "value": msg})

    for m in _IRC_TOPIC_RE.finditer(stream_bytes):
        topic = m.group(1).decode("latin-1", "replace")
        findings.append({"type": "irc-topic", "value": topic})

    return {
        "protocol": "IRC",
        "channels": channels,
        "messages": messages,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# DNS tunneling detection / reassembly
# ---------------------------------------------------------------------------
_DNS_QUERY_RE = re.compile(
    rb"\x00\x01\x00\x00\x00\x00\x00\x00"  # standard query header
    rb"(.+?)\x00"                            # domain name
    rb"\x00\x01",                             # type A query
)


def detect_dns_tunnel(packets):
    """Detect DNS tunneling by reassembling subdomain-encoded data."""
    subdomains = []
    suspicious_queries = []

    for pkt in packets:
        if pkt.proto != "UDP" or pkt.sport != 53 and pkt.dport != 53:
            continue
        payload = pkt.payload
        if len(payload) < 12:
            continue

        # Parse DNS query name from the payload
        try:
            qname = payload[12:]
            labels = []
            i = 0
            while i < len(qname) and qname[i] != 0:
                length = qname[i]
                if length > 63 or i + 1 + length > len(qname):
                    break
                label = qname[i + 1:i + 1 + length].decode("ascii", "replace")
                labels.append(label)
                i += 1 + length
            if labels:
                domain = ".".join(labels)
                # First label is often the tunneled data in DNS exfil
                if labels[0] and len(labels[0]) > 2:
                    subdomains.append(labels[0])
                # Check for high entropy subdomain (tunneling indicator)
                unique_chars = set(labels[0]) if labels[0] else set()
                if len(unique_chars) > 15:
                    suspicious_queries.append({
                        "domain": domain,
                        "entropy_hint": len(unique_chars),
                        "label": labels[0][:100],
                    })
        except Exception:
            continue

    # Reassemble hex/base32/base64 encoded subdomain chunks
    reassembled = ""
    if subdomains:
        # Try hex reassembly
        hex_chars = set("0123456789abcdef")
        all_hex = all(c in hex_chars for s in subdomains for c in s.lower())
        if all_hex and len("".join(subdomains)) >= 16:
            try:
                raw = bytes.fromhex("".join(subdomains))
                reassembled = raw.decode("utf-8", "replace")
            except Exception:
                pass

        # Try base64 reassembly
        if not reassembled:
            try:
                joined = "".join(subdomains)
                padded = joined + "=" * (-len(joined) % 4)
                raw = base64.b64decode(padded)
                if raw and all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
                    reassembled = raw.decode("utf-8", "replace")
            except Exception:
                pass

    return {
        "total_queries": len(subdomains),
        "suspicious": suspicious_queries[:50],
        "reassembled": reassembled[:4096],
        "subdomain_sample": subdomains[:20],
    }


# ---------------------------------------------------------------------------
# Telnet session parser
# ---------------------------------------------------------------------------
_TELNET_IAC = bytes([0xFF])  # Interpret As Command


def parse_telnet(stream_bytes):
    """Extract keystroke data from a Telnet session, stripping IAC commands."""
    output = bytearray()
    cleaned = bytearray()
    i = 0
    while i < len(stream_bytes):
        if stream_bytes[i:i + 1] == _TELNET_IAC:
            # Skip IAC + command + option (2-3 bytes)
            if i + 1 < len(stream_bytes):
                cmd = stream_bytes[i + 1]
                if cmd in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL/WONT/DO/DONT
                    i += 3
                elif cmd == 0xFA:  # SB ... SE
                    # skip until IAC SE
                    end = stream_bytes.find(b"\xff\xf0", i + 2)
                    i = end + 2 if end >= 0 else len(stream_bytes)
                else:
                    i += 2
            else:
                i += 1
        else:
            cleaned.append(stream_bytes[i])
            i += 1

    # Extract printable output
    text = bytes(cleaned).decode("latin-1", "replace")
    lines = []
    for line in text.split("\r\n"):
        line = line.strip()
        if line and all(c.isprintable() or c in "\t" for c in line):
            lines.append(line)

    return {
        "protocol": "Telnet",
        "lines": lines[:500],
        "raw_length": len(stream_bytes),
    }


# ---------------------------------------------------------------------------
# Redis inline command parser
# ---------------------------------------------------------------------------
_REDIS_CMD_RE = re.compile(rb"(?i)^(AUTH|SET|GET|CONFIG|FLUSHALL|FLUSHDB|SAVE|SLAVEOF|DEBUG|MODULE|EVAL|EVALSHA|SCRIPT)\b", re.M)
_REDIS_BULK_RE = re.compile(rb"\$\d+\r\n(.+?)(?:\r\n|\Z)")


def parse_redis(stream_bytes):
    """Parse Redis RESP protocol for commands and data."""
    findings = []
    commands = []

    # Inline mode
    for m in _REDIS_CMD_RE.finditer(stream_bytes):
        cmd = m.group(0).decode().upper()
        args = stream_bytes[m.end():m.end() + 200].decode("latin-1", "replace").strip()
        commands.append({"cmd": cmd, "args": args[:200]})
        if cmd == "AUTH":
            findings.append({"type": "redis-auth", "value": args.split("\r\n")[0][:200]})

    # RESP (multi-bulk) mode
    lines = stream_bytes.split(b"\r\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(b"*"):
            try:
                count = int(line[1:])
            except ValueError:
                i += 1
                continue
            parts = []
            for j in range(1, count + 1):
                if i + j < len(lines) and lines[i + j].startswith(b"$"):
                    try:
                        slen = int(lines[i + j][1:])
                        if i + j + 1 < len(lines):
                            parts.append(lines[i + j + 1][:slen])
                    except ValueError:
                        pass
            if parts:
                cmd = parts[0].decode("latin-1", "replace").upper()
                args = [p.decode("latin-1", "replace") for p in parts[1:]]
                commands.append({"cmd": cmd, "args": " ".join(args)})
                if cmd == "AUTH" and args:
                    findings.append({"type": "redis-auth", "value": args[0]})
            i += count + 1
        else:
            i += 1

    return {
        "protocol": "Redis",
        "commands": commands[:200],
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# MySQL handshake / command parser
# ---------------------------------------------------------------------------
def parse_mysql_banner(stream_bytes):
    """Extract MySQL server version and capabilities from handshake packet."""
    findings = []
    if len(stream_bytes) < 5:
        return {"protocol": "MySQL", "findings": findings}

    # Check for MySQL handshake
    pkt_len = int.from_bytes(stream_bytes[:3], "little")
    seq = stream_bytes[3]
    protocol = stream_bytes[4]

    if protocol == 10 and pkt_len > 32:
        # Protocol 10 handshake
        null_pos = stream_bytes.find(b"\x00", 5)
        if 5 < null_pos < 100:
            version = stream_bytes[5:null_pos].decode("ascii", "replace")
            findings.append({"type": "mysql-version", "value": version})

    return {"protocol": "MySQL", "findings": findings}


# ---------------------------------------------------------------------------
# Master dispatcher: run all parsers on reassembled streams
# ---------------------------------------------------------------------------
def parse_all_protocols(streams, udp_payloads=None, icmp_payloads=None):
    """Run protocol-specific parsers on reassembled TCP streams + UDP/ICMP.

    Args:
        streams: dict of (src, sport, dst, dport) -> (c2s_bytes, s2c_bytes)
        udp_payloads: list of (src, sport, dst, dport, payload) tuples
        icmp_payloads: list of (src, dst, payload) tuples

    Returns:
        dict with protocol findings, credentials, and raw data
    """
    results = {
        "ftp": [],
        "smtp": [],
        "irc": [],
        "telnet": [],
        "redis": [],
        "mysql": [],
        "dns_tunnel": None,
        "credentials": [],
        "findings": [],
    }

    for (src, sport, dst, dport), dirs in streams.items():
        c2s = dirs.get(b"c2s", b"")
        s2c = dirs.get(b"s2c", b"")
        combined = c2s + s2c

        # Identify protocol by port or payload
        client_port = min(sport, dport)
        server_port = max(sport, dport)

        # FTP (port 21)
        if server_port == 21 or b"220 " in s2c[:20] and b"FTP" in s2c[:200]:
            ftp = parse_ftp(combined)
            if ftp["credentials"] or ftp["commands"] or ftp["findings"]:
                results["ftp"].append(ftp)
                results["credentials"].extend(ftp["credentials"])
                results["findings"].extend(ftp["findings"])

        # SMTP (port 25/587/465)
        if server_port in (25, 587, 465) or b"220 " in s2c[:20] and b"SMTP" in s2c[:200]:
            smtp = parse_smtp(combined)
            if smtp["credentials"] or smtp["findings"] or smtp["data_sections"]:
                results["smtp"].append(smtp)
                results["credentials"].extend(smtp["credentials"])
                results["findings"].extend(smtp["findings"])

        # IRC (port 6667/6668/6669/6697)
        if server_port in (6667, 6668, 6669, 6697) or b"PRIVMSG" in combined[:500]:
            irc = parse_irc(combined)
            if irc["messages"] or irc["findings"]:
                results["irc"].append(irc)
                results["findings"].extend(irc["findings"])

        # Telnet (port 23)
        if server_port == 23 or client_port == 23:
            telnet = parse_telnet(combined)
            if telnet["lines"]:
                results["telnet"].append(telnet)

        # Redis (port 6379)
        if server_port == 6379 or client_port == 6379:
            redis = parse_redis(combined)
            if redis["commands"] or redis["findings"]:
                results["redis"].append(redis)
                results["credentials"].extend(redis["findings"])

        # MySQL (port 3306)
        if server_port == 3306:
            mysql = parse_mysql_banner(s2c[:2048])
            if mysql["findings"]:
                results["mysql"].append(mysql)
                results["findings"].extend(mysql["findings"])

    # DNS tunnel detection from all UDP payloads (if packets available)
    # Note: this is called from pcap.py when packets are available
    if udp_payloads is not None:
        # Wrap as fake packets for DNS detection
        class FakePkt:
            pass
        fake_pkts = []
        for src, sport, dst, dport, payload in udp_payloads:
            pkt = FakePkt()
            pkt.proto = "UDP"
            pkt.sport = sport
            pkt.dport = dport
            pkt.payload = payload
            pkt.src = src
            pkt.dst = dst
            fake_pkts.append(pkt)
        dns = detect_dns_tunnel(fake_pkts)
        if dns["total_queries"] > 0:
            results["dns_tunnel"] = dns

    return results


def format_protocol_report(results):
    """Format protocol analysis results as printable lines."""
    lines = []

    if results["credentials"]:
        lines.append("🔑 Credentials found:")
        for cred in results["credentials"]:
            for k, v in cred.items():
                if k != "source":
                    lines.append(f"  [{cred.get('source', '?')}] {k} = {v}")

    if results["ftp"]:
        lines.append(f"\n📁 FTP sessions: {len(results['ftp'])}")
        for ftp in results["ftp"]:
            for cmd in ftp.get("commands", [])[:10]:
                lines.append(f"  {cmd['cmd']} {cmd['arg']}")
            for f in ftp.get("findings", []):
                lines.append(f"  [!] {f['type']}: {f['value']}")

    if results["smtp"]:
        lines.append(f"\n📧 SMTP sessions: {len(results['smtp'])}")
        for smtp in results["smtp"]:
            for ds in smtp.get("data_sections", [])[:3]:
                lines.append(f"  Mail body: {ds[:200]}")

    if results["irc"]:
        lines.append(f"\n💬 IRC sessions: {len(results['irc'])}")
        for irc in results["irc"]:
            for msg in irc.get("messages", [])[:10]:
                lines.append(f"  <{msg['target']}> {msg['message'][:200]}")
            for f in irc.get("findings", []):
                lines.append(f"  [!] {f['type']}: {f['value']}")

    if results["telnet"]:
        lines.append(f"\n🖥️ Telnet sessions: {len(results['telnet'])}")
        for tn in results["telnet"]:
            for line in tn.get("lines", [])[:20]:
                lines.append(f"  {line}")

    if results["redis"]:
        lines.append(f"\n📦 Redis sessions: {len(results['redis'])}")
        for redis in results["redis"]:
            for cmd in redis.get("commands", [])[:10]:
                lines.append(f"  {cmd['cmd']} {cmd['args'][:100]}")

    if results["mysql"]:
        lines.append(f"\n🐬 MySQL sessions: {len(results['mysql'])}")
        for mysql in results["mysql"]:
            for f in mysql.get("findings", []):
                lines.append(f"  {f['type']}: {f['value']}")

    if results["dns_tunnel"]:
        dns = results["dns_tunnel"]
        lines.append(f"\n🌐 DNS Tunneling detected ({dns['total_queries']} queries)")
        if dns["reassembled"]:
            lines.append(f"  Reassembled: {dns['reassembled'][:200]}")
        for sq in dns.get("suspicious", [])[:5]:
            lines.append(f"  Suspicious: {sq['domain']} (entropy={sq['entropy_hint']})")

    if results["findings"]:
        lines.append(f"\n🚨 Additional findings: {len(results['findings'])}")
        for f in results["findings"][:20]:
            lines.append(f"  [{f.get('type', '?')}] {f.get('value', '')[:150]}")

    return lines
