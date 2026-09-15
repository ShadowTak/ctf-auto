"""Deep, defensive image forensics for authorized CTF artifacts.

The core parser deliberately uses the standard library. Optional external
tools (ExifTool, OCR, QR readers, steghide, zsteg, binwalk, ImageMagick) are
detected and used only when available. Nothing is executed from the image and
carved data is reported rather than written over the input.
"""
import base64
import binascii
import collections
import hashlib
import io
import json
import math
import os
import re
import shutil
import struct
import subprocess
import tempfile
import tarfile
import time
import zipfile
import zlib

from core.evidence import EvidenceLedger
from core.flag import extract_flags, looks_like_noise_flag

MAX_READ = 128 * 1024 * 1024
MAX_LIST = 240
MAX_TEXT = 1800
# Wall-clock ceiling for the crypto chain pass over image-derived snippets.
# A single autodetect call can spend seconds on adversarial noise, so a
# challenge whose image yields many snippets must still return in time.
_DECODE_TEXT_BUDGET = 8.0
MAX_TOOL_OUTPUT = 12000

_MAGICS = (
    (b"\x89PNG\r\n\x1a\n", "PNG", "png"),
    (b"\xff\xd8\xff", "JPEG", "jpg"),
    (b"GIF87a", "GIF", "gif"),
    (b"GIF89a", "GIF", "gif"),
    (b"BM", "BMP", "bmp"),
    (b"RIFF", "RIFF container", "webp"),
    (b"II*\x00", "TIFF little-endian", "tiff"),
    (b"MM\x00*", "TIFF big-endian", "tiff"),
    (b"\x00\x00\x01\x00", "ICO", "ico"),
    (b"P1\n", "PBM", "pnm"),
    (b"P2\n", "PGM", "pnm"),
    (b"P3\n", "PPM", "pnm"),
    (b"P4\n", "PBM", "pnm"),
    (b"P5\n", "PGM", "pnm"),
    (b"P6\n", "PPM", "pnm"),
)

_TAG_NAMES = {
    0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model",
    0x0112: "Orientation", 0x011A: "XResolution", 0x011B: "YResolution",
    0x011C: "PlanarConfiguration", 0x0131: "Software", 0x0132: "DateTime",
    0x013B: "Artist", 0x8298: "Copyright", 0x8769: "ExifIFD",
    0x8825: "GPSInfo", 0x9003: "DateTimeOriginal", 0x9004: "CreateDate",
    0x9286: "UserComment", 0xA001: "ColorSpace", 0xA002: "PixelXDimension",
    0xA003: "PixelYDimension", 0xA431: "OwnerName", 0xA432: "LensInfo",
    0xA434: "LensModel", 0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude",
}

_TIFF_TYPES = {
    1: (1, "BYTE"), 2: (1, "ASCII"), 3: (2, "SHORT"), 4: (4, "LONG"),
    5: (8, "RATIONAL"), 7: (1, "UNDEFINED"), 9: (4, "SLONG"),
    10: (8, "SRATIONAL"),
}


def _clip(value, limit=MAX_TEXT):
    value = str(value)
    return value if len(value) <= limit else value[:limit] + "…"


def _unique(values, limit=MAX_LIST):
    out = []
    seen = set()
    for value in values:
        key = json.dumps(value, sort_keys=True, ensure_ascii=False,
                         default=str) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").replace("\x00", "")
    return str(value)


def _printable(value):
    text = _text(value)
    return text if text and sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text) >= .78 else ""


def _safe_unpack(fmt, data, offset=0):
    try:
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            return None
        return struct.unpack_from(fmt, data, offset)
    except (struct.error, ValueError):
        return None


def _ratio_entropy(data):
    if not data:
        return 0.0
    counts = collections.Counter(data)
    length = len(data)
    return round(-sum((n / length) * math.log2(n / length)
                      for n in counts.values()), 4)


def identify_format(data, filename=""):
    for magic, name, extension in _MAGICS:
        if data.startswith(magic):
            if name == "RIFF" and len(data) >= 12 and data[8:12] == b"WEBP":
                return "WebP", "webp", "RIFF/WEBP"
            return name, extension, magic.hex()
    return "unknown", os.path.splitext(filename)[1].lower().lstrip("."), data[:16].hex()


def _add_meta(meta, key, value, source="parser"):
    value = _printable(value)
    if value:
        meta.append({"key": str(key), "value": _clip(value), "source": source})


def _tiff_value(data, endian, typ, count, raw):
    info = _TIFF_TYPES.get(typ)
    if not info or count > 100000:
        return None
    unit, name = info
    total = unit * count
    payload = raw if total <= 4 else None
    if payload is None:
        offset = int.from_bytes(raw, "little" if endian == "<" else "big")
        if offset < 0 or offset + total > len(data):
            return None
        payload = data[offset:offset + total]
    try:
        if typ == 2:
            return payload.rstrip(b"\x00").decode("utf-8", "replace")
        if typ in (1, 7):
            return payload[:256].hex() if typ == 7 else list(payload[:32])
        if typ == 3:
            return list(struct.unpack(endian + f"{count}H", payload[:2 * count]))
        if typ == 4:
            return list(struct.unpack(endian + f"{count}I", payload[:4 * count]))
        if typ == 9:
            return list(struct.unpack(endian + f"{count}i", payload[:4 * count]))
        if typ in (5, 10):
            values = []
            fmt = endian + ("II" if typ == 5 else "ii")
            for off in range(0, min(len(payload), count * 8), 8):
                num, den = struct.unpack_from(fmt, payload, off)
                values.append(round(num / den, 8) if den else None)
            return values
    except (struct.error, ZeroDivisionError, UnicodeError):
        return None
    return None


def parse_tiff(data, base=0, source="TIFF"):
    """Parse a bounded TIFF/Exif IFD tree and return printable metadata."""
    meta = []
    if base + 8 > len(data):
        return meta
    order = data[base:base + 2]
    if order == b"II":
        endian = "<"
    elif order == b"MM":
        endian = ">"
    else:
        return meta
    magic = _safe_unpack(endian + "H", data, base + 2)
    if not magic or magic[0] != 42:
        return meta
    first = _safe_unpack(endian + "I", data, base + 4)
    if not first:
        return meta
    seen = set()

    def walk(ifd_offset, depth=0):
        if depth > 3 or ifd_offset in seen:
            return
        absolute = base + ifd_offset
        count = _safe_unpack(endian + "H", data, absolute)
        if not count or count[0] > 512:
            return
        seen.add(ifd_offset)
        for index in range(count[0]):
            entry = absolute + 2 + index * 12
            vals = _safe_unpack(endian + "HHI4s", data, entry)
            if not vals:
                continue
            tag, typ, number, raw = vals
            value = _tiff_value(data[base:], endian, typ, number, raw)
            if value is not None:
                name = _TAG_NAMES.get(tag, f"Tag0x{tag:04x}")
                meta.append({"key": name, "value": _clip(value),
                             "source": source})
            if tag in (0x8769, 0x8825) and typ == 4:
                child = value[0] if isinstance(value, list) and value else value
                if isinstance(child, int):
                    walk(child, depth + 1)
        next_off = _safe_unpack(endian + "I", data,
                                absolute + 2 + count[0] * 12)
        if next_off and next_off[0]:
            walk(next_off[0], depth + 1)

    walk(first[0])
    return meta


def _png_unfilter(raw, width, height, bpp, row_bytes):
    if len(raw) < height * (row_bytes + 1):
        return b""
    rows = []
    previous = bytearray(row_bytes)
    pos = 0
    for _ in range(height):
        mode = raw[pos]
        current = bytearray(raw[pos + 1:pos + 1 + row_bytes])
        pos += row_bytes + 1
        if len(current) != row_bytes:
            return b""
        for i in range(row_bytes):
            left = current[i - bpp] if i >= bpp else 0
            up = previous[i]
            upper_left = previous[i - bpp] if i >= bpp else 0
            if mode == 1:
                current[i] = (current[i] + left) & 255
            elif mode == 2:
                current[i] = (current[i] + up) & 255
            elif mode == 3:
                current[i] = (current[i] + ((left + up) // 2)) & 255
            elif mode == 4:
                p = left + up - upper_left
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - upper_left)
                predictor = left if pa <= pb and pa <= pc else (up if pb <= pc else upper_left)
                current[i] = (current[i] + predictor) & 255
            elif mode != 0:
                return b""
        rows.append(bytes(current))
        previous = current
    return b"".join(rows)


def _bits_to_text(bits, label):
    results = []
    for shift in range(8):
        usable = bits[shift:shift + 8 * 4096]
        if len(usable) < 32:
            continue
        out = bytearray()
        for pos in range(0, len(usable) - 7, 8):
            value = 0
            for bit in usable[pos:pos + 8]:
                value = (value << 1) | bit
            out.append(value)
        text = _printable(bytes(out))
        if text:
            results.append({"method": f"{label}/bit-offset-{shift}",
                            "output": _clip(text, 4096)})
    return results


def _lsb_results(raw, label):
    bits = [(byte >> bit) & 1 for byte in raw for bit in (0,)]
    return _bits_to_text(bits, label)


def parse_png(data):
    chunks, meta, text_parts = [], [], []
    idat = bytearray()
    pos, end = 8, None
    while pos + 12 <= len(data):
        length = _safe_unpack(">I", data, pos)
        if not length or length[0] > len(data) - pos - 12:
            break
        kind = data[pos + 4:pos + 8].decode("latin-1", "replace")
        payload = data[pos + 8:pos + 8 + length[0]]
        crc = data[pos + 8 + length[0]:pos + 12 + length[0]]
        chunks.append({"type": kind, "offset": pos, "length": length[0],
                       "crc_ok": bool(crc and (binascii.crc32(data[pos + 4:pos + 8] + payload) & 0xffffffff) == int.from_bytes(crc, "big"))})
        if kind == "IHDR" and len(payload) >= 13:
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload[:13])
            meta += [{"key": "width", "value": width, "source": "PNG/IHDR"},
                     {"key": "height", "value": height, "source": "PNG/IHDR"},
                     {"key": "bit_depth", "value": depth, "source": "PNG/IHDR"},
                     {"key": "color_type", "value": color, "source": "PNG/IHDR"},
                     {"key": "interlace", "value": interlace, "source": "PNG/IHDR"}]
        elif kind == "IDAT":
            idat.extend(payload)
        elif kind == "tEXt":
            key, _, value = payload.partition(b"\x00")
            text_parts.append(_text(key) + "=" + _text(value))
        elif kind == "zTXt":
            key, _, rest = payload.partition(b"\x00")
            if len(rest) > 2 and rest[0] == 0:
                try:
                    text_parts.append(_text(key) + "=" + _text(zlib.decompress(rest[1:])))
                except zlib.error:
                    text_parts.append(_text(key) + "=<compressed text failed>")
        elif kind == "iTXt":
            pieces = payload.split(b"\x00", 5)
            if len(pieces) == 6:
                key, compressed, method, language, translated, value = pieces
                if compressed == b"\x01":
                    try:
                        value = zlib.decompress(value)
                    except zlib.error:
                        pass
                text_parts.append(_text(key) + "=" + _text(value))
        elif kind == "eXIf":
            meta.extend(parse_tiff(payload, 0, "PNG/eXIf"))
        elif kind == "IEND":
            end = pos + 12 + length[0]
            break
        pos += 12 + length[0]
    stego = []
    if idat and meta and not any(item.get("value") == 1 for item in meta if item.get("key") == "interlace"):
        try:
            raw = zlib.decompress(bytes(idat))
            width = next(item["value"] for item in meta if item["key"] == "width")
            height = next(item["value"] for item in meta if item["key"] == "height")
            depth = next(item["value"] for item in meta if item["key"] == "bit_depth")
            color = next(item["value"] for item in meta if item["key"] == "color_type")
            channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color, 0)
            if depth == 8 and channels and width * height <= 40_000_000:
                pixels = _png_unfilter(raw, width, height, channels, width * channels)
                if pixels:
                    stego += _lsb_results(pixels, "PNG filtered pixel LSB")
        except (zlib.error, StopIteration, ValueError):
            pass
    trailing = data[end:] if end and end < len(data) else b""
    return {"chunks": chunks, "metadata": meta, "text": text_parts,
            "stego": stego, "end_offset": end, "trailing_bytes": len(trailing)}


def parse_jpeg(data):
    segments, meta, text_parts = [], [], []
    pos, end = 2, None
    while pos + 1 < len(data):
        if data[pos] != 0xff:
            pos += 1
            continue
        while pos < len(data) and data[pos] == 0xff:
            pos += 1
        if pos >= len(data):
            break
        marker = data[pos]
        pos += 1
        if marker in (0xD8, 0xD9):
            if marker == 0xD9:
                end = pos
                break
            continue
        if marker == 0xDA:
            # Entropy-coded scan: locate EOI while respecting stuffed bytes.
            scan = data.find(b"\xff\xd9", pos)
            end = scan + 2 if scan >= 0 else len(data)
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        length = _safe_unpack(">H", data, pos)
        if not length or length[0] < 2 or pos + length[0] > len(data):
            break
        payload = data[pos + 2:pos + length[0]]
        name = f"APP{marker - 0xE0}" if 0xE0 <= marker <= 0xEF else f"0xFF{marker:02X}"
        segments.append({"marker": name, "offset": pos - 2, "length": length[0]})
        if marker == 0xFE:
            text_parts.append(_text(payload))
        elif marker == 0xE1:
            if payload.startswith(b"Exif\x00\x00"):
                meta.extend(parse_tiff(payload, 6, "JPEG/Exif"))
            else:
                text_parts.append(_text(payload))
        elif marker in (0xE2, 0xED, 0xE4):
            text_parts.append(_text(payload))
        elif 0xC0 <= marker <= 0xC3 and len(payload) >= 7:
            precision, height, width = payload[0], int.from_bytes(payload[1:3], "big"), int.from_bytes(payload[3:5], "big")
            meta += [{"key": "width", "value": width, "source": "JPEG/SOF"},
                     {"key": "height", "value": height, "source": "JPEG/SOF"},
                     {"key": "precision", "value": precision, "source": "JPEG/SOF"}]
        pos += length[0]
    trailing = data[end:] if end and end < len(data) else b""
    return {"segments": segments, "metadata": meta, "text": text_parts,
            "stego": [], "end_offset": end, "trailing_bytes": len(trailing)}


def parse_gif(data):
    pos, comments, applications, end = 13, [], [], None
    logical = {}
    if len(data) >= 13:
        logical = {"width": int.from_bytes(data[6:8], "little"),
                   "height": int.from_bytes(data[8:10], "little"),
                   "packed": data[10], "background": data[11]}
    while pos < len(data):
        marker = data[pos]
        pos += 1
        if marker == 0x3B:
            end = pos
            break
        if marker == 0x21 and pos < len(data):
            label = data[pos]
            pos += 1
            blocks = bytearray()
            while pos < len(data):
                size = data[pos]
                pos += 1
                if size == 0:
                    break
                blocks.extend(data[pos:pos + size])
                pos += size
            if label == 0xFE:
                comments.append(_text(blocks))
            elif label == 0xFF:
                applications.append(_text(blocks))
            continue
        if marker == 0x2C:
            if pos + 9 > len(data):
                break
            packed = data[pos + 8]
            pos += 9
            if packed & 0x80:
                pos += 3 * (2 ** ((packed & 7) + 1))
            if pos >= len(data):
                break
            pos += 1
            while pos < len(data):
                size = data[pos]
                pos += 1 + size
                if size == 0:
                    break
            continue
        break
    trailing = data[end:] if end and end < len(data) else b""
    return {"metadata": [{"key": k, "value": v, "source": "GIF/LSD"} for k, v in logical.items()],
            "text": comments + applications, "stego": [], "end_offset": end,
            "trailing_bytes": len(trailing)}


def parse_bmp(data):
    meta, stego = [], []
    if len(data) >= 54:
        offset = int.from_bytes(data[10:14], "little")
        dib = int.from_bytes(data[14:18], "little")
        width = int.from_bytes(data[18:22], "little", signed=True)
        height = int.from_bytes(data[22:26], "little", signed=True)
        planes = int.from_bytes(data[26:28], "little")
        bpp = int.from_bytes(data[28:30], "little")
        compression = int.from_bytes(data[30:34], "little")
        meta = [{"key": "pixel_offset", "value": offset, "source": "BMP/header"},
                {"key": "dib_size", "value": dib, "source": "BMP/header"},
                {"key": "width", "value": width, "source": "BMP/header"},
                {"key": "height", "value": height, "source": "BMP/header"},
                {"key": "planes", "value": planes, "source": "BMP/header"},
                {"key": "bits_per_pixel", "value": bpp, "source": "BMP/header"},
                {"key": "compression", "value": compression, "source": "BMP/header"}]
        if compression == 0 and bpp in (24, 32) and 0 < offset < len(data):
            stego = _lsb_results(data[offset:], "BMP pixel LSB")
    return {"metadata": meta, "text": [], "stego": stego,
            "end_offset": len(data), "trailing_bytes": 0}


def parse_webp(data):
    chunks, meta, text_parts = [], [], []
    pos = 12
    while pos + 8 <= len(data) and data[pos:pos + 4] != b"\x00\x00\x00\x00":
        kind = data[pos:pos + 4].decode("latin-1", "replace")
        length = int.from_bytes(data[pos + 4:pos + 8], "little")
        payload = data[pos + 8:pos + 8 + length]
        if len(payload) != length:
            break
        chunks.append({"type": kind, "offset": pos, "length": length})
        if kind in ("EXIF", "XMP ", "ICCP"):
            text_parts.append(_text(payload))
            if kind == "EXIF":
                meta.extend(parse_tiff(payload, 0, "WebP/EXIF"))
        pos += 8 + length + (length & 1)
    trailing = data[pos:] if pos < len(data) else b""
    return {"chunks": chunks, "metadata": meta, "text": text_parts,
            "stego": [], "end_offset": pos, "trailing_bytes": len(trailing)}


def extract_strings(data):
    ascii_values = [m.group().decode("utf-8", "replace")
                    for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]

    def utf_values(endian):
        pattern = rb"(?:[\x20-\x7e]\x00){4,}" if endian == "le" else rb"(?:\x00[\x20-\x7e]){4,}"
        out = []
        for match in re.finditer(pattern, data):
            raw = match.group()
            try:
                out.append(raw.decode("utf-16-" + endian).rstrip("\x00"))
            except UnicodeDecodeError:
                pass
        return out

    return {"ascii": _unique(ascii_values),
            "utf16le": _unique(utf_values("le")),
            "utf16be": _unique(utf_values("be"))}


def scan_signatures(data):
    signatures = (
        (b"PK\x03\x04", "ZIP"), (b"\x1f\x8b\x08", "GZIP"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip"), (b"Rar!\x1a\x07", "RAR"),
        (b"%PDF-", "PDF"), (b"SQLite format 3\x00", "SQLite"),
        (b"\x7fELF", "ELF"), (b"ustar", "TAR"),
        (b"<html", "HTML"), (b"<?xml", "XML"),
    )
    out = []
    for magic, name in signatures:
        start = 0
        while len(out) < MAX_LIST:
            offset = data.find(magic, start)
            if offset < 0:
                break
            out.append({"type": name, "offset": offset, "magic": magic.hex()})
            start = offset + 1
    return sorted(out, key=lambda x: x["offset"])


def inspect_embedded_payloads(data, signatures):
    """Inspect bounded embedded archives without extracting to disk."""
    reports = []
    for signature in signatures:
        offset = int(signature.get("offset", 0))
        kind = signature.get("type")
        if offset <= 0 or offset >= len(data):
            continue
        payload_offset = max(0, offset - 257) if kind == "TAR" else offset
        payload = data[payload_offset:payload_offset + MAX_READ]
        try:
            if kind == "ZIP":
                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    members = []
                    for info in archive.infolist()[:80]:
                        item = {"name": info.filename, "size": info.file_size,
                                "compressed": info.compress_size}
                        if not info.is_dir() and info.file_size <= 512 * 1024:
                            raw = archive.read(info)
                            text = _printable(raw)
                            if text:
                                item["text"] = _clip(text, 4096)
                        members.append(item)
                    reports.append({"type": kind, "offset": offset,
                                    "members": members})
            elif kind == "GZIP":
                raw = zlib.decompress(payload, 16 + zlib.MAX_WBITS)
                reports.append({"type": kind, "offset": offset,
                                "text": _clip(_printable(raw), 4096),
                                "size": len(raw)})
            elif kind == "TAR":
                with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
                    members = []
                    for info in archive.getmembers()[:80]:
                        item = {"name": info.name, "size": info.size,
                                "type": str(info.type)}
                        if info.isfile() and info.size <= 512 * 1024:
                            handle = archive.extractfile(info)
                            raw = handle.read() if handle else b""
                            text = _printable(raw)
                            if text:
                                item["text"] = _clip(text, 4096)
                        members.append(item)
                    reports.append({"type": kind, "offset": offset,
                                    "members": members})
        except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError,
                EOFError, zlib.error):
            continue
    return _unique(reports, 40)


def _tool(name, args, timeout=18):
    path = shutil.which(name)
    if not path:
        return {"tool": name, "available": False, "output": "not installed"}
    try:
        proc = subprocess.run([path] + list(args), capture_output=True, text=True,
                              errors="replace", timeout=timeout, check=False)
        output = (proc.stdout + ("\n" + proc.stderr if proc.stderr else "")).strip()
        return {"tool": name, "available": True, "returncode": proc.returncode,
                "output": _clip(output, MAX_TOOL_OUTPUT)}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"tool": name, "available": True, "error": str(exc)}


def _harvest_passphrases(data, text_hints=()):
    """Collect candidate passphrases a challenge hands out in plain sight.

    Authors routinely leave the passphrase in a trailing comment, a PNG text
    chunk or a sibling ``password.txt``; steghide/rar then open with it.
    """
    found = []

    def add(value):
        value = str(value or "").strip().strip("'\"`")
        if 3 <= len(value) <= 64 and value not in found:
            found.append(value)

    for value in text_hints:
        add(value)
    for match in re.finditer(rb"(?i)(?:password|passphrase|pass|key|hint)\s*[:=]\s*"
                             rb"([\x20-\x7e]{3,64})", data[:2_000_000]):
        text = match.group(1).decode("ascii", "ignore").strip()
        add(text.split()[0] if text.split() else text)
    # Bare tokens left after an image end marker ("...LSB pass: ORAORAORA").
    for match in re.finditer(rb"[A-Za-z0-9_!@#$%^&*]{6,32}", data[-4096:]):
        token = match.group(0).decode("ascii", "ignore")
        if not token.lower().startswith(("http", "exif", "icc")):
            add(token)
    return found[:12]


# Common throwaway passphrases plus the filename; stegseek adds its own
# defaults (empty password, file name) unless told to skip them.
_STEGSEEK_DEFAULTS = ("password", "secret", "flag", "cyberhero", "oraoraora",
                      "steghide", "ctf", "admin")


def _steghide_commands(path, passphrases):
    """steghide attempts: empty passphrase first, then harvested hints."""
    workdir = tempfile.mkdtemp(prefix="ctf-steghide-")
    commands = [("steghide",
                 ["extract", "-sf", path, "-p", "", "-f", "-xf",
                  os.path.join(workdir, "extract-empty.bin")], 25)]
    for index, passphrase in enumerate(passphrases[:6]):
        commands.append((f"steghide(pass={passphrase})",
                         ["steghide", "extract", "-sf", path, "-p", passphrase,
                          "-f", "-xf",
                          os.path.join(workdir, f"extract-{index}.bin")], 25))
    return workdir, commands


def _stegseek_command(path, passphrases, workdir):
    """Stegseek is a maintained steghide fork: same embedding, extract + crack.

    Original steghide is not packaged for current macOS/Homebrew builds, so
    when only stegseek is present the empty password and every harvested hint
    are handed over as a wordlist.
    """
    wordlist = os.path.join(workdir, "stegseek-passphrases.txt")
    guesses = [str(p) for p in passphrases if str(p)] + list(_STEGSEEK_DEFAULTS)
    with open(wordlist, "w", encoding="utf-8") as handle:
        handle.write("\n".join(dict.fromkeys(guesses)) + "\n")
    output = os.path.join(workdir, "stegseek-out.bin")
    return ("stegseek", [path, wordlist, output], 45)


def run_optional_tools(path, passphrases=(), extras=()):
    workdir, steghide_commands = _steghide_commands(path, list(passphrases))
    hints = list(passphrases)
    lower = str(path).lower()
    embed_tools = []
    if shutil.which("steghide"):
        embed_tools = [("steghide", ["info", "-p", "", "-sf", path], 15)] + \
                      steghide_commands
    elif shutil.which("stegseek"):
        name, args, timeout = _stegseek_command(path, hints, workdir)
        embed_tools = [(name, args, timeout)]
    else:
        embed_tools = [("steghide", ["info", "-p", "", "-sf", path], 15)] + \
                      steghide_commands
    commands = [
        ("exiftool", ["-j", "--", path], 20),
        ("identify", ["-verbose", path], 20),
        ("strings", ["-a", "-n", "4", "--", path], 12),
        ("zbarimg", ["--raw", "--quiet", "--", path], 15),
        ("tesseract", [path, "stdout", "--psm", "6"], 30),
    ] + embed_tools + [
        # zsteg only understands PNG/BMP, binwalk's flags differ across builds.
        ("zsteg", ["-a", path], 30),
        ("binwalk", ["-q", path], 30),
    ] + list(extras)
    always_report = ("exiftool", "tesseract", "zbarimg", "steghide", "stegseek",
                     "zsteg", "binwalk")
    results = []
    for name, args, timeout in commands:
        if name == "zsteg" and not lower.endswith((".png", ".bmp")):
            continue
        result = _tool(name, args, timeout)
        if result.get("available") or name in always_report:
            results.append(result)
    for result in results:
        if str(result.get("tool", "")) == "stegseek" and not result.get("available"):
            result["output"] = ("stegseek is not installed - build it (or plain "
                                "steghide) to extract embedded payloads")
        if str(result.get("tool", "")).startswith("steghide") and not result.get("available"):
            result["output"] = ("steghide is not installed - install it to extract "
                                "embedded files. Current Homebrew no longer ships "
                                "steghide; build stegseek (a steghide fork) or run "
                                "scripts/install_ctf_tools.sh install-steghide. "
                                "The tool then retries the empty passphrase plus "
                                "every harvested hint.")
        elif str(result.get("tool", "")).startswith("steghide(pass=") \
                and "error" not in result:
            result["tool"] = "steghide attempt"
    extracted = []
    for entry in sorted(os.listdir(workdir)):
        target = os.path.join(workdir, entry)
        try:
            with open(target, "rb") as handle:
                blob = handle.read(MAX_READ)
        except OSError:
            continue
        if not blob:
            continue
        extracted.append({"file": entry, "size": len(blob),
                          "text": _clip(_printable(blob), 4096),
                          "hex": blob[:512].hex()})
    shutil.rmtree(workdir, ignore_errors=True)
    # Successful extractions are reported as their own evidence entries so the
    # decoded text reaches the flag/decoder stage like any other source.
    for entry in extracted:
        results.append({"tool": "steghide-extracted", "available": True,
                        "output": entry["text"] or entry["hex"],
                        "extracted": entry})
    return results


def _is_stego_source(source):
    """Sources produced by brute-force plane/bit scanning rather than by the
    artifact's own structure."""
    text = str(source or "").lower()
    return any(token in text for token in ("pixel", "bit-plane", "stego",
                                           "pillow", "plane"))


def _flag_evidence(ledger, text, source, verified=False, confidence=.7,
                   allow_candidates=True):
    known, candidates = extract_flags(text, include_candidates=True)
    if not allow_candidates:
        # Bit-plane / LSB sources are noise: keep only flag-shaped text that
        # survives the strict plausibility test, so raw planes stop spraying
        # findings like ``CJ{oint}`` into the report.
        known = [value for value in known if not looks_like_noise_flag(value)]
    for value in known:
        ledger.add_flag(value, source=source, verified=verified,
                        confidence=confidence,
                        evidence=("direct flag-shaped text",))
    candidates = [value for value in candidates
                  if not looks_like_noise_flag(value)]
    for value in candidates:
        # Bit-plane hunts surface thousands of brace-shaped ghosts; they stay
        # in the decode trail instead of the candidate-flag list unless the
        # caller asks for them (raw metadata/text sources).
        if allow_candidates:
            ledger.add_flag(value, source=source, verified=False,
                            confidence=min(confidence, .68),
                            evidence=("generic flag-shaped candidate",))
        else:
            ledger.add(value, source=source, confidence=0.0,
                       evidence=["brace-shaped text from a stego plane; "
                                 "not treated as a flag"])


def _decode_texts(texts, ledger):
    from modules.crypto.autodetect import analyze_text_evidence, explain_decode
    decodes = []
    # Direct strings are evidence; only encoded-looking snippets go through
    # the expensive crypto pipeline, keeping image scans bounded and useful.
    candidates = []
    seen_values = set()
    for source, value in texts:
        value = _text(value).strip()
        if not value or len(value) < 4:
            continue
        is_stego = _is_stego_source(source)
        _flag_evidence(ledger, value, source, verified=not is_stego,
                       confidence=.68 if is_stego else .94,
                       allow_candidates=not is_stego)
        if source.startswith("tool:"):
            # Tool dumps (identify -verbose, exiftool, strings) are evidence, not
            # ciphertext.  Chaining decoders over them only invents brace-shaped
            # candidates and burns the job deadline.
            continue
        if len(value) <= 5000 and (re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}", value) or
                                   re.fullmatch(r"[0-9a-fA-F :,-]{8,}", value) or
                                   "\\" in value or "  " in value):
            if value not in seen_values:
                seen_values.add(value)
                candidates.append((source, value))
    # Real metadata/residual snippets first; raw stego planes last, because
    # they are the most expensive and least likely to be a chain encoding.
    candidates.sort(key=lambda item: _is_stego_source(item[0]))
    deadline = time.monotonic() + _DECODE_TEXT_BUDGET
    for source, value in candidates[:14]:
        if time.monotonic() > deadline:
            decodes.append({"source": "decode-budget",
                            "note": "crypto chain pass hit its time budget; "
                                    "run --deep for more"})
            break
        try:
            ranked, findings = analyze_text_evidence(value)
        except Exception as exc:
            decodes.append({"source": source, "error": str(exc)})
            continue
        stego_decode = _is_stego_source(source)
        for item in findings:
            # A repeated-token or short structureless body is decode noise, not
            # a flag: e.g. ``Metaspolit{metaspolit...x13}`` from a bit plane.
            if looks_like_noise_flag(item.value):
                continue
            kind = "decode" if (stego_decode and item.kind == "candidate") \
                else item.kind
            ledger.add(item.value, kind=kind, source=f"{source}->{item.source}",
                       confidence=item.confidence, evidence=item.evidence)
        for score, label, output in (ranked or [])[:18]:
            output = _text(output)
            if output and output != value and _printable(output):
                decodes.append({"source": source, "method": str(label),
                                "score": round(float(score), 3),
                                "output": _clip(output, 4096),
                                "explanation": explain_decode(label, output, value)})
    return _unique(decodes, 160)


def analyze_image(path, run_tools=True):
    """Return a JSON-serializable deep analysis report for one image file."""
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(path or "image path")
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        data = handle.read(MAX_READ)
    truncated = size > len(data)
    fmt, extension, magic = identify_format(data, path)
    report = {
        "file": {"path": os.path.abspath(path), "name": os.path.basename(path),
                 "size": size, "read_bytes": len(data), "truncated": truncated,
                 "extension": extension, "sha256": hashlib.sha256(data).hexdigest(),
                 "md5": hashlib.md5(data).hexdigest(),
                 "entropy": _ratio_entropy(data), "magic": magic},
        "format": fmt, "metadata": [], "text": [], "strings": {},
        "chunks": [], "stego": [], "signatures": scan_signatures(data),
        "embedded": [],
        "anomalies": [], "tools": [], "decodes": [], "findings": [],
    }
    if fmt == "PNG":
        parsed = parse_png(data)
    elif fmt == "JPEG":
        parsed = parse_jpeg(data)
    elif fmt == "GIF":
        parsed = parse_gif(data)
    elif fmt == "BMP":
        parsed = parse_bmp(data)
    elif fmt == "WebP":
        parsed = parse_webp(data)
    elif fmt.startswith("TIFF"):
        parsed = {"metadata": parse_tiff(data, 0, "TIFF"), "text": [],
                  "stego": [], "end_offset": len(data), "trailing_bytes": 0}
    else:
        parsed = {"metadata": [], "text": [], "stego": [],
                  "end_offset": len(data), "trailing_bytes": 0}
    report["metadata"] = _unique(parsed.get("metadata", []))
    report["text"] = _unique(parsed.get("text", []))
    report["chunks"] = _unique(parsed.get("chunks", parsed.get("segments", [])))
    report["stego"] = _unique(parsed.get("stego", []))
    report["trailing_bytes"] = parsed.get("trailing_bytes", 0)
    report["strings"] = extract_strings(data)
    report["embedded"] = inspect_embedded_payloads(data, report["signatures"])
    report["passphrases"] = _harvest_passphrases(
        data, [item.get("value", "") for item in report["metadata"]] +
        list(report["text"]))
    try:
        from .pixel_stego import extract_pixel_planes
        pixel_results, pixel_note = extract_pixel_planes(path)
        report["stego"] = _unique(report["stego"] + pixel_results)
        if pixel_note:
            report["anomalies"].append(pixel_note)
    except Exception as exc:  # optional backend must never break core parsing
        report["anomalies"].append(f"pixel-plane scan unavailable: {exc}")
    expected_extension = {"PNG": "png", "JPEG": "jpg", "GIF": "gif",
                          "BMP": "bmp", "WebP": "webp"}.get(fmt)
    if expected_extension and extension and extension not in (expected_extension, "jpeg"):
        report["anomalies"].append(
            f"extension mismatch: .{extension} but magic identifies {fmt}")
    bad_chunks = [item for item in report["chunks"]
                  if item.get("crc_ok") is False]
    if bad_chunks:
        report["anomalies"].append(
            f"{len(bad_chunks)} image chunk CRC check(s) failed")
    if report["trailing_bytes"]:
        report["anomalies"].append(
            f"{report['trailing_bytes']} trailing byte(s) after image end marker")
    if report["file"]["truncated"]:
        report["anomalies"].append(
            f"analysis read capped at {MAX_READ} bytes; file is larger")
    if report["file"]["entropy"] >= 7.6:
        report["anomalies"].append(
            "very high byte entropy; encrypted/compressed/appended data is possible")
    try:
        from .hinted_stego import parse_hints, sweep as sweep_hints
        hints = parse_hints(list(report["text"]) +
                            [str(item.get("value", ""))
                             for item in report["metadata"] if item.get("is_text")] +
                            [item.get("value", "") for item in report["metadata"]])
        report["stego_hints"] = hints
        if hints.get("seed") is not None:
            hint_results, hint_note = sweep_hints(path, hints)
            if hint_results:
                report["stego"] = _unique(report["stego"] + [
                    {"method": "seeded %s / %s (channel %s plane %s)" % (
                        item["generator"], item["mapping"], item["channel"],
                        item["plane"]),
                     "output": item["text"], "score": item["score"],
                     "hint": item} for item in hint_results])
            if hint_note:
                report["anomalies"].append(hint_note)
        elif hints.get("raw"):
            report["anomalies"].append(
                "image advertises stego hints without a usable seed: " +
                "; ".join(hints["raw"])[:200])
    except Exception as exc:  # optional hint sweep must never break parsing
        report["anomalies"].append(f"hint sweep unavailable: {exc}")
    if run_tools:
        report["tools"] = run_optional_tools(path, passphrases=report["passphrases"])

    ledger = EvidenceLedger()
    text_inputs = []
    for item in report["metadata"]:
        text_inputs.append((f"metadata:{item.get('key')}", item.get("value", "")))
    for value in report["text"]:
        text_inputs.append(("embedded-text", value))
    for kind, values in report["strings"].items():
        for value in values:
            text_inputs.append((f"strings:{kind}", value))
    for item in report["stego"]:
        text_inputs.append((item.get("method", "stego"), item.get("output", "")))
    for item in report["embedded"]:
        for member in item.get("members", []):
            if member.get("text"):
                text_inputs.append((f"embedded:{item.get('type')}:{member.get('name')}",
                                    member["text"]))
        if item.get("text"):
            text_inputs.append((f"embedded:{item.get('type')}", item["text"]))
    for item in report["tools"]:
        output = item.get("output", "")
        if output:
            text_inputs.append((f"tool:{item.get('tool')}", output))
    report["decodes"] = _decode_texts(text_inputs, ledger)
    _flag_evidence(ledger, json.dumps(report["signatures"]),
                   "embedded-signature", verified=False, confidence=.45)
    report["findings"] = [item.as_dict() for item in ledger.all()]
    # Kept out of findings/verified/candidate lists on purpose: these are the
    # traps the challenge planted, and no summary should offer them as answers.
    report["decoy_flags"] = ledger.suppressed_decoys()
    report["verified_flags"] = ledger.values("verified")
    report["candidate_flags"] = ledger.values("candidate")
    report["summary"] = {
        "metadata": len(report["metadata"]), "chunks": len(report["chunks"]),
        "anomalies": len(report["anomalies"]),
        "strings": sum(len(v) for v in report["strings"].values()),
        "stego_decodes": len(report["stego"]), "derived_decodes": len(report["decodes"]),
        "signatures": len(report["signatures"]),
        "embedded": len(report["embedded"]),
        "tools_run": sum(1 for x in report["tools"] if x.get("available")),
        "verified_flags": len(report["verified_flags"]),
        "candidate_flags": len(report["candidate_flags"]),
        "decoy_flags": len(report["decoy_flags"]),
    }
    return report


def run_image(path, run_tools=True):
    """CLI presentation; return only verified values for legacy dispatch."""
    from core.output import flag_line, info_line, ok_line, section, warn_line
    report = analyze_image(path, run_tools=run_tools)
    section("🖼️ IMAGE FORENSICS / STEGO")
    for key, value in report["file"].items():
        info_line(f"{key}: {value}")
    info_line(f"format: {report['format']}")
    if report["metadata"]:
        section("Metadata / EXIF / chunks")
        for item in report["metadata"]:
            ok_line(f"{item.get('source')}: {item.get('key')} = {item.get('value')}")
    for name, values in (("Embedded text", report["text"]),
                         ("Strings ASCII/UTF", [f"{k}: {v}" for k, vals in report["strings"].items() for v in vals])):
        if values:
            section(name)
            for value in values[:MAX_LIST]:
                info_line(_clip(value))
    if report["stego"]:
        section("Stego bit-plane candidates")
        for item in report["stego"]:
            warn_line(f"{item.get('method')}: {item.get('output')}")
    if report["embedded"]:
        section("Embedded archive payloads")
        for item in report["embedded"]:
            info_line(json.dumps(item, ensure_ascii=False, default=str)[:MAX_TEXT])
    if report["signatures"]:
        section("Embedded / polyglot signatures")
        for item in report["signatures"]:
            warn_line(f"{item['type']} at offset {item['offset']} ({item['magic']})")
    if report["anomalies"]:
        section("Anomalies / warnings")
        for item in report["anomalies"]:
            warn_line(item)
    if report["decodes"]:
        section("Derived decodes")
        for item in report["decodes"]:
            info_line(f"{item.get('source')} :: {item.get('method')} => {item.get('output', item.get('error'))}")
            explanation = item.get("explanation")
            if explanation:
                ok_line(f"วิธีแกะ: {explanation['summary']} ({explanation['scope']})")
                for step in explanation.get("steps", []):
                    print(f"      {step['index']}. {step['operation']}: "
                          f"{step['input']} -> {step['output']}")
    if report["tools"]:
        section("Optional forensic tools")
        for item in report["tools"]:
            info_line(f"{item.get('tool')}: {item.get('output', item.get('error', 'not installed'))}")
    section("Findings")
    verified = [item for item in report["findings"] if item["kind"] == "verified"]
    candidates = [item for item in report["findings"] if item["kind"] == "candidate"]
    for item in verified:
        flag_line(item["value"])
    for item in candidates:  # guesses stay secondary and clearly labelled
        warn_line(f"UNVERIFIED GUESS [{item['source']}] {item['value']}")
    for value in report.get("decoy_flags", []):
        info_line(f"decoy ignored (do not submit): {value}")
    if not verified and not candidates:
        info_line("no flag-shaped text found in this image")
    info_line("summary: " + json.dumps(report["summary"], ensure_ascii=False))
    return report["verified_flags"]
