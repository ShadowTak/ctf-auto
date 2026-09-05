"""Bounded in-memory traversal; no archive member is executed or written."""
import io
import tarfile
import zipfile
import bz2
import lzma
import zlib

MAX_DEPTH = 4
MAX_MEMBERS = 256
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def _known_magic(data):
    return data.startswith((b'\x89PNG\r\n\x1a\n', b'\xff\xd8\xff', b'GIF8',
                            b'PK\x03\x04', b'\x7fELF', b'%PDF', b'\x1f\x8b'))


def byte_order_repairs(data):
    """Recognize reversed 16/32/64-bit words and fully reversed file headers."""
    if _known_magic(data) or len(data) < 8:
        return []
    out = []
    for width in (2, 4, 8):
        head = b''.join(data[i:i+width][::-1] for i in range(0, min(len(data), 32), width))
        if _known_magic(head):
            out.append((f'byte-swap-{width * 8}',
                        b''.join(data[i:i+width][::-1] for i in range(0, len(data), width))))
    if _known_magic(data[-32:][::-1]):
        out.append(('reverse-bytes', data[::-1]))
    return out


def _decompress(data, limit=None):
    """Bound allocation while decompressing, rather than after allocation."""
    limit = MAX_MEMBER_BYTES if limit is None else max(0, int(limit))
    try:
        chunks, size = [], 0
        # Concatenated members share the same limit; never silently drop a
        # second gzip/bzip2/xz member containing the rest of a challenge.
        for _ in range(MAX_MEMBERS):
            if data.startswith(bytes.fromhex("1f8b")):
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            elif data.startswith(b"BZh"):
                decoder = bz2.BZ2Decompressor()
            elif data.startswith(bytes.fromhex("fd377a585a00")):
                decoder = lzma.LZMADecompressor(memlimit=64 * 1024 * 1024)
            else:
                return None
            chunk = decoder.decompress(data, max_length=limit - size + 1)
            size += len(chunk)
            if size > limit or not decoder.eof:
                return None
            chunks.append(chunk)
            data = decoder.unused_data
            if not data:
                return b''.join(chunks)
        return None
    except (OSError, ValueError, EOFError, lzma.LZMAError, zlib.error):
        return None


def extract(data, depth=0, *, passwords=(), diagnostics=None):
    """Return root and nested members under traversal-wide byte/node limits.

    Bad/encrypted ZIP members are skipped individually. Passwords are explicit
    bounded guesses; TAR links are skipped and ZIP links remain inert bytes.
    """
    data = bytes(data)
    output = [("root", data)]
    remaining = max(0, MAX_TOTAL_BYTES - len(data))
    attempted = 0
    passwords = [p.encode() if isinstance(p, str) else bytes(p)
                 for p in list(passwords)[:64]]

    def note(path, reason):
        if diagnostics is not None and len(diagnostics) < MAX_MEMBERS:
            diagnostics.append({"path": path, "reason": reason})

    def visit(value, path, level):
        nonlocal remaining, attempted
        if level >= MAX_DEPTH or len(value) > MAX_MEMBER_BYTES:
            note(path, "depth or member-byte limit")
            return

        def add(label, child):
            nonlocal remaining
            name = label if path == "root" else path + "/" + label
            if len(child) > MAX_MEMBER_BYTES or len(child) > remaining:
                note(name, "expanded-byte limit")
                return
            remaining -= len(child)
            output.append((name + "/root", child))
            visit(child, name, level + 1)

        try:
            for label, repaired in byte_order_repairs(value):
                if attempted >= MAX_MEMBERS - 1 or len(output) >= MAX_MEMBERS:
                    break
                attempted += 1
                add(label, repaired)
            if value.startswith(b"PK"):
                with zipfile.ZipFile(io.BytesIO(value)) as archive:
                    for member in archive.infolist():
                        if attempted >= MAX_MEMBERS - 1 or len(output) >= MAX_MEMBERS:
                            note(path, "member-count limit")
                            break
                        attempted += 1
                        if member.is_dir():
                            continue
                        label = "zip:" + member.filename
                        limit = min(MAX_MEMBER_BYTES, remaining)
                        if member.file_size > limit:
                            note(label, "expanded-byte limit")
                            continue
                        keys = passwords if member.flag_bits & 1 else [None]
                        success = False
                        for password in keys:
                            try:
                                with archive.open(member, pwd=password) as stream:
                                    child = stream.read(limit + 1)
                                add(label, child)
                                success = True
                                break
                            except (RuntimeError, NotImplementedError, OSError,
                                    ValueError, EOFError, zipfile.BadZipFile, zlib.error):
                                continue
                        if not success:
                            note(label, "encrypted, corrupt or unsupported ZIP member")
            elif len(value) >= 512 and value[257:262] == b"ustar":
                with tarfile.open(fileobj=io.BytesIO(value), mode="r:") as archive:
                    for member in archive:
                        if attempted >= MAX_MEMBERS - 1 or len(output) >= MAX_MEMBERS:
                            note(path, "member-count limit")
                            break
                        attempted += 1
                        if not member.isfile():
                            continue
                        limit = min(MAX_MEMBER_BYTES, remaining)
                        if member.size > limit:
                            note(member.name, "expanded-byte limit")
                            continue
                        with archive.extractfile(member) as stream:
                            add("tar:" + member.name, stream.read(limit + 1))
            elif value.startswith((bytes.fromhex("1f8b"), b"BZh", bytes.fromhex("fd377a585a00"))):
                if attempted >= MAX_MEMBERS - 1 or len(output) >= MAX_MEMBERS:
                    note(path, "member-count limit")
                    return
                attempted += 1
                child = _decompress(value, min(MAX_MEMBER_BYTES, remaining))
                if child is None:
                    note(path, "compressed stream corrupt or expanded-byte limit")
                else:
                    add("compressed", child)
        except (OSError, ValueError, EOFError, tarfile.TarError, zipfile.BadZipFile):
            note(path, "malformed container")

    visit(data, "root", max(0, int(depth)))
    return output
