"""Recursive artifact extraction without trusting filenames or archive paths."""
import io
import tarfile
import zipfile
import gzip
import bz2
import lzma


MAX_DEPTH = 4
MAX_MEMBERS = 256
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def _decompress(data):
    for magic, fn in ((b"\x1f\x8b", gzip.decompress),
                      (b"BZh", bz2.decompress),
                      (b"\xfd7zXZ\x00", lzma.decompress)):
        if data.startswith(magic):
            try:
                return fn(data)
            except Exception:
                return None
    return None


def extract(data, depth=0):
    """Return [(label, bytes)] for input and safe nested members."""
    data = bytes(data)
    output = [("root", data)]
    if depth >= MAX_DEPTH or len(data) > MAX_MEMBER_BYTES:
        return output
    children = []
    try:
        if data.startswith(b"PK"):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist()[:MAX_MEMBERS]:
                    if info.is_dir() or info.file_size > MAX_MEMBER_BYTES:
                        continue
                    children.append(("zip:" + info.filename, archive.read(info)))
        elif len(data) > 512 and (data.startswith(b"ustar") or data[257:262] == b"ustar"):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for info in archive.getmembers()[:MAX_MEMBERS]:
                    if not info.isfile() or info.size > MAX_MEMBER_BYTES:
                        continue
                    stream = archive.extractfile(info)
                    if stream:
                        children.append(("tar:" + info.name, stream.read(MAX_MEMBER_BYTES + 1)))
    except (OSError, ValueError, EOFError, tarfile.TarError, zipfile.BadZipFile):
        children = []
    decompressed = _decompress(data)
    if decompressed is not None:
        children.append(("compressed", decompressed))
    total = sum(len(value) for _, value in output)
    for label, value in children:
        if len(value) > MAX_MEMBER_BYTES or total + len(value) > MAX_TOTAL_BYTES:
            continue
        output.extend((label + "/" + child_label, child)
                      for child_label, child in extract(value, depth + 1))
        total += len(value)
        if len(output) >= MAX_MEMBERS:
            break
    return output[:MAX_MEMBERS]
