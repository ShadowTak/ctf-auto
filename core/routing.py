"""Decide what a single ``auto`` target actually is.

A competition throws two very different things at you: files to unpack (a
binary, an archive, a pcap, a cipher blob) and live services to search (a web
URL, a host to recon). ``--category auto`` should swallow either without the
operator having to pick the category first, so this maps a raw target string
to the scanner that fits it.
"""
from __future__ import annotations

import os
import re

# Dotted strings whose final label is one of these are files, not hostnames —
# so a mistyped ``cipher.txt`` is analysed as data instead of being scanned as
# a network host that will never resolve.
_FILE_SUFFIXES = {
    "txt", "bin", "dat", "enc", "hex", "b64", "png", "jpg", "jpeg", "gif",
    "bmp", "webp", "tiff", "ico", "pcap", "pcapng", "zip", "gz", "tar", "tgz",
    "7z", "rar", "py", "js", "json", "xml", "html", "md", "pem", "der", "pub",
    "key", "elf", "exe", "so", "dll", "o", "wav", "mp3", "flac", "pdf", "doc",
    "csv", "tsv", "vcd", "sal", "log", "class", "jar", "apk", "img", "iso",
}

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)


def classify_target(target) -> str:
    """Return ``path`` | ``url`` | ``host`` | ``text`` for *target*.

    An existing filesystem path always wins, so a file literally named like a
    URL is still treated as a file.
    """
    if target is None:
        return "text"
    text = str(target).strip()
    if not text:
        return "text"
    if os.path.exists(text) and not os.path.islink(text):
        return "path"
    if re.match(r"^https?://", text, re.IGNORECASE):
        return "url"
    if " " in text or "\n" in text or "\t" in text:
        return "text"
    # host, host:port, or host/path — only the authority is examined.
    authority = text.split("/", 1)[0]
    host = authority
    port_split = authority.rsplit(":", 1)
    has_port = len(port_split) == 2 and port_split[1].isdigit()
    if has_port:
        host = port_split[0]
    if _IPV4.match(host):
        return "host"
    if _HOSTNAME.match(host):
        suffix = host.rsplit(".", 1)[-1].lower()
        if has_port or suffix not in _FILE_SUFFIXES:
            return "host"
    return "text"


# How each non-path target kind is scanned. A URL is a web app; a bare host is
# a full network→web chain; raw text is a cipher/encoding blob.
_KIND_TO_CATEGORY = {"url": "web", "host": "full", "text": "crypto"}


def category_for_target(target):
    """Return ``(category, kind)`` for routing an ``auto`` run.

    ``category`` is ``"batch"`` for a file/directory (the isolated artifact
    solver) or a direct scanning category otherwise.
    """
    kind = classify_target(target)
    if kind == "path":
        return "batch", kind
    return _KIND_TO_CATEGORY[kind], kind
