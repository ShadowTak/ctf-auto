"""Low-cost, byte-preserving decode chains before statistical solver search.

Strict alphabet gates avoid dispatching every cipher at every layer. The
fallback graph still owns XOR, unusual alphabets and ambiguous transforms.
"""
import base64
import binascii
import codecs
import heapq
import html
import json
import re
import time
import urllib.parse
import zlib

from core.flag import extract_flags, normalize_prefix
from .artifacts import _decompress

TRANSPORTS = frozenset({'base64', 'base32', 'hex', 'binary', 'base85',
                        'ascii85', 'url', 'html', 'json-string', 'compressed',
                        'gzip', 'zlib', 'unicode'})
MAGIC = (b'\x1f\x8b', b'BZh', b'\xfd7zXZ\x00', b'PK\x03\x04', b'\x89PNG', b'%PDF')


def _interesting(data):
    if data.startswith(MAGIC) or (len(data) > 2 and data[0] == 0x78 and
                                  int.from_bytes(data[:2], 'big') % 31 == 0):
        return True
    try:
        text = data.decode('utf-8')
        return bool(text) and sum(c.isprintable() or c.isspace() for c in text) / len(text) >= .95
    except UnicodeError:
        return False


def _layers(raw, limit):
    compact = re.sub(rb'\s+', b'', raw)
    decoders = []
    if len(compact) >= 4 and re.fullmatch(rb'[A-Za-z0-9+/_-]+={0,2}', compact):
        decoders.append(('base64', lambda: base64.b64decode(compact + b'=' * (-len(compact) % 4), altchars=b'-_', validate=True)))
    if len(compact) >= 8 and re.fullmatch(rb'[A-Z2-7]+={0,6}', compact, re.I):
        decoders.append(('base32', lambda: base64.b32decode(compact.upper() + b'=' * (-len(compact) % 8))))
    if len(compact) >= 2 and len(compact) % 2 == 0 and re.fullmatch(rb'[a-fA-F0-9]+', compact):
        decoders.insert(0, ('hex', lambda: bytes.fromhex(compact.decode())))
    if len(compact) >= 8 and len(compact) % 8 == 0 and re.fullmatch(rb'[01]+', compact):
        decoders.insert(0, ('binary', lambda: bytes(int(compact[i:i+8], 2) for i in range(0, len(compact), 8))))
    if raw.startswith(MAGIC[:3]):
        decoders.insert(0, ('compressed', lambda: _decompress(raw, limit)))
    elif len(raw) > 2 and raw[0] == 0x78 and int.from_bytes(raw[:2], 'big') % 31 == 0:
        def inflate():
            decoder = zlib.decompressobj()
            value = decoder.decompress(raw, limit + 1)
            return value if decoder.eof and len(value) <= limit else None
        decoders.insert(0, ('zlib', inflate))
    if 5 <= len(raw) <= 65536 and re.fullmatch(rb'[!-u\s]+', raw):
        decoders.append(('ascii85', lambda: base64.a85decode(raw, adobe=raw.startswith(b'<~'))))
    if 5 <= len(raw) <= 65536 and re.fullmatch(rb'[0-9A-Za-z!#$%&()*+;<=>?@^_`{|}~-]+', raw):
        decoders.append(('base85', lambda: base64.b85decode(raw)))
    if re.search(rb'%[0-9a-fA-F]{2}', raw):
        decoders.append(('url', lambda: urllib.parse.unquote_to_bytes(raw)))
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        text = ''
    if text:
        if re.search(r'&(?:#\d+|#x[0-9a-fA-F]+|[A-Za-z]+);', text):
            decoders.append(('html', lambda: html.unescape(text).encode()))
        if text.startswith('"') and text.endswith('"'):
            def string_value():
                value = json.loads(text)
                return value.encode() if isinstance(value, str) else None
            decoders.append(('json-string', string_value))
        if re.fullmatch(r'(?:\\x[\da-fA-F]{2})+', text):
            decoders.append(('unicode', lambda: bytes.fromhex(text.replace('\\x', ''))))
        # A low-priority reversible transform catches ROT13-wrapped transport
        # strings. Its evidence remains a candidate until independently checked.
        if len(text) <= 65536 and re.search('[A-Za-z]', text):
            decoders.append(('rot13', lambda: codecs.encode(text, 'rot_13').encode()))
    for name, decode in decoders:
        try:
            value = decode()
            if value and value != raw and len(value) <= limit and _interesting(value):
                yield name, value
        except (ValueError, UnicodeError, binascii.Error, zlib.error):
            continue


def decode_fast(value, *, prefix=None, max_depth=64, max_nodes=512,
                max_bytes=16 * 1024 * 1024, timeout=1.0):
    """Return exact path/plaintext pairs, with all search limits enforced."""
    raw = value.encode() if isinstance(value, str) else bytes(value)
    if len(raw) > max_bytes:
        return []
    expected = normalize_prefix(prefix)
    started, spent = time.monotonic(), len(raw)
    queue, seen, results = [(0, 0, 0, raw, ())], {raw}, []
    serial = 0
    while queue and len(seen) < max_nodes and time.monotonic() - started < timeout:
        transforms, _, _, raw, path = heapq.heappop(queue)
        text = raw.decode('utf-8', 'replace')
        known, candidates = extract_flags(text)
        hinted = expected and re.search(re.escape(expected) + r'[^}\r\n]{1,300}\}', text)
        if path and (known or candidates or hinted):
            return [('>'.join(path), text)]
        if len(path) >= max_depth:
            continue
        for name, data in _layers(raw, max_bytes - spent):
            if data in seen or spent + len(data) > max_bytes:
                continue
            seen.add(data); spent += len(data); serial += 1
            child = path + (name,)
            heapq.heappush(queue, (transforms + (name not in TRANSPORTS), -len(child), serial, data, child))
            if len(seen) >= max_nodes:
                break
    return results
