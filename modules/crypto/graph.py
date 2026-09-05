"""Typed recursive decode graph for heterogeneous CTF artifacts.

The legacy encoding helpers intentionally return printable text.  That is a
useful presentation contract, but it loses the binary intermediate between
layers such as ``base64 -> gzip -> XOR -> base64``.  This module keeps every
node as bytes, applies the existing decoders as adapters, and only converts to
text at the reporting boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import base64
import hashlib
import re
import time
from typing import Callable, Iterable, Optional

from core import budget
from core.cancel import cancelled
from core.flag import extract_flags
from . import encodings
from .common import is_printable_text, looks_like_encoding, text_score


@dataclass
class CryptoNode:
    """One typed value in a decode graph."""

    node_id: int
    depth: int
    kind: str
    data: bytes
    path: tuple[str, ...] = field(default_factory=tuple)
    parent: Optional[int] = None
    score: float = 0.0
    decoder: str = "input"

    @property
    def text(self) -> str:
        try:
            return self.data.decode("utf-8")
        except UnicodeDecodeError:
            return self.data.decode("latin-1", "replace")

    @property
    def printable(self) -> bool:
        return is_printable_text(self.text, min_ratio=0.85)

    def as_dict(self) -> dict:
        return {
            "id": self.node_id,
            "parent": self.parent,
            "depth": self.depth,
            "kind": self.kind,
            "decoder": self.decoder,
            "path": list(self.path),
            "score": round(float(self.score), 3),
            "bytes": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest()[:16],
            "preview": _preview(self.data),
        }


@dataclass
class CryptoEdge:
    source: int
    target: int
    operation: str

    def as_dict(self) -> dict:
        return {"source": self.source, "target": self.target,
                "operation": self.operation}


def _preview(data: bytes, limit: int = 240) -> str:
    text = bytes(data).decode("utf-8", "replace")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    if len(text) > limit:
        return text[:limit] + f"… ({len(text)} chars)"
    return text


def _as_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return str(value or "").encode("latin-1", "replace")


def _text(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("latin-1", "replace")


def _raw_decoders() -> list[tuple[str, Callable[[bytes], Optional[bytes]]]]:
    """Return binary-safe transport/compression adapters.

    Printable decoders from :mod:`encodings` remain the source of truth for
    normal text.  These adapters add only the missing byte-preserving step.
    """

    def b64(raw):
        compact = re.sub(rb"\s+", b"", raw)
        if len(compact) < 4:
            return None
        try:
            return base64.b64decode(compact, validate=True)
        except Exception:
            try:
                return base64.urlsafe_b64decode(compact + b"=" * (-len(compact) % 4))
            except Exception:
                return None

    def b32(raw):
        compact = re.sub(rb"\s+", b"", raw).upper()
        if len(compact) < 8:
            return None
        try:
            return base64.b32decode(compact + b"=" * (-len(compact) % 8))
        except Exception:
            return None

    def hex_bytes(raw):
        compact = re.sub(rb"\s+", b"", raw)
        if len(compact) < 2 or len(compact) % 2:
            return None
        if not re.fullmatch(rb"[0-9a-fA-F]+", compact):
            return None
        try:
            return bytes.fromhex(compact.decode("ascii"))
        except Exception:
            return None

    def binary(raw):
        compact = re.sub(rb"\s+", b"", raw)
        if len(compact) < 8 or len(compact) % 8 or not re.fullmatch(rb"[01]+", compact):
            return None
        try:
            return bytes(int(compact[i:i + 8], 2)
                         for i in range(0, len(compact), 8))
        except Exception:
            return None

    def base85(raw):
        if len(raw) < 5:
            return None
        for fn in (base64.a85decode, base64.b85decode):
            try:
                return fn(raw)
            except Exception:
                continue
        return None

    def compressed(raw):
        try:
            value = encodings.dec_compressed(raw)
            return _as_bytes(value) if value is not None else None
        except Exception:
            return None

    def gzip(raw):
        try:
            value = encodings.dec_gzip(raw)
            return _as_bytes(value) if value is not None else None
        except Exception:
            return None

    return [("base64", b64), ("base32", b32), ("hex", hex_bytes),
            ("binary", binary), ("base85", base85),
            ("compressed", compressed), ("gzip", gzip)]


_RAW_DECODERS = _raw_decoders()


def _score(data: bytes) -> float:
    """Lower is better, while retaining encoded and binary branches."""
    text = _text(data)
    known, candidates = extract_flags(text)
    if known:
        return -2000.0
    if candidates:
        return -1000.0
    if data and is_printable_text(text, min_ratio=0.95):
        try:
            return text_score(text) - min(len(data), 4000) * 0.03
        except Exception:
            pass
    if data and looks_like_encoding(text):
        return 80.0 - min(len(data), 4000) * 0.02
    # Keep binary nodes available, but below a likely text/transport branch.
    return 350.0 + min(len(data), 1_000_000) * 0.0001


def _binary_is_interesting(data: bytes) -> bool:
    """Keep binary intermediates only when they can plausibly lead somewhere.

    Generic base85/base62 decodes produce enormous amounts of random bytes.
    Retaining every one of them starves a clean repeated-base64 branch.  Raw
    compressed/archive magic and the explicit XOR/compression adapters are
    still preserved so mixed binary chains remain solvable.
    """
    if not data:
        return False
    if encodings.sniff_bytes(data):
        return True
    return data.startswith((b"\\x1f\\x8b", b"BZh", b"\\xfd7zXZ\\x00",
                            b"\\x78\\x01", b"\\x78\\x5e", b"\\x78\\x9c",
                            b"\\x78\\xda"))


def _candidate_is_useful(name: str, data: bytes) -> bool:
    text = _text(data)
    if _flag_hit(text) or is_printable_text(text, min_ratio=0.85):
        return True
    if _binary_is_interesting(data):
        return True
    return name in {"xor1", "hexxor", "b64xor", "compressed", "gzip"}


def _path_shape(path: tuple[str, ...]):
    """Return transform count and structural depth for beam tie-breaking."""
    transforms = {name for name, _ in encodings._CHAIN_TRANSFORMS}
    transform_count = sum(1 for name in path if name in transforms)
    structural_count = len(path) - transform_count
    return transform_count, structural_count


class DecodeGraph:
    """Budgeted beam-search graph over text and binary decode layers."""

    def __init__(self, value, *, max_depth=12, max_branches=8,
                 max_nodes=600, timeout=12.0, max_bytes=64 * 1024 * 1024,
                 flag_hint=None, context=None):
        self.root_data = _as_bytes(value)
        self.max_depth = max(1, int(max_depth or 12))
        self.max_branches = max(1, int(max_branches or 8))
        self.max_nodes = max(1, int(max_nodes or 600))
        self.timeout = max(0.1, float(timeout or 12.0))
        self.max_bytes = max(1, int(max_bytes or 64 * 1024 * 1024))
        self.flag_hint = flag_hint
        self.context = context
        self.nodes: list[CryptoNode] = []
        self.edges: list[CryptoEdge] = []
        self._seen = {self.root_data}
        self._expanded_bytes = len(self.root_data)
        self._built = False

    @property
    def root(self) -> CryptoNode:
        if not self.nodes:
            self.nodes.append(CryptoNode(0, 0, "bytes", self.root_data,
                                         (), None, _score(self.root_data), "input"))
        return self.nodes[0]

    def _allowed(self, data: bytes) -> bool:
        if not data or data in self._seen:
            return False
        if len(data) > self.max_bytes or self._expanded_bytes + len(data) > self.max_bytes:
            return False
        if self.context is not None:
            if not self.context.charge_bytes(len(data)):
                return False
        return True

    def _adapted_candidates(self, node: CryptoNode):
        raw = node.data
        text = _text(raw)
        yielded = []
        for name, fn in _RAW_DECODERS:
            try:
                value = fn(raw)
            except Exception:
                value = None
            if value and _candidate_is_useful(name, value):
                yielded.append((name, value))

        # Existing text decoders cover URL/HTML/JWT/classic transforms and
        # challenge-specific layers. Run them on a lossless latin-1 view.
        for name, fn in encodings._ALL_LAYER_DECODERS + encodings._CHAIN_TRANSFORMS:
            if name in {"base64", "base32", "base85", "hex", "binary",
                        "compressed", "gzip"}:
                continue
            try:
                value = fn(text)
            except Exception:
                value = None
            if value is None:
                continue
            value = _as_bytes(value)
            if value and _candidate_is_useful(name, value):
                yielded.append((name, value))
        # Multiple adapters can produce the same byte string. Keep the first
        # (usually the most specific raw adapter) to avoid consuming node
        # budget with duplicate edges.
        unique = []
        seen = set()
        for name, value in yielded:
            if value in seen:
                continue
            seen.add(value)
            unique.append((name, value))
        return unique

    def build(self):
        if self._built:
            return self
        started = time.monotonic()
        frontier = [self.root]
        for depth in range(self.max_depth):
            if not frontier or time.monotonic() - started >= self.timeout:
                break
            if cancelled():
                break
            next_nodes = []
            for node in frontier:
                # A flag-shaped plaintext is a terminal evidence node. Do
                # not run lossy transforms (leet/ROT/etc.) over it and create
                # counterfeit flag variants after the real answer is found.
                if _flag_hit(node.text):
                    continue
                if self.context is not None and not self.context.charge_node():
                    break
                elif self.context is None and not budget.take_node():
                    # With no active global budget this is a no-op.  If an
                    # external budget is active, stop cleanly at its limit.
                    if budget.active() is not None:
                        break
                for name, data in self._adapted_candidates(node):
                    if len(self.nodes) >= self.max_nodes or not self._allowed(data):
                        continue
                    self._seen.add(data)
                    self._expanded_bytes += len(data)
                    node_id = len(self.nodes)
                    child = CryptoNode(
                        node_id=node_id,
                        depth=node.depth + 1,
                        kind="text" if is_printable_text(_text(data), 0.85) else "bytes",
                        data=data,
                        path=node.path + (name,),
                        parent=node.node_id,
                        score=_score(data),
                        decoder=name,
                    )
                    self.nodes.append(child)
                    self.edges.append(CryptoEdge(node.node_id, node_id, name))
                    next_nodes.append(child)
                    if len(self.nodes) >= self.max_nodes:
                        break
                if len(self.nodes) >= self.max_nodes:
                    break
            if not next_nodes:
                break
            # Keep flag nodes and likely next encoding layers ahead of noisy
            # binary branches, while retaining enough diversity for mixed
            # chains that do not look English until their final layer.
            next_nodes.sort(key=lambda item: (
                0 if _flag_hit(item.text) else 1,
                # A transform-heavy branch is useful as a fallback, but a
                # clean structural path must survive ahead of ROT/leet noise.
                _path_shape(item.path)[0],
                -_path_shape(item.path)[1],
                0 if _encoding_like(item.text) else 1,
                item.score,
                -len(item.data),
            ))
            frontier = next_nodes[:self.max_branches]
        self._built = True
        return self

    def leaves(self) -> list[CryptoNode]:
        self.build()
        parents = {edge.source for edge in self.edges}
        return [node for node in self.nodes if node.node_id not in parents]

    def results(self, *, include_binary=False) -> list[tuple[str, str]]:
        """Return unique path/output pairs compatible with legacy ranking."""
        self.build()
        nodes = sorted(self.nodes[1:], key=lambda item: (
            0 if _flag_hit(item.text) else 1, item.score, item.depth))
        output = []
        seen = set()
        for node in nodes:
            if not include_binary and not node.printable and not _flag_hit(node.text):
                continue
            key = (">".join(node.path), node.data)
            if key in seen:
                continue
            seen.add(key)
            output.append((">".join(node.path), node.text))
        return output

    def flag_hits(self) -> list[str]:
        self.build()
        values = []
        for node in self.nodes:
            known, candidates = extract_flags(node.text)
            for item in known + candidates:
                if item not in values:
                    values.append(item)
        return values

    def as_dict(self, *, include_binary=False) -> dict:
        self.build()
        return {
            "root": 0,
            "nodes": [node.as_dict() for node in self.nodes
                      if include_binary or node.printable or _flag_hit(node.text)],
            "edges": [edge.as_dict() for edge in self.edges
                      if include_binary or edge.target < len(self.nodes)],
            "limits": {"max_depth": self.max_depth, "max_branches": self.max_branches,
                       "max_nodes": self.max_nodes, "max_bytes": self.max_bytes,
                       "timeout": self.timeout},
            "stats": {"nodes": len(self.nodes), "edges": len(self.edges),
                      "bytes": self._expanded_bytes},
        }


def _flag_hit(value: str) -> bool:
    known, candidates = extract_flags(value)
    return bool(known or candidates)


def _encoding_like(value: str) -> bool:
    try:
        return bool(value and looks_like_encoding(value))
    except Exception:
        return False


def decode_graph(value, **kwargs) -> DecodeGraph:
    """Convenience constructor used by autodetect and artifact pipelines."""
    return DecodeGraph(value, **kwargs).build()
