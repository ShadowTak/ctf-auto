"""Evidence-aware findings shared by crypto, web, and UI layers.

Legacy scanners still return ``list[str]``.  The ledger gives newer code a
thread-safe place to retain provenance, confidence, and decode traces without
forcing every solver to change its return type at once.
"""
from dataclasses import dataclass, field
import threading
from typing import Iterable, Optional

from .flag import extract_flags

_KIND_RANK = {"decode": 0, "candidate": 1, "verified": 2}


def decode_trace(label):
    """Turn a solver label into a compact, stable human-readable trace."""
    label = str(label or "").strip()
    if label.startswith("chain-best(") and ")" in label:
        body = label[len("chain-best("):label.find(")")]
        return tuple(part.strip() for part in body.split(">") if part.strip())
    if label.startswith("chain[") and "=" in label:
        return (label.split("=", 1)[1].strip(),)
    if "->" in label:
        return tuple(part.strip() for part in label.split("->") if part.strip())
    return (label,) if label else ()


@dataclass
class Finding:
    value: str
    kind: str = "decode"
    source: str = "unknown"
    confidence: float = 0.0
    evidence: tuple = field(default_factory=tuple)
    sources: tuple = field(default_factory=tuple)

    def as_dict(self):
        return {
            "value": self.value,
            "kind": self.kind,
            "source": self.source,
            "sources": list(self.sources or (self.source,)),
            "confidence": round(float(self.confidence), 3),
            "evidence": list(self.evidence),
        }


def _clean_kind(kind):
    return kind if kind in _KIND_RANK else "decode"


def looks_flag_shaped(value):
    """Return whether a value has a known or generic flag shape.

    Shape is never proof by itself; callers must explicitly promote a finding
    to ``verified`` after mathematical or exact-transform validation.
    """
    known, candidates = extract_flags(str(value), include_candidates=True)
    return bool(known or candidates)


class EvidenceLedger:
    """Thread-safe deduplicating evidence store."""

    def __init__(self):
        self._items = {}
        self._lock = threading.RLock()

    @staticmethod
    def _key(value):
        return str(value).strip()

    def add(self, value, *, kind="decode", source="unknown", confidence=0.0,
            evidence: Optional[Iterable[str]] = None,
            trace: Optional[Iterable[str]] = None):
        if value is None:
            return None
        raw = str(value)
        key = self._key(raw)
        if not key:
            return None
        kind = _clean_kind(kind)
        evidence = tuple(str(x) for x in (evidence or ()) if str(x))
        trace = tuple(str(x) for x in (trace or ()) if str(x))
        source = str(source or "unknown")
        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.0
        trace_evidence = (("decode trace: " + " -> ".join(trace),)
                          if trace else ())
        with self._lock:
            old = self._items.get(key)
            if old is None:
                item = Finding(raw, kind, source, confidence,
                               evidence + trace_evidence, (source,))
                self._items[key] = item
                return item
            if _KIND_RANK[kind] > _KIND_RANK[old.kind]:
                old.kind = kind
            old.confidence = max(old.confidence, confidence)
            old.evidence = tuple(dict.fromkeys(
                old.evidence + evidence + trace_evidence))
            old.sources = tuple(dict.fromkeys(old.sources + (source,)))
            old.source = (old.sources[0] if len(old.sources) == 1
                          else ",".join(old.sources))
            return old

    def add_flag(self, value, *, source="unknown", verified=False,
                 confidence=0.0, evidence=None, trace=None):
        return self.add(value, kind="verified" if verified else "candidate",
                        source=source, confidence=confidence,
                        evidence=evidence, trace=trace)

    def extend(self, findings):
        for finding in findings or ():
            if isinstance(finding, Finding):
                self.add(finding.value, kind=finding.kind,
                         source=finding.source,
                         confidence=finding.confidence,
                         evidence=finding.evidence)
            elif isinstance(finding, dict):
                self.add(finding.get("value", ""),
                         kind=finding.get("kind", "decode"),
                         source=finding.get("source", "unknown"),
                         confidence=finding.get("confidence", 0.0),
                         evidence=finding.get("evidence", ()))
        return self

    def all(self):
        with self._lock:
            values = list(self._items.values())
        return sorted(values,
                      key=lambda x: (-_KIND_RANK[x.kind],
                                     -x.confidence, x.value))

    def verified(self):
        return [x for x in self.all() if x.kind == "verified"]

    def values(self, kind=None):
        items = self.all()
        if kind:
            items = [x for x in items if x.kind == kind]
        return [x.value for x in items]

    def as_dicts(self):
        return [item.as_dict() for item in self.all()]


def findings_from_flags(values, *, source="unknown", verified=False,
                        confidence=0.0, evidence=None):
    ledger = EvidenceLedger()
    for value in values or ():
        ledger.add_flag(value, source=source, verified=verified,
                        confidence=confidence, evidence=evidence)
    return ledger.all()
