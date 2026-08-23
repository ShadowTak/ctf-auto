"""Evidence-aware findings shared by the crypto, web, and UI layers.

The legacy scanners return ``list[str]`` for compatibility.  This module
provides a richer representation without forcing every solver to change its
return type at once.
"""
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .flag import extract_flags

_KIND_RANK = {"decode": 0, "candidate": 1, "verified": 2}


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
    """Return whether *value* has a known or generic flag shape.

    Shape alone is intentionally not treated as proof.  Callers should use
    ``verified=True`` only after the solver has independently validated it.
    """
    known, candidates = extract_flags(str(value), include_candidates=True)
    return bool(known or candidates)


class EvidenceLedger:
    """Deduplicate findings while retaining the strongest evidence.

    A value can be discovered by many solvers.  The ledger merges those
    observations and promotes ``decode -> candidate -> verified`` only when a
    caller explicitly supplies stronger evidence.
    """

    def __init__(self):
        self._items = {}

    @staticmethod
    def _key(value):
        return str(value).strip()

    def add(self, value, *, kind="decode", source="unknown", confidence=0.0,
            evidence: Optional[Iterable[str]] = None):
        if value is None:
            return None
        raw = str(value)
        key = self._key(raw)
        if not key:
            return None
        kind = _clean_kind(kind)
        evidence = tuple(str(x) for x in (evidence or ()) if str(x))
        source = str(source or "unknown")
        old = self._items.get(key)
        if old is None:
            item = Finding(raw, kind, source, max(0.0, float(confidence)),
                           evidence, (source,))
            self._items[key] = item
            return item

        if _KIND_RANK[kind] > _KIND_RANK[old.kind]:
            old.kind = kind
        old.confidence = max(old.confidence, float(confidence))
        old.evidence = tuple(dict.fromkeys(old.evidence + evidence))
        old.sources = tuple(dict.fromkeys(old.sources + (source,)))
        old.source = old.sources[0] if len(old.sources) == 1 else ",".join(old.sources)
        return old

    def add_flag(self, value, *, source="unknown", verified=False,
                 confidence=0.0, evidence=None):
        kind = "verified" if verified else "candidate"
        return self.add(value, kind=kind, source=source,
                        confidence=confidence, evidence=evidence)

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
        return sorted(self._items.values(),
                      key=lambda x: (-_KIND_RANK[x.kind],
                                     -x.confidence, x.value))

    def verified(self):
        return [x for x in self.all() if x.kind == "verified"]

    def values(self, kind=None):
        items = self.all()
        if kind:
            items = [x for x in items if x.kind == kind]
        return [x.value for x in items]


def findings_from_flags(values, *, source="unknown", verified=False,
                        confidence=0.0, evidence=None):
    ledger = EvidenceLedger()
    for value in values or ():
        ledger.add_flag(value, source=source, verified=verified,
                        confidence=confidence, evidence=evidence)
    return ledger.all()
