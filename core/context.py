"""Per-scan coordination for bounded, explainable CTF workflows.

The project still exposes legacy module functions that use process-local
helpers.  ``ScanContext`` is the bridge: a job owns its budget, cancellation
token, evidence ledger, events, and optional graph metadata.  Modules can
adopt it incrementally without changing their public return values.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import threading
import time
from typing import Any, Dict, Iterator, Optional

from . import budget as budget_mod
from . import cancel as cancel_mod
from .evidence import EvidenceLedger, Finding


@dataclass
class SessionState:
    """Serializable authentication state used for branchable web scans."""

    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    timeout: Optional[int] = None

    def clone(self) -> "SessionState":
        return SessionState(dict(self.cookies), dict(self.headers),
                            self.proxy, self.timeout)

    def as_dict(self) -> dict:
        return {
            "cookies": dict(self.cookies),
            "headers": dict(self.headers),
            "proxy": self.proxy,
            "timeout": self.timeout,
        }


@dataclass
class ScanEvent:
    timestamp: float
    kind: str
    message: str
    data: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "timestamp": round(float(self.timestamp), 3),
            "kind": self.kind,
            "message": self.message,
            "data": self.data,
        }


@dataclass
class ScanContext:
    """State shared by one bounded scan.

    ``active`` is the default CTF mode.  ``passive`` tells the web
    orchestrator to stop after read-only discovery and evidence collection;
    it does not change the legacy solver APIs.
    """

    target: str = ""
    category: str = ""
    mode: str = "active"
    prefix_hint: Optional[str] = None
    context_text: Optional[str] = None
    max_seconds: int = 0
    max_requests: int = 0
    max_nodes: int = 0
    max_bytes: int = 0
    max_depth: int = 12
    metadata: dict = field(default_factory=dict)
    ledger: EvidenceLedger = field(default_factory=EvidenceLedger)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    started: float = field(default_factory=time.time)
    events: list[ScanEvent] = field(default_factory=list)
    _event_lock: threading.RLock = field(default_factory=threading.RLock,
                                          repr=False)
    _budget: Any = field(default=None, init=False, repr=False)
    _entered: bool = field(default=False, init=False, repr=False)
    _finished: bool = field(default=False, init=False, repr=False)

    def __post_init__(self):
        self.mode = str(self.mode or "active").lower()
        if self.mode not in {"active", "passive"}:
            self.mode = "active"
        for name in ("max_seconds", "max_requests", "max_nodes",
                     "max_bytes"):
            setattr(self, name, max(0, int(getattr(self, name) or 0)))
        self.max_depth = max(1, int(self.max_depth or 12))
        self.target = str(self.target or "")
        self.category = str(self.category or "")

    @property
    def active(self) -> bool:
        return self.mode == "active"

    @property
    def elapsed(self) -> float:
        return max(0.0, time.time() - self.started)

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set() or budget_mod.expired()

    @property
    def finished(self) -> bool:
        return self._finished

    def event(self, kind: str, message: str, **data) -> ScanEvent:
        """Append a small JSON-safe event and return it."""
        item = ScanEvent(time.time(), str(kind), str(message), data)
        with self._event_lock:
            self.events.append(item)
            # A stalled solver must not make the in-memory job grow forever.
            if len(self.events) > 4000:
                del self.events[:-2000]
        return item

    def progress(self, phase: str, done: int = 0, total: int = 0, **data):
        payload = {"phase": str(phase), "done": max(0, int(done or 0)),
                   "total": max(0, int(total or 0))}
        payload.update(data)
        self.metadata["progress"] = payload
        self.event("progress", str(phase), **payload)

    def charge_node(self, amount: int = 1) -> bool:
        if self.cancelled:
            return False
        return budget_mod.take_node(max(1, int(amount or 1)))

    def charge_bytes(self, amount: int) -> bool:
        """Charge expanded bytes against the optional per-scan byte budget."""
        amount = max(0, int(amount or 0))
        if not amount:
            return not self.cancelled
        if self.max_bytes <= 0:
            return not self.cancelled
        with self._event_lock:
            used = int(self.metadata.get("expanded_bytes", 0))
            if used + amount > self.max_bytes:
                self.event("budget", "byte budget exhausted", used=used,
                           requested=amount, limit=self.max_bytes)
                return False
            self.metadata["expanded_bytes"] = used + amount
        return True

    def cancel(self, reason: str = "operator requested stop") -> None:
        self.event("cancel", reason)
        cancel_mod.stop_event(self.cancel_event)

    def add(self, value, **kwargs) -> Optional[Finding]:
        finding = self.ledger.add(value, **kwargs)
        if finding is not None:
            self.event("finding", "evidence recorded", finding=finding.as_dict())
        return finding

    def add_flag(self, value, **kwargs) -> Optional[Finding]:
        finding = self.ledger.add_flag(value, **kwargs)
        if finding is not None:
            self.event("finding", "flag evidence recorded", finding=finding.as_dict())
        return finding

    def snapshot(self) -> dict:
        with self._event_lock:
            events = [item.as_dict() for item in self.events]
            metadata = dict(self.metadata)
        active_budget = budget_mod.active()
        budget_snapshot = None
        if active_budget is not None:
            budget_snapshot = {
                "requests": active_budget.requests,
                "request_limit": active_budget.request_limit,
                "nodes": active_budget.nodes,
                "node_limit": active_budget.node_limit,
                "expired": active_budget.expired(),
            }
        return {
            "target": self.target,
            "category": self.category,
            "mode": self.mode,
            "prefix_hint": self.prefix_hint,
            "elapsed": round(self.elapsed, 3),
            "cancelled": bool(self.cancelled),
            "finished": self.finished,
            "metadata": metadata,
            "budget": budget_snapshot,
            "findings": self.ledger.as_dicts(),
            "events": events[-2000:],
        }

    def __enter__(self) -> "ScanContext":
        if self._entered:
            return self
        self._budget = budget_mod.configure(
            requests=self.max_requests,
            seconds=self.max_seconds,
            nodes=self.max_nodes,
        )
        cancel_mod.set_event(self.cancel_event)
        self._entered = True
        self.event("scan", "scan context started", target=self.target,
                   category=self.category, mode=self.mode)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self._entered:
            return
        self._finished = True
        self.event("scan", "scan context finished", elapsed=round(self.elapsed, 3),
                   error=str(exc) if exc else "")
        cancel_mod.clear_event()
        budget_mod.clear()
        self._budget = None
        self._entered = False


@contextmanager
def context_scope(context: Optional[ScanContext]) -> Iterator[Optional[ScanContext]]:
    """Install a context for legacy code and always restore global state."""
    if context is None:
        yield None
        return
    with context:
        yield context


def context_from_dict(data: Optional[dict], *, target: str = "",
                      category: str = "") -> ScanContext:
    """Build a context from CLI/API JSON without trusting unknown fields."""
    data = data or {}
    metadata = data.get("metadata", {}) or {}
    if not isinstance(metadata, dict):
        metadata = {}
    return ScanContext(
        target=target or str(data.get("target", "")),
        category=category or str(data.get("category", "")),
        mode=str(data.get("mode", "active")),
        prefix_hint=data.get("prefix_hint", data.get("prefix")),
        context_text=data.get("context_text", data.get("context")),
        max_seconds=data.get("max_seconds", 0),
        max_requests=data.get("max_requests", 0),
        max_nodes=data.get("max_nodes", 0),
        max_bytes=data.get("max_bytes", 0),
        max_depth=data.get("max_depth", 12),
        metadata=dict(metadata),
    )
