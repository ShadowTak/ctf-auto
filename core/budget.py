"""Adaptive resource limits shared by CPU and network-heavy scanners.

The defaults are intentionally conservative: more threads do not always mean
more throughput, especially when scanners nest pools or targets rate-limit.
"""
import os
import threading
import time


def cpu_count():
    return max(1, os.cpu_count() or 1)


def workers(kind="io", requested=None):
    """Return bounded worker count, overridable with CTF_AUTO_WORKERS."""
    if requested is not None:
        return max(1, int(requested))
    try:
        override = int(os.environ.get("CTF_AUTO_WORKERS", "0"))
    except ValueError:
        override = 0
    if override > 0:
        return override
    if kind == "cpu":
        return min(8, cpu_count())
    return min(32, max(4, cpu_count() * 4))


class Budget:
    """Thread-safe request/time/node budget.

    A budget is best-effort: in-flight requests are not forcibly interrupted,
    but new work stops immediately after exhaustion.
    """
    def __init__(self, requests=0, seconds=0, nodes=0):
        self.request_limit = max(0, int(requests or 0))
        self.node_limit = max(0, int(nodes or 0))
        self.deadline = time.monotonic() + float(seconds) if seconds else 0
        self._requests = 0
        self._nodes = 0
        self._lock = threading.Lock()

    def expired(self):
        return bool(self.deadline and time.monotonic() >= self.deadline)

    def take_request(self, amount=1):
        with self._lock:
            if self.expired() or (self.request_limit and
                                  self._requests + amount > self.request_limit):
                return False
            self._requests += amount
            return True

    def take_node(self, amount=1):
        with self._lock:
            if self.expired() or (self.node_limit and
                                  self._nodes + amount > self.node_limit):
                return False
            self._nodes += amount
            return True

    @property
    def requests(self):
        return self._requests

    @property
    def nodes(self):
        return self._nodes
