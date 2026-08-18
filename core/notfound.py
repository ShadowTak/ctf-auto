"""Shared soft-404 / skeleton-page calibration.

Many apps answer *every* unknown path with HTTP 200 and the same HTML page
(catch-all SPA, custom 404 handler with wrong status, WAF interstitial...).
Probing a few guaranteed-missing paths gives us a fingerprint of that
skeleton page; every module that walks paths (dirbust, leak checks, asset
crawl) can then reject responses identical to it instead of reporting a
wall of false positives.

The calibrator is cached per base URL so it is only probed once per scan.
"""
import hashlib
import threading

from core import httpx

_PROBES = (
    "/zzz_does_not_exist_xyz",
    "/nonexistent_8383_qq",
    "/a1b2c3def_zzz_404",
    "/definitely_missing_404_qq",
)

_cache = {}
_lock = threading.Lock()


class NotFoundCalibrator:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self._fps = set()          # (status, content-type, body-hash)
        self._fallback_status = None
        self._probe()

    def _probe(self):
        statuses = set()
        for p in _PROBES:
            r = httpx.get(self.base + p, timeout=6)
            if r is None:
                continue
            statuses.add(r.status)
            self._fps.add(self._fp(r))
        # if the app returns one status code for every missing path, remember it
        if len(statuses) == 1:
            self._fallback_status = statuses.pop()

    @staticmethod
    def _fp(r):
        return (r.status, r.headers.get("content-type", ""),
                hashlib.md5(r.body[:8000]).hexdigest())

    def is_missing(self, r):
        """True when a response looks like the app's missing-page skeleton."""
        if r is None or r.status == 404:
            return True
        if self._fp(r) in self._fps:
            return True  # byte-identical to a known-missing path
        if self._fallback_status is not None and r.status == self._fallback_status:
            # same status as every missing path; keep non-HTML hits (real files)
            ctype = r.headers.get("content-type", "")
            if "text/html" in ctype:
                return True
        return False


def calibrator_for(base):
    """Get (and cache) the calibrator for a base URL."""
    base = base.rstrip("/")
    with _lock:
        c = _cache.get(base)
        if c is None:
            c = _cache[base] = NotFoundCalibrator(base)
        return c
