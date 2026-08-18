"""Threaded directory/endpoint brute force with 404 normalization."""
import os

from core import httpx
from core.flag import extract_flags
from core.notfound import calibrator_for
from core.parallel import pmap

WORDLISTS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "wordlists"))
DEFAULT_WORDLIST = os.path.join(WORDLISTS, "dirs.txt")

INTERESTING = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}


class DirBuster:
    def __init__(self, base, wordlist=None, workers=50, extensions=None):
        self.base = base.rstrip("/")
        self.workers = workers
        self.extensions = extensions or [""]
        with open(wordlist or DEFAULT_WORDLIST, encoding="utf-8", errors="ignore") as f:
            self.paths = [line.strip() for line in f if line.strip()]
        self.cal = calibrator_for(self.base)
        self.found = []

    def _is_interesting(self, r, path):
        if r is None:
            return False
        if self.cal.is_missing(r):
            return False  # hard-404 or byte-identical soft-404 skeleton
        if r.status not in INTERESTING:
            return False
        # soft-404 heuristics on 200 HTML pages that differ from the probes
        fp = (r.status, r.headers.get("content-type", ""), 0)
        if r.status == 200 and "text/html" in fp[1]:
            low = r.text[:4000].lower()
            if ("page not found" in low or "does not exist" in low
                    or "no such file" in low or "<title>404" in low):
                if len(r.body) < 1500:
                    return False
        # soft-404 heuristics on 200 HTML pages
        if r.status == 200 and "text/html" in fp[1]:
            low = r.text[:4000].lower()
            if ("page not found" in low or "does not exist" in low
                    or "no such file" in low or "<title>404" in low):
                if len(r.body) < 1500:
                    return False
        return True

    def _check(self, path):
        hits = []
        for ext in self.extensions:
            full = path if not ext else path + ext
            r = httpx.get(self.base + "/" + full, timeout=6)
            if self._is_interesting(r, full):
                hits.append((full, r))
        return hits

    def run(self, extra_paths=None):
        candidates = list(dict.fromkeys(self.paths + (extra_paths or [])))
        # prioritize paths containing interesting keywords
        def rank(p):
            kw = ("flag", "secret", "admin", "config", "env", "backup", "git", "user")
            return sum(1 for k in kw if k in p.lower())
        candidates.sort(key=rank, reverse=True)
        self.found = []
        for item, result in pmap(self._check, candidates, workers=self.workers, desc="dirbust"):
            if isinstance(result, Exception):
                continue
            for full, r in result:
                note = ""
                loc = r.headers.get("location", "")
                if loc:
                    note = f" -> {loc[:60]}"
                self.found.append((full, r.status, len(r.body), note))
        # sort: interesting first
        self.found.sort(key=lambda x: (x[1] not in (200, 301, 302), x[1]))
        return self.found


def format_results(found, limit=60):
    lines = []
    for path, status, size, note in found[:limit]:
        lines.append(f"  {status:<4} {path:<45} ({size} bytes){note}")
    return lines


def scan_for_flags(found_results, base):
    """Re-fetch interesting results and scan bodies for flags."""
    flags = []
    for path, status, _, _ in found_results:
        if status not in (200, 301):
            continue
        r = httpx.get(base + "/" + path, timeout=8)
        if r is None:
            continue
        known, cands = extract_flags(r.text)
        for f in known + cands:
            if f not in flags:
                flags.append(f)
        # content-type hints: source code often contains flags
        if status == 200 and ("text/plain" in r.headers.get("content-type", "")):
            known, cands = extract_flags(r.body.decode("latin-1", "replace"))
            for f in known + cands:
                if f not in flags:
                    flags.append(f)
    return flags
