"""Threading helpers — run many small tasks in parallel with progress."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from .output import Progress


def pmap(func, items, workers=32, desc="", timeout=None):
    """Apply func to every item across a thread pool.

    Returns list of (item, result). Exceptions are captured per item and
    returned as (item, exc) so one failure never kills the sweep.
    """
    items = list(items)
    if not items:
        return []
    workers = max(1, min(workers, len(items)))
    progress = Progress(len(items), desc=desc)
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(func, it): it for it in items}
        for fut in as_completed(futures):
            it = futures[fut]
            try:
                results.append((it, fut.result()))
            except Exception as exc:  # noqa: BLE001 — sweep must survive
                results.append((it, exc))
            progress.tick()
    progress.finish()
    return results


def run_concurrent(funcs, workers=16, desc=""):
    """Run a list of zero-arg callables concurrently; return list of results."""
    if not funcs:
        return []
    progress = Progress(len(funcs), desc=desc)
    results = [None] * len(funcs)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for i, fn in enumerate(funcs):
            futures[pool.submit(fn)] = i
        for fut in as_completed(futures):
            i = futures[fut]
            try:
                results[i] = fut.result()
            except Exception as exc:  # noqa: BLE001
                results[i] = exc
            progress.tick()
    progress.finish()
    return results
