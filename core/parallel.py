"""Threading helpers — run many small tasks in parallel with progress."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from .cancel import cancelled
from .output import Progress
from .budget import workers as adaptive_workers


def pmap(func, items, workers=32, desc="", timeout=None):
    """Apply func to every item across a thread pool.

    Returns list of (item, result). Exceptions are captured per item and
    returned as (item, exc) so one failure never kills the sweep.
    """
    items = list(items)
    if not items:
        return []
    workers = max(1, min(adaptive_workers("io", workers), len(items)))
    progress = Progress(len(items), desc=desc)
    results = []
    pool = ThreadPoolExecutor(max_workers=adaptive_workers("io", workers))
    try:
        futures = {}
        for it in items:
            if cancelled():
                break
            futures[pool.submit(func, it)] = it
        for fut in as_completed(futures):
            it = futures[fut]
            try:
                results.append((it, fut.result()))
            except Exception as exc:  # noqa: BLE001 — sweep must survive
                results.append((it, exc))
            progress.tick()
            if cancelled():
                for pending in futures:
                    pending.cancel()
                break
    finally:
        pool.shutdown(wait=not cancelled(), cancel_futures=True)
    progress.finish()
    return results


def run_concurrent(funcs, workers=16, desc="", on_result=None):
    """Run a list of zero-arg callables concurrently; return list of results."""
    if not funcs:
        return []
    progress = Progress(len(funcs), desc=desc)
    results = [None] * len(funcs)
    pool = ThreadPoolExecutor(max_workers=adaptive_workers("io", workers))
    try:
        futures = {}
        for i, fn in enumerate(funcs):
            if cancelled():
                break
            futures[pool.submit(fn)] = i
        for fut in as_completed(futures):
            i = futures[fut]
            try:
                results[i] = fut.result()
            except Exception as exc:  # noqa: BLE001
                results[i] = exc
            if on_result is not None:
                on_result(i, results[i])
            progress.tick()
            if cancelled():
                for pending in futures:
                    pending.cancel()
                break
    finally:
        pool.shutdown(wait=not cancelled(), cancel_futures=True)
    progress.finish()
    return results
