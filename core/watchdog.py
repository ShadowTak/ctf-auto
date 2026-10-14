"""A hard wall-clock deadline for a single in-process scan.

The batch/competition engine already runs each challenge in a disposable
subprocess it can SIGKILL. The *direct* CLI categories (``--category web`` and
friends) run in this process, so they need their own guarantee that a scan
cannot run forever. Two layers provide it:

* **SIGALRM** (posix, main thread) raises :class:`Deadline` at the next
  interruptible point — this breaks a blocking socket read instantly and
  unwinds the stack so partial findings already printed are kept.
* **A daemon backstop thread** force-exits the whole process a short grace
  period later. This is the catch-all for the cases SIGALRM cannot reach: a
  tight CPU loop in C, or the main thread blocked while a worker pool holds the
  GIL. ``os._exit`` skips interpreter shutdown so non-daemon worker threads
  cannot wedge the exit.

The network-touching categories get a finite default deadline; local compute
(crypto/image/logic on a file) is left uncapped unless the operator asks,
because there the work is CPU-bound, offline, and under their control.
"""
from __future__ import annotations

import os
import signal
import sys
import threading
import time

# Finite defaults, in seconds, for categories that reach out over the network.
# Anything not listed defaults to 0 (no hard kill) unless overridden.
_NETWORK_DEADLINES = {"web": 300, "network": 300, "service": 180, "full": 420}

DEFAULT_GRACE = 10


class Deadline(Exception):
    """Raised in the main thread when the soft (SIGALRM) deadline fires."""


_cancel = threading.Event()
_armed = False


def default_deadline(category: str, user_seconds) -> int:
    """Resolve the effective deadline for *category*.

    An explicit positive ``user_seconds`` always wins; otherwise network
    categories fall back to a finite default and everything else to 0 (off).
    """
    try:
        user = int(user_seconds or 0)
    except (TypeError, ValueError):
        user = 0
    if user > 0:
        return user
    return _NETWORK_DEADLINES.get(category, 0)


def arm(seconds, *, label: str = "scan", grace: int = DEFAULT_GRACE, on_fire=None):
    """Install a hard deadline of *seconds*. A value <= 0 is a no-op."""
    global _armed
    seconds = float(seconds)
    if seconds <= 0:
        return
    _cancel.clear()
    _armed = True
    if os.name == "posix" and threading.current_thread() is threading.main_thread():
        def _handler(signum, frame):
            raise Deadline(f"{label} exceeded its {seconds:.0f}s deadline")
        signal.signal(signal.SIGALRM, _handler)
        signal.setitimer(signal.ITIMER_REAL, seconds)

    def _backstop():
        # Returns True (and stops) the moment disarm() is called.
        if _cancel.wait(seconds + grace):
            return
        if on_fire is not None:
            try:
                on_fire()
            except Exception:
                pass
        sys.stderr.write(
            f"\n[watchdog] {label}: hard deadline "
            f"{seconds:.0f}s (+{grace}s grace) reached — forcing exit\n")
        sys.stderr.flush()
        os._exit(124)

    threading.Thread(target=_backstop, name="ctf-watchdog", daemon=True).start()


def disarm():
    """Cancel the active deadline. Safe to call when nothing is armed."""
    global _armed
    if not _armed:
        return
    _armed = False
    _cancel.set()
    if os.name == "posix" and threading.current_thread() is threading.main_thread():
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
        except (ValueError, OSError):
            pass
