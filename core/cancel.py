"""Cooperative cancellation token shared by one active scanner job."""
import threading


_lock = threading.Lock()
_event = None


def set_event(event=None):
    """Set the event checked by scanner worker threads."""
    global _event
    with _lock:
        _event = event


def clear_event():
    set_event(None)


def cancelled():
    with _lock:
        event = _event
    return bool(event and event.is_set())

