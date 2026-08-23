"""Cooperative cancellation token shared by one active scanner job."""
import socket
import threading


_lock = threading.Lock()
_event = None
_connections = set()


def set_event(event=None):
    """Set the event checked by scanner worker threads."""
    global _event
    with _lock:
        _event = event


def clear_event():
    global _event, _connections
    with _lock:
        _event = None
        _connections.clear()


def register_connection(connection):
    """Track a live HTTP connection so a stop request can close it."""
    with _lock:
        stopping = _event is not None and _event.is_set()
        if _event is not None:
            _connections.add(connection)
    if stopping:
        try:
            if connection.sock:
                connection.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            connection.close()
        except Exception:
            pass


def unregister_connection(connection):
    with _lock:
        _connections.discard(connection)


def stop_event(event):
    """Set *event* and interrupt sockets currently owned by that job."""
    with _lock:
        if event is not _event:
            event.set()
            return
        connections = tuple(_connections)
        event.set()
    for connection in connections:
        try:
            if connection.sock:
                connection.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            connection.close()
        except Exception:
            pass


def cancelled():
    with _lock:
        event = _event
    return bool(event and event.is_set())
