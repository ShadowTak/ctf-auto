"""Regression tests for the web UI's cooperative stop endpoint."""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import web_app


def test_stop_running_job_becomes_cancelled():
    jid = web_app._new_job()
    client = web_app.app.test_client()

    response = client.post(f"/api/stop/{jid}")
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["accepted"] is True
    assert payload["status"] == "stopping"

    status = client.get(f"/api/status/{jid}").get_json()
    assert status["status"] == "stopping"
    assert status["stop_requested"] is True

    web_app._finish_job(jid, [{"type": "partial"}])
    status = client.get(f"/api/status/{jid}").get_json()
    assert status["status"] == "cancelled"
    assert status["results"] == [{"type": "partial"}]


def test_stop_completed_job_is_not_accepted():
    jid = web_app._new_job()
    web_app._finish_job(jid, [])
    response = web_app.app.test_client().post(f"/api/stop/{jid}")
    assert response.status_code == 200
    assert response.get_json() == {"status": "done", "accepted": False}


def test_stop_interrupts_blocked_http_request():
    """Closing tracked sockets makes Stop return without waiting for timeout."""
    from core import httpx
    from core.cancel import clear_event, set_event, stop_event

    class SlowHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler API
            time.sleep(5)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"late")

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    event = threading.Event()
    result = {}
    set_event(event)
    worker = threading.Thread(
        target=lambda: result.setdefault(
            "value", httpx.get(f"http://127.0.0.1:{server.server_port}/", timeout=30)),
        daemon=True,
    )
    started = time.perf_counter()
    worker.start()
    time.sleep(.15)
    stop_event(event)
    worker.join(1.0)
    elapsed = time.perf_counter() - started
    clear_event()
    httpx.close_pool()
    server.shutdown()
    assert not worker.is_alive()
    assert elapsed < 1.0
    assert result.get("value") is None


if __name__ == "__main__":
    test_stop_running_job_becomes_cancelled()
    test_stop_completed_job_is_not_accepted()
    test_stop_interrupts_blocked_http_request()
    print("web cancel regression: PASS")
