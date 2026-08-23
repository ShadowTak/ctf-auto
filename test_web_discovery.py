"""Local regression tests for recursive route/API discovery."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from modules.web.discovery import crawl


class _DiscoveryHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *_args):
        pass

    def do_GET(self):  # noqa: N802
        routes = {
            "/": ("text/html", b'<a href="/app">app</a><a href="/openapi.json">api</a><script src="/app.js"></script>'),
            "/app": ("text/html", b'<form action="/api/search"><input name="q"></form>'),
            "/app.js": ("application/javascript", b'fetch("/api/hidden");'),
            "/api/hidden": ("text/plain", b"redacted{discovery_ok}"),
            "/openapi.json": ("application/json", json.dumps({
                "paths": {"/api/openapi-secret": {"get": {}}}}).encode()),
        }
        content_type, body = routes.get(self.path.split("?", 1)[0],
                                        ("text/plain", b"not found"))
        status = 200 if self.path.split("?", 1)[0] in routes else 404
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class WebDiscoveryTests(unittest.TestCase):
    def test_recursive_links_js_and_json_routes(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _DiscoveryHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            findings, flags, paths, pages = crawl(base, max_pages=12, max_depth=3)
        finally:
            server.shutdown()
            server.server_close()
        self.assertIn("redacted{discovery_ok}", flags)
        self.assertIn("app.js", paths)
        self.assertIn("api/hidden", paths)
        self.assertTrue(any("form GET" in line for line in findings))
        self.assertGreaterEqual(len(pages), 3)


if __name__ == "__main__":
    unittest.main()
