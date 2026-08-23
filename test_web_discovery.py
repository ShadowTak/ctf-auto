"""Local regression tests for recursive route/API discovery."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from modules.web.browser import _network_route_is_interesting
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
            "/app.js.map": ("application/json", json.dumps({
                "sources": ["src/app.ts"],
                "sourcesContent": ["const flag = 'MAP{source_map_ok}';"],
            }).encode()),
            "/api/hidden": ("text/plain", b"redacted{discovery_ok}"),
            "/openapi.json": ("application/json", json.dumps({
                "paths": {"/api/openapi-secret": {"get": {}}}}).encode()),
            "/v3/api-docs": ("application/json", json.dumps({
                "paths": {"/v1/unlinked": {
                    "post": {"operationId": "unlinked_secret"}}}}).encode()),
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
        self.assertIn("MAP{source_map_ok}", flags)
        self.assertIn("app.js", paths)
        self.assertIn("app.js.map", paths)
        self.assertIn("api/hidden", paths)
        self.assertIn("v1/unlinked", paths)
        self.assertTrue(any("API operation POST /v1/unlinked" in line
                            for line in findings))
        self.assertTrue(any("form GET" in line for line in findings))
        self.assertGreaterEqual(len(pages), 3)

    def test_spa_route_classifier_covers_non_api_names(self):
        self.assertTrue(_network_route_is_interesting(
            "http://127.0.0.1:1/v1/hidden", "fetch"))
        self.assertTrue(_network_route_is_interesting(
            "http://127.0.0.1:1/query", "xhr"))
        self.assertTrue(_network_route_is_interesting(
            "http://127.0.0.1:1/report.json", "document"))
        self.assertFalse(_network_route_is_interesting(
            "http://127.0.0.1:1/assets/app.js", "script"))


if __name__ == "__main__":
    unittest.main()
