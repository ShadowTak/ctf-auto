"""Tiny vulnerable test server for exercising the web scanner locally.
ThreadingHTTPServer so concurrent scanner workers don't queue up behind a
single-threaded acceptor (which made the leak checks flaky)."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse

HOST = "127.0.0.1"
PORT = 18080

PAGES = {
    "/": b"""<!DOCTYPE html><html><body>
<!-- redacted{web_comment_flag_777} -->
<h1>Welcome to the test CTF shop</h1>
<p>Powered by TestCMS 1.0</p>
<form action="/search" method="get"><input name="q"><button>Search</button></form>
</body></html>""",
    "/robots.txt": b"User-agent: *\nDisallow: /secret/\nDisallow: /admin\n",
    "/secret/flag.txt": b"redacted{hidden_dir_flag_888}\n",
    "/admin": b"<h1>Admin panel (restricted)</h1>",
    "/config.php.bak": b"<?php $db_password = 'redacted{backup_file_flag_999}'; ?>\n",
    "/flag.txt": b"redacted{root_flag_555}\n",
}

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive + Content-Length framing

    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype="text/html"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "TestCMS/1.0")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in PAGES:
            body = PAGES[parsed.path]
            if parsed.path == "/admin":
                self._send(401, b"<h1>401 Unauthorized</h1>")
                return
            self._send(200, body,
                       "text/plain" if parsed.path.endswith(".txt") else "text/html")
            return
        if parsed.path == "/search":
            q = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
            self._send(200, f"<html><body>You searched for: {q}</body></html>".encode())
            return
        # 404 with distinctive body
        self._send(404, b"<html><body><h1>404 Not Found</h1>test-404-page</body></html>")

    do_POST = do_GET

if __name__ == "__main__":
    print(f"test server on http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
