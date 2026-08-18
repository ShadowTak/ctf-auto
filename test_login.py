"""Test login brute-force against a THCTT-style login (default username NCSA,
4-digit pin 7331). Run: python3 test_login.py"""
import sys, os, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse

FLAG = "TCTT{pin_login_ok}"
USER = "NCSA"
PIN = "7331"

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = ("<html><body><h1>Login</h1>"
                "<form method='POST' action='/login'>"
                "<input name='username' type='text'>"
                "<input name='password' type='password'>"
                "</form><p>Hint: 4 digit pin</p></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = urllib.parse.parse_qs(self.rfile.read(length).decode())
        u = (data.get("username") or [""])[0]
        p = (data.get("password") or [""])[0]
        if u == USER and p == PIN:
            body = f"<h1>Welcome {u}</h1><p>{FLAG}</p>"
            self.send_response(200)
        else:
            body = "<h1>Invalid username or password</h1>"
            self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

from modules.web import login as login_mod

base = f"http://127.0.0.1:{port}"
page = __import__("core.httpx", fromlist=["get"]).get(base + "/")
findings, flags = login_mod.run_login_brute(base, page.text, full_pin=True)
for f in findings:
    print(f)
ok = FLAG in flags
print("PASS login-pin" if ok else "FAIL login-pin", "| flags:", flags)
srv.shutdown()
sys.exit(0 if ok else 1)
