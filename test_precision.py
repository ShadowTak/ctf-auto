"""Regression tests for evidence classification and stateful HTTP handling."""
import sys
import unittest
import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, ".")

from core import httpx
from core.capabilities import detect_capabilities
from core.evidence import EvidenceLedger
from modules.crypto.autodetect import analyze_text_evidence
from modules.web.login import _find_login_forms


class PrecisionTests(unittest.TestCase):
    def tearDown(self):
        httpx.reset_session()
        httpx.close_pool()

    def test_evidence_promotes_only_with_explicit_verification(self):
        ledger = EvidenceLedger()
        ledger.add_flag("customEvent{candidate}", source="decode",
                        verified=False, confidence=0.6)
        ledger.add_flag("customEvent{candidate}", source="oracle",
                        verified=True, confidence=0.95,
                        evidence=("response accepted",))

        item = ledger.all()[0]
        self.assertEqual(item.kind, "verified")
        self.assertIn("decode", item.sources)
        self.assertIn("oracle", item.sources)
        self.assertIn("response accepted", item.evidence)

    def test_crypto_evidence_keeps_exact_plaintext_and_status(self):
        plaintext = b"DUCTF{verified_xor_body}"
        ciphertext = base64.b64encode(plaintext).decode("ascii")

        _ranked, findings = analyze_text_evidence(ciphertext)

        match = next(item for item in findings
                     if item.value == "DUCTF{verified_xor_body}")
        self.assertEqual(match.kind, "verified")
        self.assertIn("crypto:", match.source)

    def test_http_cookie_jar_and_hidden_csrf_values(self):
        class CookieHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                if self.path == "/set":
                    self.send_response(200)
                    self.send_header("Set-Cookie", "flow=ok; Path=/")
                    self.end_headers()
                    return
                if self.path == "/token":
                    body = b'{"access_token":"token-value-1234567890"}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path == "/auth":
                    if self.headers.get("Authorization") == \
                            "Bearer token-value-1234567890":
                        self.send_response(200)
                    else:
                        self.send_response(401)
                    self.end_headers()
                    return
                if self.headers.get("Cookie") == "flow=ok":
                    self.send_response(200)
                else:
                    self.send_response(403)
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), CookieHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        self.assertEqual(httpx.get(base + "/set").status, 200)
        self.assertEqual(httpx.get(base + "/check").status, 200)
        self.assertEqual(httpx.get(base + "/token").status, 200)
        self.assertEqual(httpx.get(base + "/auth").status, 200)
        server.shutdown()
        server.server_close()

        httpx.configure(cookie="seed=one")
        httpx._store_set_cookie("session=abc123; Path=/")
        self.assertIn("seed=one", httpx.cookie_header())
        self.assertIn("session=abc123", httpx.cookie_header())

        html = ("<form action='/login' method='post'>"
                "<input type='hidden' name='csrf' value='token-123'>"
                "<input name='username' type='text'>"
                "<input name='password' type='password'>"
                "</form>")
        forms = _find_login_forms("http://target.local/", html)
        self.assertEqual(forms[0][1][0], ("csrf", "hidden", "token-123"))

    def test_capability_detection_is_safe(self):
        capabilities = detect_capabilities()
        names = {item.name for item in capabilities}
        self.assertIn("z3", names)
        self.assertIn("playwright", names)
        self.assertTrue(all(isinstance(item.available, bool)
                            for item in capabilities))


if __name__ == "__main__":
    unittest.main()
