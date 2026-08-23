"""Regression for cookies learned from redirect responses."""
import unittest
from unittest.mock import patch

from core import httpx
from modules.web.scanner import _cookie_headers, run_web


class _Response:
    headers = {}


class CookieHeaderTests(unittest.TestCase):
    def tearDown(self):
        httpx.reset_session()

    def test_falls_back_to_http_session_cookie_jar(self):
        httpx.configure(cookie="session=eyJyb2xlIjoiZ3Vlc3QifQ==")
        self.assertEqual(_cookie_headers(_Response()),
                         ["session=eyJyb2xlIjoiZ3Vlc3QifQ=="])

    @patch("modules.web.scanner.httpx.get", return_value=None)
    @patch("modules.web.scanner.httpx.reset_session")
    def test_scan_resets_auth_state_by_default(self, reset, _get):
        run_web("http://target.local")
        reset.assert_called_once_with()

    @patch("modules.web.scanner.httpx.get", return_value=None)
    @patch("modules.web.scanner.httpx.reset_session")
    def test_scan_can_keep_intentional_auth_state(self, reset, _get):
        run_web("http://target.local", reset_session=False)
        reset.assert_not_called()


if __name__ == "__main__":
    unittest.main()
