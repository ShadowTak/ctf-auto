"""Regression for RSA attacks that should stop after a verified fast hit."""
import unittest
from unittest.mock import patch

from modules.crypto.rsa import crack_rsa


class RSAFastPathTests(unittest.TestCase):
    @patch("modules.crypto.factoring.factor_n", side_effect=AssertionError(
        "generic factoring must not run after exact small-e recovery"))
    def test_small_e_returns_without_factoring(self, factor_n):
        n = 1_000_000_007 * 1_000_000_009
        message = 42
        found = crack_rsa(n=n, e=3, c=message ** 3)
        self.assertEqual(found, [("small e", b"*")])
        factor_n.assert_not_called()


if __name__ == "__main__":
    unittest.main()
