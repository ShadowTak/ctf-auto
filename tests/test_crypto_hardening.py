import os
import tempfile
import unittest

from modules.crypto.correlation import correlate
from modules.crypto.verification import (
    crt_recombine, digest_matches, rsa_factorization, rsa_roundtrip,
    xor_roundtrip,
)


class CryptoHardeningTests(unittest.TestCase):
    def test_verification_helpers(self):
        self.assertTrue(rsa_roundtrip(42, 3, 7, 55))
        self.assertTrue(rsa_factorization(55, 5, 11)["verified"])
        self.assertEqual(crt_recombine([2, 3], [3, 5]), 8)
        self.assertTrue(xor_roundtrip(b"abc", b"K", bytes([42, 41, 40])))
        self.assertTrue(digest_matches(b"abc", "900150983cd24fb0d6963f7d28e17f72", "md5"))

    def test_recursive_correlation_and_shared_prime(self):
        with tempfile.TemporaryDirectory() as directory:
            nested = os.path.join(directory, "nested")
            os.mkdir(nested)
            p, q, r = 101, 113, 127
            with open(os.path.join(directory, "one.txt"), "w") as handle:
                handle.write(f"n={p*q}\nnonce=12345678901234567890\n")
            with open(os.path.join(nested, "two.txt"), "w") as handle:
                handle.write(f"n={p*r}\nnonce=12345678901234567890\n")
            report = correlate(directory)
            self.assertTrue(report["shared_factors"])
            self.assertIn("shared RSA prime candidate", report["hints"])
            self.assertTrue(any(x["kind"] == "nonce" for x in report["repeated"]))


if __name__ == "__main__":
    unittest.main()
