import hashlib
import unittest

from modules.crypto.extra import digest_matches, rsa_broadcast


class CryptoExtraTests(unittest.TestCase):
    def test_digest_matches_md5(self):
        digest = hashlib.md5(b"competition").hexdigest()
        self.assertEqual(digest_matches("competition", digest), "openssl_md5")

    def test_rsa_broadcast(self):
        message = 42
        exponent = 3
        moduli = [(101 * 113, exponent, pow(message, exponent, 101 * 113)),
                  (107 * 127, exponent, pow(message, exponent, 107 * 127)),
                  (109 * 131, exponent, pow(message, exponent, 109 * 131))]
        self.assertEqual(rsa_broadcast(moduli), message)


if __name__ == "__main__":
    unittest.main()
