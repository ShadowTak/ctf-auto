import unittest

from modules.crypto.planner import plan
from modules.crypto.source_fingerprint import fingerprint


class HardeningRoundTwoTests(unittest.TestCase):
    def test_source_fingerprint_is_static(self):
        result = fingerprint("n = 123456789\n# LLL Coppersmith nonce")
        self.assertTrue(result["safe"])
        self.assertIn("rsa", result["families"])
        self.assertIn("lattice", result["families"])

    def test_planner_exposes_costs(self):
        result = plan("RSA modulus n=123456789 and Coppersmith LLL")
        self.assertIn("costs", result)
        self.assertIn("source_fingerprint", result)
        self.assertIn("lattice-backend", result["jobs"])
        self.assertEqual(result["costs"]["encoding-chain"], "cheap")


if __name__ == "__main__":
    unittest.main()
