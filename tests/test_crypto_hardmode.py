import os
import tempfile
import unittest

from modules.crypto.correlation import correlate
from modules.crypto.hardmode import choose_backends


class CryptoHardModeTests(unittest.TestCase):
    def test_cross_file_repeated_modulus(self):
        with tempfile.TemporaryDirectory() as directory:
            value = "n=123456789012345678901234567890123456789"
            for name in ("a.txt", "b.txt"):
                with open(os.path.join(directory, name), "w") as handle:
                    handle.write(value)
            report = correlate(directory)
            self.assertTrue(any(item["kind"] == "n" for item in report["repeated"]))
            self.assertIn("stdlib", choose_backends())


if __name__ == "__main__":
    unittest.main()
