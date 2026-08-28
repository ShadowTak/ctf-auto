import base64
import gzip
import io
import json
import unittest
import zipfile

from modules.crypto.artifacts import extract
from modules.crypto.planner import plan


class CryptoArtifactTests(unittest.TestCase):
    def test_recursive_zip_and_gzip(self):
        inner = gzip.compress(b"flag{inside_nested_artifact}")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("payload.bin", inner)
        entries = extract(buffer.getvalue())
        values = [value for _, value in entries]
        self.assertIn(b"flag{inside_nested_artifact}", values)

    def test_crypto_plan_finds_rsa_and_kdf(self):
        result = plan(json.dumps({"n": 123, "e": 3, "c": 5,
                                  "kdf": "pbkdf2_sha256"}))
        self.assertIn("rsa-attacks", result["jobs"])
        self.assertIn("kdf-wordlist", result["jobs"])


if __name__ == "__main__":
    unittest.main()
