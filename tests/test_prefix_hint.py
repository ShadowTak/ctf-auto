import unittest

from core.flag import normalize_prefix
from modules.crypto.autodetect import analyze_text_evidence


class PrefixHintTests(unittest.TestCase):
    def test_prefix_forms(self):
        self.assertEqual(normalize_prefix("ctf"), "ctf{")
        self.assertEqual(normalize_prefix("ctf{"), "ctf{")
        self.assertEqual(normalize_prefix("ctf{anything}"), "ctf{")
        self.assertEqual(normalize_prefix(""), "")

    def test_prefix_hint_is_optional(self):
        ranked, findings = analyze_text_evidence("ciphertext", prefix_hint="ctf")
        self.assertIsInstance(ranked, list)
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
