"""Regression tests for format-safe raw flag output."""
import sys
import unittest
import base64

sys.path.insert(0, ".")

from core.flag import extract_flags
from modules.crypto.autodetect import _filter_flag_families, analyze_text
from modules.crypto.xor import crib_attack


class RawFlagOutputTests(unittest.TestCase):
    def test_xor_crib_returns_literal_plaintext_unchanged(self):
        plaintext = b"DUCTF{real_xor_flag_123}"
        key = b"KEY"
        ciphertext = bytes(
            value ^ key[index % len(key)]
            for index, value in enumerate(plaintext)
        )

        result = crib_attack(ciphertext, [b"DUCTF{"])

        self.assertEqual(result[0][1], "DUCTF{real_xor_flag_123}")

    def test_analyze_text_preserves_raw_crib_plaintext(self):
        plaintext = b"DUCTF{real_xor_flag_123}"
        key = b"KEY"
        ciphertext = bytes(
            value ^ key[index % len(key)]
            for index, value in enumerate(plaintext)
        )

        ranked, flags = analyze_text(
            base64.b64encode(b"DUCTF{real_xor_flag_123}").decode("ascii"))

        self.assertIn("DUCTF{real_xor_flag_123}", flags)
        self.assertTrue(any(text == "DUCTF{real_xor_flag_123}"
                            for _score, label, text in ranked
                            if label.startswith("base64")))

    def test_same_body_under_many_prefixes_is_discarded(self):
        values = [
            "ductf{same_body}",
            "sdctf{same_body}",
            "thctt{same_body}",
        ]
        self.assertEqual(_filter_flag_families(values), [])

    def test_plaintext_flag_format_is_still_preserved(self):
        known, candidates = extract_flags("answer=customEvent{kept_as_is}")
        self.assertEqual(known, [])
        self.assertEqual(candidates, ["customEvent{kept_as_is}"])


if __name__ == "__main__":
    unittest.main()
