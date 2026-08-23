"""Regression tests for recursive JSON payload decoding and trace output."""
import base64
import json
import unittest

from modules.crypto.autodetect import analyze_text, analyze_text_evidence


class NestedPayloadTests(unittest.TestCase):
    def test_encoded_leaf_runs_full_chain_and_keeps_json_path(self):
        flag = "THCTT{json_nested_solver}"
        inner = base64.b64encode(flag.encode()).decode()
        nested = base64.b64encode(inner.encode()).decode()
        artifact = json.dumps({"response": {"token": nested}})

        ranked, flags = analyze_text(artifact)

        self.assertIn(flag, flags)
        self.assertTrue(any("json[$.response.token]" in label
                            and "base64" in label
                            for _, label, _ in ranked))

        _, findings = analyze_text_evidence(artifact)
        matching = [item for item in findings if item.value == flag]
        self.assertTrue(matching)
        self.assertTrue(any("json[$.response.token]" in evidence
                            for evidence in matching[0].evidence))


if __name__ == "__main__":
    unittest.main()
