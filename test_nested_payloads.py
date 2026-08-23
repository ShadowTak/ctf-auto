"""Regression tests for recursive JSON payload decoding and trace output."""
import base64
import json
import unittest

from modules.crypto.autodetect import (analyze_text, analyze_text_evidence,
                                       explain_decode)


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

    def test_explanation_replays_intermediate_values(self):
        flag = "THCTT{explain_every_step}"
        inner = base64.b64encode(flag.encode()).decode()
        nested = base64.b64encode(inner.encode()).decode()
        artifact = json.dumps({"token": nested})

        explanation = explain_decode(
            "json[$.token] -> chain-best(base64>base64)", flag, artifact)

        self.assertEqual(explanation["scope"], "JSON path $.token")
        self.assertEqual(explanation["trace"], ["base64", "base64"])
        self.assertEqual(explanation["steps"][-1]["output"], flag)
        self.assertIn(inner, explanation["steps"][0]["output"])


if __name__ == "__main__":
    unittest.main()
