import unittest

from modules.crypto.planner import plan
from modules.web.parameter_inventory import inventory, summarize


class ReleaseSchemaTests(unittest.TestCase):
    def test_web_summary_is_bounded_and_json_safe(self):
        result = inventory('<form><input name="token"></form>', 'text/html', 'http://x/')
        summary = summarize(result)
        self.assertEqual(summary["forms"], 1)
        self.assertIn("token", summary["field_names"])
        self.assertEqual(summary["kind"], "html")

    def test_crypto_plan_keeps_legacy_keys(self):
        result = plan("n=123456789 e=3 c=5")
        self.assertIn("jobs", result)
        self.assertIn("reasons", result)
        self.assertIn("costs", result)
        self.assertIn("source_fingerprint", result)


if __name__ == "__main__":
    unittest.main()
