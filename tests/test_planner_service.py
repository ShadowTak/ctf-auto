import unittest

from core.planner import artifact_kind, plan
from modules.service.runner import parse_target


class PlannerServiceTests(unittest.TestCase):
    def test_service_target(self):
        self.assertEqual(parse_target("[::1]:31337"), ("::1", 31337))

    def test_text_plan(self):
        result = plan("base64 payload")
        self.assertEqual(result["kind"], "text")
        self.assertIn("encoding-chain", result["pipelines"])

    def test_missing_file_is_text_input(self):
        self.assertEqual(artifact_kind("does-not-exist"), "text")


if __name__ == "__main__":
    unittest.main()
