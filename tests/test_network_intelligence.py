import unittest

from modules.network.intelligence import extract_indicators, extract_links


class NetworkIntelligenceTests(unittest.TestCase):
    def test_ranks_sensitive_links(self):
        records = extract_links(
            '<a href="/about">about</a><a href="/admin/config?debug=1">x</a>',
            base_url="http://challenge.local/",
        )
        self.assertEqual(records[0]["url"], "http://challenge.local/admin/config?debug=1")
        self.assertGreaterEqual(records[0]["score"], 25)

    def test_extracts_flags_secrets_ips_and_base64(self):
        result = extract_indicators(
            'http://10.0.0.2:8080/internal/api?token=x '
            'Authorization: Bearer abcdef '
            'ctf{network_found} SGVsbG8=',
            source="fixture",
        )
        self.assertIn("ctf{network_found}", result["flags"])
        self.assertIn("10.0.0.2:8080", result["ips"])
        self.assertTrue(result["secrets"])
        self.assertEqual(result["decoded_blobs"][0]["decoded"], "Hello")


if __name__ == "__main__":
    unittest.main()
