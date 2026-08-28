import base64
import bz2
import gzip
import lzma
import unittest

from core import budget
from modules.crypto import encodings


class CompetitionCoreTests(unittest.TestCase):
    def test_compression_layers(self):
        payload = b"flag{compressed_layers}"
        for compressor, expected in (
            (gzip.compress, "compressed"),
            (bz2.compress, "compressed"),
            (lzma.compress, "compressed"),
        ):
            decoded = encodings.dec_compressed(compressor(payload))
            self.assertEqual(decoded, payload.decode("latin-1"), expected)

    def test_nested_base64_is_recovered(self):
        expected = "flag{nested_fast_path}"
        value = expected
        for _ in range(3):
            value = base64.b64encode(value.encode()).decode()
        # The public chain API must retain the final node even when multiple
        # syntactically-valid decoders compete for beam space.
        results = encodings.chain_decode_best(
            value, max_depth=8, max_branches=12, max_nodes=2000, timeout=8)
        self.assertIn(expected, [output for _, output in results])

    def test_budget_limits_requests_and_nodes(self):
        budget.configure(requests=2, nodes=1)
        try:
            self.assertTrue(budget.take_request())
            self.assertTrue(budget.take_request())
            self.assertFalse(budget.take_request())
            self.assertTrue(budget.take_node())
            self.assertFalse(budget.take_node())
        finally:
            budget.clear()


if __name__ == "__main__":
    unittest.main()
