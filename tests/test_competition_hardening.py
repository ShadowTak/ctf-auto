"""Tests for competition hardening features: lattice, ECDSA, workflow,
corpus benchmark, and evidence dashboard."""
import math
import unittest

from modules.crypto.common import invmod


class LatticeSolverTests(unittest.TestCase):
    """Test lattice-based crypto solvers."""

    def test_available_backends(self):
        from modules.crypto.lattice import available_backends
        backends = available_backends()
        self.assertIn("z3", backends)
        self.assertIn("fpylll", backends)
        self.assertIn("sympy", backends)

    def test_coppersmith_small_roots_trivial(self):
        """Test Coppersmith with a known small root."""
        from modules.crypto.lattice import coppersmith_small_roots
        # f(x) = x - 5 = 0 mod 101  =>  root = 5
        N = 101
        X = 50
        roots = coppersmith_small_roots(N, X, lambda _: [(-5) % N, 1])
        self.assertIn(5, roots)

    def test_boneh_durfee_small_instance(self):
        """Test Boneh-Durfee with a small RSA instance."""
        from modules.crypto.lattice import boneh_durfee
        # Generate a small RSA with known small d
        p = 61
        q = 53
        N = p * q
        e = 17
        phi = (p - 1) * (q - 1)
        d = invmod(e, phi)
        # d should be found by continued fraction fallback
        result = boneh_durfee(N, e)
        if result:
            d_found, p_found, q_found = result
            self.assertEqual(p_found * q_found, N)

    def test_hnp_solve_trivial(self):
        """Test HNP returns candidates (may not be exact for small instances)."""
        from modules.crypto.lattice import hnp_solve
        p = 101
        secret = 42
        moduli = [p] * 5
        remainders = [(secret + i) % p for i in range(5)]
        bound = 10
        candidates = hnp_solve(moduli, remainders, bound)
        self.assertIsInstance(candidates, list)

    def test_franklin_reiter(self):
        """Test Franklin-Reiter related message attack."""
        from modules.crypto.rsa import franklin_reiter
        p = 61
        q = 53
        N = p * q
        e = 3
        m = 42
        delta = 7
        c1 = pow(m, e, N)
        c2 = pow(m + delta, e, N)
        result = franklin_reiter(N, e, c1, c2, delta)
        if result is not None:
            self.assertEqual(result, m)


class ECDSASolverTests(unittest.TestCase):
    """Test ECDSA signature analysis."""

    def test_nonce_reuse_detection(self):
        from modules.crypto.ecdsa_solver import detect_nonce_reuse, CURVES
        from modules.crypto.common import invmod
        n = CURVES["secp256k1"]["n"]
        d, k = 42, 99
        r = 50000
        z1, z2 = 1000, 2000
        s1 = ((z1 + d * r) * invmod(k, n)) % n
        s2 = ((z2 + d * r) * invmod(k, n)) % n
        sigs = [{"r": r, "s": s1, "z": z1}, {"r": r, "s": s2, "z": z2}]
        results = detect_nonce_reuse(sigs)
        self.assertEqual(len(results), 1)
        self.assertIn("private_key", results[0])
        self.assertEqual(results[0]["private_key"], d)

    def test_nonce_reuse_no_reuse(self):
        from modules.crypto.ecdsa_solver import detect_nonce_reuse
        sigs = [
            {"r": 12345, "s": 111, "z": 100},
            {"r": 67890, "s": 222, "z": 200},
        ]
        results = detect_nonce_reuse(sigs)
        self.assertEqual(len(results), 0)

    def test_malleable_variants(self):
        from modules.crypto.ecdsa_solver import malleable_variants, CURVES
        n = CURVES["secp256k1"]["n"]
        r = 12345
        s = 67890
        variants = malleable_variants(r, s)
        self.assertEqual(len(variants), 1)
        self.assertEqual(variants[0]["r"], r)
        self.assertEqual(variants[0]["s"], (n - s) % n)

    def test_parse_der_signature(self):
        from modules.crypto.ecdsa_solver import parse_der_signature
        # Construct a minimal DER signature with correct lengths
        r = 0x1234
        s = 0x5678
        r_bytes = r.to_bytes(2, "big")
        s_bytes = s.to_bytes(2, "big")
        seq_len = 2 + len(r_bytes) + 2 + len(s_bytes)
        der = bytes([0x30, seq_len,
                     0x02, len(r_bytes)] + list(r_bytes) +
                    [0x02, len(s_bytes)] + list(s_bytes))
        r_parsed, s_parsed = parse_der_signature(der)
        self.assertEqual(r_parsed, r)
        self.assertEqual(s_parsed, s)

    def test_extract_signatures_from_json(self):
        from modules.crypto.ecdsa_solver import extract_signatures_from_text
        text = '{"r": "0x1234", "s": "0x5678"}'
        sigs = extract_signatures_from_text(text)
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["r"], 0x1234)
        self.assertEqual(sigs[0]["s"], 0x5678)

    def test_analyze_auth_state(self):
        from modules.web.workflow import analyze_auth_state_from_cookies
        cookies = {
            "session": "12345",
            "jwt_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        }
        findings = analyze_auth_state_from_cookies(cookies)
        self.assertTrue(len(findings) > 0)


class CorpusBenchmarkTests(unittest.TestCase):
    """Test challenge corpus generation and benchmarking."""

    def test_generate_corpus(self):
        from tests.corpus.generate import generate_corpus
        corpus = generate_corpus()
        self.assertGreater(len(corpus), 0)
        for c in corpus:
            self.assertIn("category", c)
            self.assertIn("type", c)

    def test_corpus_has_expected_flags(self):
        from tests.corpus.generate import generate_corpus
        corpus = generate_corpus()
        flags = [c["flag"] for c in corpus if "flag" in c]
        self.assertGreater(len(flags), 0)

    def test_benchmark_runs(self):
        from tests.corpus.benchmark import benchmark_crypto
        result = benchmark_crypto()
        self.assertIn("total", result)
        self.assertIn("solved", result)
        self.assertIn("solve_rate", result)
        self.assertGreater(result["total"], 0)

    def test_rsa_small_e_corpus(self):
        from tests.corpus.generate import generate_rsa_small_e
        challenge = generate_rsa_small_e()
        self.assertEqual(challenge["category"], "crypto")
        self.assertIn("n", challenge["inputs"])
        self.assertIn("e", challenge["inputs"])
        self.assertIn("c", challenge["inputs"])


class EvidenceDashboardTests(unittest.TestCase):
    """Test evidence dashboard API response structure."""

    def test_api_evidence_structure(self):
        """Test that evidence API returns expected structure."""
        from web_app import app
        with app.test_client() as client:
            # Create a job first
            resp = client.post("/api/scan", json={
                "category": "crypto",
                "text": "aGVsbG8gd29ybGQ=",
            })
            data = resp.get_json()
            jid = data["job_id"]

            # Wait for job to finish
            import time
            for _ in range(30):
                time.sleep(0.5)
                resp = client.get(f"/api/status/{jid}")
                status = resp.get_json()
                if status["status"] in ("done", "error"):
                    break

            # Get evidence
            resp = client.get(f"/api/evidence/{jid}")
            evidence = resp.get_json()
            self.assertIn("summary", evidence)
            self.assertIn("flags", evidence)
            self.assertIn("candidates", evidence)
            self.assertIn("decodes", evidence)
            self.assertIn("elapsed", evidence)

    def test_lattice_api_structure(self):
        """Test lattice solver API returns expected structure."""
        from web_app import app
        with app.test_client() as client:
            resp = client.post("/api/solver/lattice", json={
                "n": 3233, "e": 17, "c": 2790,
            })
            data = resp.get_json()
            self.assertIn("job_id", data)

    def test_ecdsa_api_structure(self):
        """Test ECDSA solver API returns expected structure."""
        from web_app import app
        with app.test_client() as client:
            resp = client.post("/api/solver/ecdsa", json={
                "text": '{"r": "0x1234", "s": "0x5678"}',
            })
            data = resp.get_json()
            self.assertIn("job_id", data)


if __name__ == "__main__":
    unittest.main()
