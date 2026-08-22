"""Small regression tests for JSON/labeled crypto attack dispatch."""
import base64
import json
import unittest

from modules.crypto import structured
from core.flag import extract_flags, infer_prefixes


class StructuredCryptoTests(unittest.TestCase):
    def test_generic_flag_formats(self):
        for prefix in ("picoCTF", "HTB", "THCTT", "customEvent"):
            known, candidates = extract_flags(f"answer={prefix}{{works_here}}")
            self.assertTrue(known or candidates, prefix)
        self.assertEqual(infer_prefixes("flag_format: picoCTF{...}"), ["picoCTF{"])
        self.assertEqual(infer_prefixes("prefix=customEvent"), ["customEvent{"])

    def test_autokey_matrix(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        key = "KEY"
        plain = "FLAGAUTOKEY"
        recovered = []
        for i, char in enumerate(plain):
            key_char = key[i] if i < len(key) else plain[i - len(key)]
            if char not in alphabet or key_char not in alphabet:
                raise AssertionError("test vector must stay inside the alphabet")
            recovered.append(alphabet[(alphabet.index(char) + alphabet.index(key_char)) % 26])
        obj = {"alphabet": alphabet, "initial_key": key,
               "ciphertext": "".join(recovered)}
        results = structured.analyze(json.dumps(obj))
        self.assertIn(("structured-autokey", plain), results)

    def test_rsa_common_modulus(self):
        n, message, e1, e2 = 3233, 42, 3, 5
        obj = {"n": n, "e1": e1, "e2": e2,
               "c1": pow(message, e1, n), "c2": pow(message, e2, n)}
        results = structured.analyze(json.dumps(obj))
        self.assertIn(("structured-rsa-common-modulus", b"*"), results)

    def test_lcg_stream(self):
        modulus, a, c = 2 ** 32, 1664525, 1013904223
        state = 7
        samples = []
        for _ in range(3):
            state = (a * state + c) % modulus
            samples.append(state)
        plain = b"AegisCTF{lcg}"
        encrypted = bytearray()
        for byte in plain:
            state = (a * state + c) % modulus
            encrypted.append(byte ^ (state & 0xff))
        obj = {"m": modulus, "sample_outputs": samples,
               "encrypted_flag_hex": bytes(encrypted).hex()}
        results = structured.analyze(json.dumps(obj))
        self.assertIn(("structured-lcg", plain), results)

    def test_stream_nonce_reuse_base64(self):
        known = b"known plaintext for keystream"
        target = b"AegisCTF{stream_nonce_reuse}"
        keystream = bytes(range(1, 80))
        obj = {
            "known_plaintext": base64.b64encode(known).decode(),
            "known_ciphertext": base64.b64encode(
                bytes(a ^ b for a, b in zip(known, keystream))).decode(),
            "target_ciphertext": base64.b64encode(
                bytes(a ^ b for a, b in zip(target, keystream))).decode(),
        }
        results = structured.analyze(json.dumps(obj))
        self.assertIn(("structured-stream-nonce-reuse", target), results)

    def test_mt19937_stream(self):
        from modules.crypto.modern import MT19937

        seed = 0x12345678
        source = MT19937(seed=seed)
        samples = [source.next_u32() for _ in range(624)]
        plain = b"AegisCTF{mt_clone}"
        encrypted = bytes(byte ^ (source.next_u32() & 0xff) for byte in plain)
        obj = {"mt_outputs": samples,
               "encrypted_flag_hex": encrypted.hex()}
        results = structured.analyze(json.dumps(obj))
        self.assertIn(("structured-mt19937-stream", plain), results)


if __name__ == "__main__":
    unittest.main()
