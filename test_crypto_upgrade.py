"""Vectors for the generic math, modern symmetric, signature, and KDF paths."""
import base64
import hashlib
import json
import unittest

from modules.crypto import aead, dh, kdf, lattice, signatures, structured
from modules.crypto.rsa import franklin_reiter


class CryptoUpgradeTests(unittest.TestCase):
    def test_modular_math_and_dh(self):
        p, g, private = 467, 2, 37
        public = pow(g, private, p)
        self.assertEqual(dh.discrete_log(g, public, p, order=p - 1), private)
        self.assertEqual(dh.tonelli_shanks(4, p) ** 2 % p, 4)
        self.assertEqual(dh.crt([(2, 3), (3, 5)]), (8, 15))

    def test_franklin_reiter(self):
        n, e, message, delta = 101 * 113, 3, 42, 7
        c1, c2 = pow(message, e, n), pow(message + delta, e, n)
        self.assertEqual(franklin_reiter(c1, c2, n, e, delta), message)
        modulus = 1_000_000_007 * 1_000_000_009
        self.assertIn(42, lattice.coppersmith_univariate(
            [-(42 * 42), 0, 1], modulus, 100))

    def test_ecdsa_reused_nonce_and_der(self):
        n, r, k, private = 101, 3, 17, 29
        z1, z2 = 11, 22
        s1 = (pow(k, -1, n) * (z1 + r * private)) % n
        s2 = (pow(k, -1, n) * (z2 + r * private)) % n
        self.assertEqual(signatures.recover_reused_nonce(
            n, r, s1, z1, s2, z2), (private, k))
        self.assertEqual(signatures.decode_dss_signature(
            bytes.fromhex("3006020101020102")), (1, 2))

    def test_aes_gcm_and_nonce_reuse(self):
        from Crypto.Cipher import AES
        key, nonce = b"0123456789abcdef", b"123456789012"
        plain = b"redactedCTF{gcm_ok}"
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plain)
        self.assertEqual(aead.decrypt_aes("GCM", key, ciphertext,
                                          nonce=nonce, tag=tag), plain)
        known = b"known plaintext"
        target = b"redactedCTF{reuse}"
        stream = bytes(range(1, 80))
        recovered = aead.recover_stream_nonce_reuse(
            known, bytes(x ^ y for x, y in zip(known, stream)),
            bytes(x ^ y for x, y in zip(target, stream)))
        self.assertEqual(recovered, target)
        records = []
        for message in (b"hello 1234567890", b"world 1234567890"):
            instance = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = instance.encrypt_and_digest(message)
            records.append({"nonce": nonce, "ciphertext": ciphertext,
                            "tag": tag, "aad": b""})
        self.assertTrue(aead.recover_gcm_subkey_one_block(
            records[0], records[1]))
        self.assertTrue(any(label == "aead-gcm-nonce-reuse" for label, _ in
                            aead.gcm_nonce_reuse_analysis(records)))

    def test_structured_dh_and_aead(self):
        p, g, a, b = 467, 2, 37, 71
        A, B = pow(g, a, p), pow(g, b, p)
        shared = pow(B, a, p)
        key = hashlib.sha256(str(shared).encode()).digest()
        plain = b"redactedCTF{dh_structured}"
        encrypted = bytes(x ^ key[i % len(key)] for i, x in enumerate(plain))
        dh_obj = {"p": p, "g": g, "A": A, "B": B,
                  "ciphertext": encrypted.hex()}
        dh_results = structured.analyze(json.dumps(dh_obj))
        self.assertIn(("structured-dh-xor[sha256(shared-int)]", plain), dh_results)

        aead_obj = {"algorithm": "AES-GCM", "key": key.hex(),
                    "nonce": "123456789012", "ciphertext": "00", "tag": "00"}
        # Invalid tag is intentionally rejected, not surfaced as plaintext.
        self.assertFalse(any(label.startswith("structured-aes")
                             for label, _ in structured.analyze(json.dumps(aead_obj))))

    def test_pbkdf2_kdf(self):
        digest = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1000)
        encoded = base64.b64encode(digest).decode().rstrip("=")
        value = f"pbkdf2_sha256$1000$salt${encoded}"
        self.assertEqual(kdf.identify_kdf(value), "PBKDF2-HMAC-SHA256 (Django)")
        self.assertEqual(kdf.crack_kdf(value, ["wrong", "password"]), "password")


if __name__ == "__main__":
    unittest.main()
