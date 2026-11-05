"""Tests for Omnihermes cryptographic security module."""

import unittest
from core.crypto import derive_key, encrypt_payload, decrypt_payload


class TestCrypto(unittest.TestCase):
    def test_key_derivation_deterministic(self):
        salt = b"test_salt_123456"
        key1 = derive_key(salt, "secret_pass")
        key2 = derive_key(salt, "secret_pass")
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)  # 256 bits

    def test_encrypt_decrypt_roundtrip(self):
        payload = {"owner_name": "Alice", "embedding": [0.123, -0.456, 0.789]}
        encrypted = encrypt_payload(payload, user_passphrase="passphrase123")

        self.assertIn("salt", encrypted)
        self.assertIn("nonce", encrypted)
        self.assertIn("ciphertext", encrypted)

        decrypted = decrypt_payload(encrypted, user_passphrase="passphrase123")
        self.assertEqual(decrypted["owner_name"], "Alice")
        self.assertAlmostEqual(decrypted["embedding"][0], 0.123)

    def test_tampered_ciphertext_fails(self):
        payload = {"secret": "sensitive_data"}
        encrypted = encrypt_payload(payload)

        # Mutate ciphertext string
        mutated = dict(encrypted)
        mutated["ciphertext"] = mutated["ciphertext"][:-2] + "AA"

        with self.assertRaises(Exception):
            decrypt_payload(mutated)


if __name__ == "__main__":
    unittest.main()

