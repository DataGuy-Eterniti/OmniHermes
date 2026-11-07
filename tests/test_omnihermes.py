"""Unit tests for the real OmniHermes engine."""

import tempfile
import unittest
from pathlib import Path

import numpy as np

import omnihermes
from omnihermes.audit import AuditLogger
from omnihermes.biometrics import BiometricEngine, DEFAULT_COSINE_THRESHOLD
from omnihermes.crypto import encrypt_payload, decrypt_payload, get_or_generate_key
from omnihermes.liveness import calculate_ear, euclidean_dist


class DummyLandmark:
    def __init__(self, x: float, y: float):
        self.x = x
        self.y = y


class TestOmniHermesEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_crypto_roundtrip(self):
        secret_key = get_or_generate_key(data_dir=self.data_dir)
        self.assertEqual(len(secret_key), 32)

        data = {"owner_name": "Elijah", "role": "PRIMARY_OWNER", "embedding": [0.1] * 128}
        enc = encrypt_payload(data, data_dir=self.data_dir)
        self.assertIn("ciphertext", enc)
        self.assertIn("nonce", enc)

        dec = decrypt_payload(enc, data_dir=self.data_dir)
        self.assertEqual(dec["owner_name"], "Elijah")
        self.assertEqual(dec["role"], "PRIMARY_OWNER")
        self.assertEqual(len(dec["embedding"]), 128)

    def test_audit_hash_chain(self):
        logger = AuditLogger(data_dir=self.data_dir)
        self.assertTrue(logger.verify_integrity()["valid"])

        logger.log_event("ENROLL", "Elijah", "Enrollment", "SUCCESS", 1.0, 0.95)
        logger.log_event("VERIFY", "Elijah", "Verification", "APPROVED", 0.85, 0.90)

        report = logger.verify_integrity()
        self.assertTrue(report["valid"])
        self.assertEqual(report["count"], 2)

        # Tamper test
        with open(logger.log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        tampered_line = lines[0].replace("Elijah", "Attacker")
        with open(logger.log_path, "w", encoding="utf-8") as f:
            f.write(tampered_line + lines[1])

        tamper_report = logger.verify_integrity()
        self.assertFalse(tamper_report["valid"])

    def test_biometrics_sface_matching(self):
        engine = BiometricEngine(data_dir=self.data_dir)
        self.assertFalse(engine.is_enrolled())

        # Create normalized 128-d vector
        emb1 = np.random.randn(1, 128).astype(np.float32)
        emb1 /= np.linalg.norm(emb1)

        engine.save_profile("Elijah", emb1, is_primary=True)
        self.assertTrue(engine.is_enrolled())

        owner = engine.get_owner_info()
        self.assertEqual(owner["owner_name"], "Elijah")
        self.assertEqual(owner["role"], "PRIMARY_OWNER")

        # Test identical match
        passed, score = engine.match_against_owner(emb1)
        self.assertTrue(passed)
        self.assertGreater(score, 0.95)

        # Test opposite / orthogonal vector
        diff_emb = -emb1.copy()
        passed_diff, score_diff = engine.match_against_owner(diff_emb)
        self.assertFalse(passed_diff)
        self.assertLess(score_diff, DEFAULT_COSINE_THRESHOLD)

    def test_ear_calculation(self):
        # Open eye coordinates
        open_eye = [
            DummyLandmark(0.1, 0.5),  # 0: outer
            DummyLandmark(0.3, 0.4),  # 1: top-left
            DummyLandmark(0.7, 0.4),  # 2: top-right
            DummyLandmark(0.9, 0.5),  # 3: inner
            DummyLandmark(0.7, 0.6),  # 4: bottom-right
            DummyLandmark(0.3, 0.6),  # 5: bottom-left
        ]
        ear_open = calculate_ear(open_eye, [0, 1, 2, 3, 4, 5], 100, 100)
        self.assertGreater(ear_open, 0.20)

        # Closed eye coordinates (top and bottom points close together)
        closed_eye = [
            DummyLandmark(0.1, 0.50),
            DummyLandmark(0.3, 0.49),
            DummyLandmark(0.7, 0.49),
            DummyLandmark(0.9, 0.50),
            DummyLandmark(0.7, 0.51),
            DummyLandmark(0.3, 0.51),
        ]
        ear_closed = calculate_ear(closed_eye, [0, 1, 2, 3, 4, 5], 100, 100)
        self.assertLess(ear_closed, 0.10)


if __name__ == "__main__":
    unittest.main()

