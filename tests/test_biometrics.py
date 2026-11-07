"""Tests for Omnihermes biometrics engine."""

import os
import tempfile
import unittest
from pathlib import Path

import numpy as np
from core.biometrics import BiometricEngine


class TestBiometrics(unittest.TestCase):
    def setUp(self):
        os.environ["OMNIHERMES_TEST_MODE"] = "1"
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["HERMES_PLUGIN_DATA_DIR"] = self.temp_dir.name
        self.engine = BiometricEngine(data_dir=Path(self.temp_dir.name))

    def tearDown(self):
        os.environ.pop("HERMES_PLUGIN_DATA_DIR", None)
        self.temp_dir.cleanup()

    def test_enrollment_and_matching(self):
        self.assertFalse(self.engine.is_enrolled())

        # Generate fake 128-d face embedding
        ref_vec = np.ones(128, dtype=np.float32)
        res = self.engine.enroll_owner("Alice", ref_vec)
        self.assertEqual(res["status"], "success")
        self.assertTrue(self.engine.is_enrolled())

        # Verify same face
        same_vec = np.ones(128, dtype=np.float32)
        ver_res = self.engine.verify(same_vec, liveness_score=0.90)
        self.assertTrue(ver_res["verified"])
        self.assertAlmostEqual(ver_res["confidence"], 1.0, places=2)

        # Verify completely different face
        diff_vec = -np.ones(128, dtype=np.float32)
        diff_res = self.engine.verify(diff_vec, liveness_score=0.90)
        self.assertFalse(diff_res["verified"])
        self.assertEqual(diff_res["reason"], "FACE_MISMATCH")

    def test_spoof_detection(self):
        # Static image spoof (motion variance = 0.0)
        score, passed, status = BiometricEngine.calculate_liveness(
            frames_ear=[0.28, 0.28],
            motion_variance=0.002,
            texture_entropy=2.1,
        )
        self.assertFalse(passed)
        self.assertEqual(status, "REJECTED_SPOOF_STATIC")

        # Live human (blink + natural micro-motion)
        score_live, passed_live, status_live = BiometricEngine.calculate_liveness(
            frames_ear=[0.28, 0.28, 0.15, 0.28],  # dip in EAR = blink
            motion_variance=0.08,
            texture_entropy=4.5,
        )
        self.assertTrue(passed_live)
        self.assertEqual(status_live, "PASSED")


if __name__ == "__main__":
    unittest.main()

