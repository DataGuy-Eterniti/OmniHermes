"""Tests for Omnihermes policy engine."""

import tempfile
import unittest
from pathlib import Path

from core.policy import PolicyEngine


class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cfg_file = Path(self.temp_dir.name) / "test_config.json"
        self.engine = PolicyEngine(config_path=self.cfg_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_benign_tool_not_guarded(self):
        assessment = self.engine.assess_risk("calculator", {"expr": "2 + 2"})
        self.assertFalse(assessment["requires_biometric"])
        self.assertEqual(assessment["risk_level"], "LOW")

    def test_guarded_tool_intercepted(self):
        assessment = self.engine.assess_risk("make_payment", {"amount": 50, "currency": "USD"})
        self.assertTrue(assessment["requires_biometric"])
        self.assertIn("Tool 'make_payment' is in guarded tools policy", assessment["reasons"])

    def test_dangerous_pattern_in_arguments(self):
        assessment = self.engine.assess_risk("random_helper", {"cmd": "rm -rf /tmp/test"})
        self.assertTrue(assessment["requires_biometric"])
        self.assertEqual(assessment["risk_level"], "HIGH")

    def test_update_config(self):
        self.engine.update_config({"mode": "cached_presence", "away_timeout_seconds": 60})
        self.assertEqual(self.engine.config["mode"], "cached_presence")
        self.assertEqual(self.engine.config["away_timeout_seconds"], 60)


if __name__ == "__main__":
    unittest.main()
