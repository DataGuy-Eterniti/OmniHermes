"""Tests for Omnihermes tamper-evident audit logger."""

import json
import tempfile
import unittest
from pathlib import Path

from core.audit import AuditLogger


class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "test_audit.jsonl"
        self.logger = AuditLogger(log_path=self.log_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_log_and_chain_verification(self):
        # Log 3 events
        self.logger.log_event("TEST", "tool_1", "action_1", "APPROVED", 0.95, 0.90)
        self.logger.log_event("TEST", "tool_2", "action_2", "APPROVED", 0.92, 0.88)
        self.logger.log_event("TEST", "tool_3", "action_3", "REJECTED_SPOOF", 0.30, 0.20)

        # Verify integrity
        report = self.logger.verify_integrity()
        self.assertTrue(report["valid"])
        self.assertEqual(report["entries_checked"], 3)

    def test_detects_tampered_entry(self):
        self.logger.log_event("TEST", "tool_1", "action_1", "APPROVED", 0.95, 0.90)
        self.logger.log_event("TEST", "tool_2", "action_2", "APPROVED", 0.92, 0.88)

        # Mutate the second line in the log file
        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        record = json.loads(lines[1])
        record["action_summary"] = "HACKED_ACTION"
        lines[1] = json.dumps(record) + "\n"

        with open(self.log_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

        report = self.logger.verify_integrity()
        self.assertFalse(report["valid"])
        self.assertIn("Tampered record detected", report.get("error", ""))


if __name__ == "__main__":
    unittest.main()

