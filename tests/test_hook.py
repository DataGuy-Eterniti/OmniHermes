"""Tests for pre_tool_call lifecycle interceptor in OmniHermes.

Tests fail-closed behavior across critical error scenarios:
- Blocks on exception in policy or hook
- Blocks on dialog timeout
- Blocks on camera failure
- Blocks under cron execution
- Blocks with no display / headless
- Blocks for an unenrolled user
- Proves no code path allows risky commands without verification or active unlock window
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import __init__ as omnihermes_gate
import omnihermes.tools as tools
from core.audit import AuditLogger
from omnihermes.tools import get_biometrics, get_policy, get_presence, handle_omnihermes_enroll


class TestHookInterceptor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_audit_file = Path(self.temp_dir.name) / "test_audit.jsonl"
        self.temp_debug_log = Path(self.temp_dir.name) / "test_debug.log"
        self.mock_audit = AuditLogger(log_path=self.temp_audit_file)
        
        self.audit_patcher = patch.object(tools, "_audit", self.mock_audit)
        self.audit_patcher.start()
        self.debug_patcher = patch.object(omnihermes_gate, "DEBUG_LOG_PATH", self.temp_debug_log)
        self.debug_patcher.start()

        get_policy().update_config({"enabled": True, "mode": "strict"})
        get_presence().mark_seen("Elijah")

    def tearDown(self):
        self.audit_patcher.stop()
        self.debug_patcher.stop()
        self.temp_dir.cleanup()

    def test_benign_tool_allowed_instantly(self):
        """Live Test: Benign read operation should pass without biometric check."""
        result = omnihermes_gate.on_pre_tool_call(
            tool_name="read_file",
            arguments={"path": "README.md"},
        )
        self.assertEqual(result.get("action"), "allow")

    def test_omnihermes_self_tools_never_blocked(self):
        """Live Test: OmniHermes management tools should never be blocked."""
        for tool in ["omnihermes_status", "omnihermes_enroll", "presence_status"]:
            result = omnihermes_gate.on_pre_tool_call(
                tool_name=tool,
                arguments={},
            )
            self.assertEqual(result.get("action"), "allow", f"{tool} should be allowed")

    def test_away_state_blocks_guarded_tool(self):
        """Live Test: Away detector automatically pauses sensitive operations."""
        get_presence().mark_away()
        result = omnihermes_gate.on_pre_tool_call(
            tool_name="terminal",
            arguments={"command": "rm -rf /test"},
        )
        self.assertEqual(result.get("action"), "block")
        self.assertIn("away", result.get("message", "").lower())
        self.assertIn("/omnihermes unlock", result.get("message", ""))

    def test_cached_presence_mode_with_mock_embedding(self):
        """Mock Test: Cached presence mode approves when user is actively present."""
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            get_presence().mark_seen("Elijah")
            get_policy().update_config({"mode": "cached_presence"})

            result = omnihermes_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "rm -rf /temp"},
            )
            self.assertEqual(result.get("action"), "allow")

    def test_hook_blocks_unenrolled_user(self):
        """Mock Test: Fails closed when no owner profile has been enrolled."""
        with patch.object(get_biometrics(), "is_enrolled", return_value=False):
            result = omnihermes_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "rm -rf /data"},
            )
            self.assertEqual(result.get("action"), "block")
            self.assertIn("no owner profile is enrolled", result.get("message", ""))
            self.assertIn("omnihermes.enroll", result.get("message", ""))

    def test_hook_blocks_under_cron(self):
        """Mock Test: Blocks automated cron execution when physical user cannot verify."""
        mock_ctx = MagicMock()
        mock_ctx.current_cron_execution.return_value = "cron-job-123"

        result = omnihermes_gate.on_pre_tool_call(
            tool_name="terminal",
            arguments={"command": "npm publish"},
            context=mock_ctx,
        )
        self.assertEqual(result.get("action"), "block")
        self.assertIn("verify with /omnihermes unlock", result.get("message", ""))

    def test_hook_blocks_with_no_display(self):
        """Mock Test: Blocks headless/gateway sessions where no GUI can open."""
        mock_ctx = MagicMock()
        mock_ctx.current_cron_execution.return_value = None
        mock_ctx.is_headless = True

        result = omnihermes_gate.on_pre_tool_call(
            tool_name="terminal",
            arguments={"command": "git push --force"},
            context=mock_ctx,
        )
        self.assertEqual(result.get("action"), "block")
        self.assertIn("verify with /omnihermes unlock", result.get("message", ""))

    def test_hook_blocks_on_timeout(self):
        """Task 3d: Blocks execution when interactive dialog reaches internal timeout."""
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            with patch("core.ui.BiometricAuthDialog.run_dialog", return_value={
                "approved": False,
                "reason": "TIMEOUT",
                "message": "Biometric authorization timed out.",
            }):
                result = omnihermes_gate.on_pre_tool_call(
                    tool_name="terminal",
                    arguments={"command": "sudo apt update"},
                )
                self.assertEqual(result.get("action"), "block")
                self.assertEqual(
                    result.get("message"),
                    "OmniHermes: verify with /omnihermes unlock, then ask me to retry.",
                )

    def test_hook_blocks_on_camera_failure(self):
        """Task 3d: Blocks execution if webcam cannot be opened or fails."""
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            with patch("core.ui.BiometricAuthDialog.run_dialog", return_value={
                "approved": False,
                "reason": "CAMERA_UNAVAILABLE",
                "message": "OmniHermes: Could not open camera device. Action blocked.",
            }):
                result = omnihermes_gate.on_pre_tool_call(
                    tool_name="terminal",
                    arguments={"command": "rm -rf 'C:/Users/USER/presence-test/junk'"},
                )
                self.assertEqual(result.get("action"), "block")
                self.assertIn("denied", result.get("message", ""))
                self.assertIn("Could not open camera device", result.get("message", ""))

    def test_hook_blocks_on_exception(self):
        """Task 3d: Fail-closed guarantee — blocks if any unexpected exception occurs."""
        with patch.object(get_policy(), "assess_risk", side_effect=RuntimeError("Hardware sensor fault")):
            result = omnihermes_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "format c:"},
            )
            self.assertEqual(result.get("action"), "block")
            self.assertIn("unexpected error", result.get("message", "").lower())
            self.assertIn("fail-closed", result.get("message", "").lower())

    def test_hook_blocks_on_ui_dialog_exception(self):
        """Task 3d: Blocks fail-closed if UI dialog itself throws an unexpected exception."""
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            with patch("core.ui.BiometricAuthDialog.run_dialog", side_effect=Exception("Tkinter X11 display crash")):
                result = omnihermes_gate.on_pre_tool_call(
                    tool_name="terminal",
                    arguments={"command": "del /s junk"},
                )
                self.assertEqual(result.get("action"), "block")
                self.assertIn("fail-closed", result.get("message", "").lower())

    def test_active_unlock_window_allows_action(self):
        """An active unlock window allows high-risk commands without camera challenge."""
        from omnihermes.tools import get_unlock_manager
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            get_presence().mark_seen("Elijah")
            get_unlock_manager().grant_unlock("Elijah", duration_seconds=60)

            result = omnihermes_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "npm publish"},
            )
            self.assertEqual(result.get("action"), "allow")

    def test_unlock_revoked_when_away(self):
        """Stepping away immediately revokes an active unlock window."""
        from omnihermes.tools import get_unlock_manager
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            get_unlock_manager().grant_unlock("Elijah", duration_seconds=60)
            get_presence().mark_away()  # Walk away

            result = omnihermes_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "npm publish"},
            )
            self.assertEqual(result.get("action"), "block")
            self.assertIn("away", result.get("message", "").lower())
            self.assertFalse(get_unlock_manager().is_unlocked(is_away=True))

    def test_debug_log_is_written_on_hook_call(self):
        """Task 3a: Verify that debug log is appended on hook invocation without face data."""
        omnihermes_gate.on_pre_tool_call(
            tool_name="read_file",
            arguments={"path": "README.md"},
        )
        self.assertTrue(omnihermes_gate.DEBUG_LOG_PATH.exists())
        with open(omnihermes_gate.DEBUG_LOG_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertGreater(len(lines), 0)
        last_line = lines[-1]
        self.assertIn("read_file", last_line)
        self.assertIn("LOW_RISK", last_line)
        self.assertIn("return=", last_line)
        # Ensure no face embeddings or raw biometric features are logged
        self.assertNotIn("embedding", last_line.lower())


if __name__ == "__main__":
    unittest.main()
