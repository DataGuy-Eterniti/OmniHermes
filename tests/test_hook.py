"""Tests for pre_tool_call lifecycle interceptor.

Tests fail-closed behavior across critical error scenarios:
- Blocks on exception
- Blocks on timeout
- Blocks under cron execution
- Blocks with no display / headless
- Blocks for an unenrolled user
All tests using mocks are clearly labeled.
"""

import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import __init__ as presence_gate
from tools import get_biometrics, get_policy, get_presence, handle_presence_enroll


class TestHookInterceptor(unittest.TestCase):
    def setUp(self):
        get_policy().update_config({"enabled": True, "mode": "strict"})
        get_presence().mark_seen("Elijah")

    def test_benign_tool_allowed_instantly(self):
        """Live Test: Benign read operation should pass without biometric check."""
        result = presence_gate.on_pre_tool_call(
            tool_name="read_file",
            arguments={"path": "README.md"},
        )
        self.assertEqual(result.get("action"), "allow")

    def test_presence_self_tools_never_blocked(self):
        """Live Test: Presence management tools should never be blocked."""
        result = presence_gate.on_pre_tool_call(
            tool_name="presence_status",
            arguments={},
        )
        self.assertEqual(result.get("action"), "allow")

    def test_away_state_blocks_guarded_tool(self):
        """Live Test: Away detector automatically pauses sensitive operations."""
        get_presence().mark_away()
        result = presence_gate.on_pre_tool_call(
            tool_name="terminal",
            arguments={"command": "rm -rf /test"},
        )
        self.assertEqual(result.get("action"), "block")
        self.assertIn("away", result.get("message", "").lower())

    def test_cached_presence_mode_with_mock_embedding(self):
        """Mock Test: Cached presence mode approves when user is actively present."""
        dummy_vec = [0.1] * 128
        handle_presence_enroll({"owner_name": "Elijah", "test_embedding": dummy_vec})
        get_presence().mark_seen("Elijah")
        get_policy().update_config({"mode": "cached_presence"})

        result = presence_gate.on_pre_tool_call(
            tool_name="terminal",
            arguments={"command": "rm -rf /temp"},
        )
        self.assertEqual(result.get("action"), "allow")

    def test_hook_blocks_unenrolled_user(self):
        """Mock Test: Fails closed when no owner profile has been enrolled."""
        with patch.object(get_biometrics(), "is_enrolled", return_value=False):
            result = presence_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "rm -rf /data"},
            )
            self.assertEqual(result.get("action"), "block")
            self.assertIn("no owner profile is enrolled", result.get("message", ""))
            self.assertIn("presence.enroll", result.get("message", ""))

    def test_hook_blocks_under_cron(self):
        """Mock Test: Blocks automated cron execution when physical user cannot verify."""
        # Setup mock context with active cron execution
        mock_ctx = MagicMock()
        mock_ctx.current_cron_execution.return_value = "cron-job-123"

        result = presence_gate.on_pre_tool_call(
            tool_name="terminal",
            arguments={"command": "npm publish"},
            context=mock_ctx,
        )
        self.assertEqual(result.get("action"), "block")
        self.assertIn("needs face verification at Elijah's computer", result.get("message", ""))

    def test_hook_blocks_with_no_display(self):
        """Mock Test: Blocks headless/gateway sessions where no GUI can open."""
        mock_ctx = MagicMock()
        mock_ctx.current_cron_execution.return_value = None
        mock_ctx.is_headless = True

        result = presence_gate.on_pre_tool_call(
            tool_name="terminal",
            arguments={"command": "git push --force"},
            context=mock_ctx,
        )
        self.assertEqual(result.get("action"), "block")
        self.assertIn("needs face verification at Elijah's computer", result.get("message", ""))

    def test_hook_blocks_on_timeout(self):
        """Mock Test: Blocks execution when interactive dialog reaches internal timeout."""
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            with patch("core.ui.BiometricAuthDialog.run_dialog", return_value={
                "approved": False,
                "reason": "TIMEOUT",
                "message": "Biometric authorization timed out.",
            }):
                result = presence_gate.on_pre_tool_call(
                    tool_name="terminal",
                    arguments={"command": "sudo apt update"},
                )
                self.assertEqual(result.get("action"), "block")
                self.assertIn("verify with /presence unlock", result.get("message", "").lower())

    def test_hook_blocks_on_exception(self):
        """Mock Test: Fail-closed guarantee — blocks if any unexpected exception occurs."""
        with patch.object(get_policy(), "assess_risk", side_effect=RuntimeError("Hardware sensor fault")):
            result = presence_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "format c:"},
            )
            self.assertEqual(result.get("action"), "block")
            self.assertIn("unexpected error", result.get("message", "").lower())
            self.assertIn("fail-closed", result.get("message", "").lower())

    def test_active_unlock_window_allows_action(self):
        """Mock Test: An active unlock window allows high-risk commands without camera challenge."""
        from tools import get_unlock_manager
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            get_presence().mark_seen("Elijah")
            get_unlock_manager().grant_unlock("Elijah", duration_seconds=60)

            result = presence_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "npm publish"},
            )
            self.assertEqual(result.get("action"), "allow")

    def test_unlock_revoked_when_away(self):
        """Mock Test: Stepping away immediately revokes an active unlock window."""
        from tools import get_unlock_manager
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            get_unlock_manager().grant_unlock("Elijah", duration_seconds=60)
            get_presence().mark_away()  # Walk away

            result = presence_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "npm publish"},
            )
            self.assertEqual(result.get("action"), "block")
            self.assertIn("away", result.get("message", "").lower())
            self.assertFalse(get_unlock_manager().is_unlocked(is_away=True))


if __name__ == "__main__":
    unittest.main()
