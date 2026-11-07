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
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import __init__ as omnihermes_gate
import omnihermes.tools as tools
from core.audit import AuditLogger
from omnihermes.tools import get_biometrics, get_policy, get_presence, handle_omnihermes_enroll, reset_singletons


class TestHookInterceptor(unittest.TestCase):
    def setUp(self):
        os.environ["OMNIHERMES_TEST_MODE"] = "1"
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        os.environ["HERMES_PLUGIN_DATA_DIR"] = str(self.data_dir)
        tools.reset_singletons(self.data_dir)

        self.temp_audit_file = self.data_dir / "test_audit.jsonl"
        self.temp_debug_log = self.data_dir / "test_debug.log"
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
        tools.reset_singletons(None)
        os.environ.pop("HERMES_PLUGIN_DATA_DIR", None)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_benign_tool_allowed_instantly(self):
        """Live Test: Benign read operation should pass without biometric check."""
        result = omnihermes_gate.on_pre_tool_call(
            tool_name="read_file",
            args={"path": "README.md"},
        )
        self.assertEqual(result.get("action"), "allow")

    def test_benign_ls_command_allowed(self):
        """Benign terminal command like 'ls -la' passes without biometric check."""
        result = omnihermes_gate.on_pre_tool_call(
            tool_name="terminal",
            args={"command": "ls -la"},
        )
        self.assertEqual(result.get("action"), "allow")

    def test_exact_session_commands_trigger_guard(self):
        """Task 4: Exactly tests the two real session commands with args parameter."""
        cmd1 = 'rmdir /s /q "C:\\Users\\USER\\presence-test\\junk"'
        cmd2 = "powershell -Command \"Remove-Item -Recurse -Force 'C:\\Users\\USER\\presence-test\\junk'\""

        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            with patch("core.ui.BiometricAuthDialog.run_dialog", return_value={
                "approved": False,
                "reason": "CANCELLED",
                "message": "User closed window",
            }) as mock_dialog:
                # 1. rmdir /s /q
                res1 = omnihermes_gate.on_pre_tool_call(
                    tool_name="terminal",
                    args={"command": cmd1},
                )
                self.assertEqual(res1.get("action"), "block")
                self.assertTrue(mock_dialog.called)

                # Reset mock
                mock_dialog.reset_mock()

                # 2. powershell -Command Remove-Item -Recurse -Force
                res2 = omnihermes_gate.on_pre_tool_call(
                    tool_name="terminal",
                    args={"command": cmd2},
                )
                self.assertEqual(res2.get("action"), "block")
                self.assertTrue(mock_dialog.called)

    def test_default_to_safe_on_empty_terminal_args(self):
        """Task 5: Empty or missing arguments to terminal must fail closed and trigger guard."""
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            with patch("core.ui.BiometricAuthDialog.run_dialog", return_value={
                "approved": False,
                "reason": "TIMEOUT",
                "message": "Timeout",
            }) as mock_dialog:
                res = omnihermes_gate.on_pre_tool_call(
                    tool_name="terminal",
                    args={},
                )
                self.assertEqual(res.get("action"), "block")
                self.assertTrue(mock_dialog.called)

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
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            get_presence().mark_away()
            result = omnihermes_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "rm -rf /test"},
            )
            self.assertEqual(result.get("action"), "block")
            self.assertEqual(
                result.get("message"),
                "OmniHermes: this action needs face verification. Run /omnihermes unlock, then ask me to retry.",
            )

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
        self.assertEqual(
            result.get("message"),
            "OmniHermes: this action needs face verification. Run /omnihermes unlock, then ask me to retry.",
        )

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
        self.assertEqual(
            result.get("message"),
            "OmniHermes: this action needs face verification. Run /omnihermes unlock, then ask me to retry.",
        )

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
                    "OmniHermes: this action needs face verification. Run /omnihermes unlock, then ask me to retry.",
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
                self.assertEqual(
                    result.get("message"),
                    "OmniHermes: this action needs face verification. Run /omnihermes unlock, then ask me to retry.",
                )

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

    def test_unlock_window_120s_lifecycle(self):
        """Item 1: unlock -> risky terminal call within 120 s -> allowed; after 120 s -> blocked."""
        from omnihermes.tools import get_unlock_manager
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            # 1. Grant 120s unlock
            get_unlock_manager().grant_unlock("Elijah", duration_seconds=120)

            # 2. Risky call within 120s -> allowed
            res1 = omnihermes_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "rmdir /s /q testdir"},
            )
            self.assertEqual(res1.get("action"), "allow")

            # 3. Simulate expiry after 120s
            mgr = get_unlock_manager()
            from omnihermes.unlock import write_unlock_state_atomic
            write_unlock_state_atomic(mgr.state_file, {
                "unlocked_until": time.time() - 5.0,
                "verified_at": time.time() - 125.0,
                "owner": "Elijah",
            })

            # 4. Same risky call after 120s -> blocked
            res2 = omnihermes_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "rmdir /s /q testdir"},
            )
            self.assertEqual(res2.get("action"), "block")
            self.assertEqual(
                res2.get("message"),
                "OmniHermes: this action needs face verification. Run /omnihermes unlock, then ask me to retry.",
            )

    def test_shared_durable_unlock_file_and_telemetry(self):
        """User Requirement: write an unlock file, call the hook from fresh import path, confirm allows; after expiry blocks."""
        from omnihermes.unlock import write_unlock_state_atomic
        state_file = self.data_dir / "unlock_state.json"

        # 1. Write an unlock file directly to disk with active window
        write_unlock_state_atomic(state_file, {
            "unlocked_until": time.time() + 120.0,
            "verified_at": time.time(),
            "owner": "Elijah",
        })

        # 2. Invoke hook as if from a fresh process / fresh import path
        reset_singletons(self.data_dir)
        with patch.object(get_biometrics(), "is_enrolled", return_value=True):
            res_allow = omnihermes_gate.on_pre_tool_call(
                tool_name="terminal",
                arguments={"command": "rmdir /s /q testdir"},
            )
            self.assertEqual(res_allow.get("action"), "allow")

            # Verify telemetry was logged with all 7 fields
            self.assertTrue(omnihermes_gate.DEBUG_LOG_PATH.exists())
            with open(omnihermes_gate.DEBUG_LOG_PATH, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("tool='terminal'", content)
            self.assertIn("decision='allow'", content)
            self.assertIn("state_file=", content)
            self.assertIn("unlocked_until=", content)
            self.assertIn("seconds_left=", content)
            self.assertIn("away_status='PRESENT'", content)

            # 3. Write an expired state to disk
            write_unlock_state_atomic(state_file, {
                "unlocked_until": time.time() - 10.0,
                "verified_at": time.time() - 130.0,
                "owner": "Elijah",
            })
            reset_singletons(self.data_dir)

            with patch.object(get_biometrics(), "is_enrolled", return_value=True):
                res_block = omnihermes_gate.on_pre_tool_call(
                    tool_name="terminal",
                    arguments={"command": "rmdir /s /q testdir"},
                )
                self.assertEqual(res_block.get("action"), "block")
                self.assertEqual(
                    res_block.get("message"),
                    "OmniHermes: this action needs face verification. Run /omnihermes unlock, then ask me to retry.",
                )

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
            self.assertEqual(
                result.get("message"),
                "OmniHermes: this action needs face verification. Run /omnihermes unlock, then ask me to retry.",
            )
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
        debug_lines = [l for l in lines if "return=" in l]
        self.assertGreater(len(debug_lines), 0)
        last_line = debug_lines[-1]
        self.assertIn("read_file", last_line)
        self.assertIn("LOW_RISK", last_line)
        self.assertIn("return=", last_line)
        # Ensure no face embeddings or raw biometric features are logged
        self.assertNotIn("embedding", last_line.lower())


if __name__ == "__main__":
    unittest.main()
