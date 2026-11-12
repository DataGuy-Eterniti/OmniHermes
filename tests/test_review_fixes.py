"""Regression tests for the Hermes plugin-catalog review of OmniHermes (PR #153906).

Each class maps to one point the reviewer raised:
1. The model must not be able to unlock itself by writing or reading gate state.
2. The read-only allowlist must not run other programs or dump secrets.
3. The model must not choose its own unlock length.
4. The Desktop half is removed (no unsupported APIs shipped).
5. Secrets and the data directory are created owner-only.
6. No hard-coded owner name.
Plus the two recommendations: pinned model URLs and a profile-aware data dir.
"""

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import __init__ as omnihermes_gate
import omnihermes.tools as tools
from core.audit import AuditLogger
from core.policy import PolicyEngine, is_terminal_command_readonly
from omnihermes.tools import get_policy, get_presence, get_unlock_manager, handle_omnihermes_enroll

REPO = Path(__file__).resolve().parent.parent
POSIX = os.name != "nt"


class _GateTestBase(unittest.TestCase):
    def setUp(self):
        os.environ["OMNIHERMES_TEST_MODE"] = "1"
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        os.environ["HERMES_PLUGIN_DATA_DIR"] = str(self.data_dir)
        tools.reset_singletons(self.data_dir)
        self.audit_patcher = patch.object(tools, "_audit", AuditLogger(log_path=self.data_dir / "audit_test.jsonl"))
        self.audit_patcher.start()
        self.debug_patcher = patch.object(omnihermes_gate, "DEBUG_LOG_PATH", self.data_dir / "debug_test.log")
        self.debug_patcher.start()
        self.display_patcher = patch.object(omnihermes_gate, "is_display_detected", return_value=True)
        self.display_patcher.start()
        get_policy().update_config({"enabled": True, "mode": "strict"})
        handle_omnihermes_enroll({"owner_name": "Ada", "test_embedding": [0.1] * 128})
        get_presence().mark_seen("Ada")

    def tearDown(self):
        self.display_patcher.stop()
        self.audit_patcher.stop()
        self.debug_patcher.stop()
        tools.reset_singletons(None)
        os.environ.pop("HERMES_PLUGIN_DATA_DIR", None)
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def hook(self, tool, args):
        # Any face dialog reaching this point would be a bug; make it fail loudly as a denial.
        with patch("core.ui.BiometricAuthDialog.run_dialog", return_value={"approved": False, "reason": "TEST"}):
            return omnihermes_gate.on_pre_tool_call(tool_name=tool, args=args)


class TestProtectedGateState(_GateTestBase):
    """Review point 1: writes/reads of the plugin's own data dir are always blocked."""

    def protected_targets(self):
        d = self.data_dir
        return [d / "unlock_state.json", d / "config.json", d / "presence_state.json", d / "profile.enc", d / ".secret_key"]

    def test_write_file_into_data_dir_blocked_even_when_unlocked(self):
        get_unlock_manager().grant_unlock("Ada")
        self.assertTrue(get_unlock_manager().is_unlocked())
        for target in self.protected_targets():
            for tool in ("write_file", "patch"):
                res = self.hook(tool, {"path": str(target), "content": "{}"})
                self.assertEqual(res["action"], "block", f"{tool} -> {target.name} must be blocked")
                self.assertNotIn("unlock", res["message"].lower(), "protected block must not suggest unlocking")

    def test_write_file_blocked_with_cwd_equal_to_data_dir(self):
        # Policy project root is the data dir here (worst case: cwd == data dir).
        res = self.hook("write_file", {"path": "unlock_state.json", "content": "{}"})
        self.assertEqual(res["action"], "block")

    def test_reading_secret_material_blocked(self):
        for args in (
            {"path": str(self.data_dir / ".secret_key")},
            {"path": str(self.data_dir / "profile.enc")},
        ):
            self.assertEqual(self.hook("read_file", args)["action"], "block")
        for cmd in (
            f"cat {self.data_dir / '.secret_key'}",
            "type C:\\Users\\me\\.hermes\\omnihermes\\.secret_key",
            "ls ~/.hermes/omnihermes",
            "cat $HERMES_HOME/plugin-data/omnihermes/config.json",
        ):
            self.assertFalse(is_terminal_command_readonly(cmd), cmd)
            self.assertEqual(self.hook("terminal", {"command": cmd})["action"], "block", cmd)

    def test_disabling_gate_via_config_is_blocked(self):
        get_policy().update_config({"enabled": False})
        res = self.hook("write_file", {"path": str(self.data_dir / "config.json"), "content": '{"enabled": true}'})
        self.assertEqual(res["action"], "block")

    def test_unrelated_reads_still_allowed(self):
        self.assertEqual(self.hook("read_file", {"path": "README.md"})["action"], "allow")
        self.assertEqual(self.hook("terminal", {"command": "grep -n SECRET_KEY settings.py"})["action"], "allow")


class TestUnlockStateCannotBeForged(_GateTestBase):
    """Review point 1 (second half): unlock state is HMAC-bound to the local key."""

    def write_raw(self, record):
        (self.data_dir / "unlock_state.json").write_text(json.dumps(record), encoding="utf-8")

    def assert_locked_and_blocks(self):
        mgr = get_unlock_manager()
        self.assertFalse(mgr.is_unlocked())
        self.assertEqual(mgr.get_remaining_seconds(), 0)
        self.assertEqual(self.hook("terminal", {"command": "rm -rf build"})["action"], "block")

    def test_unsigned_file_is_locked(self):
        now = time.time()
        self.write_raw({"unlocked_until": now + 3600, "verified_at": now, "owner": "Ada"})
        self.assert_locked_and_blocks()

    def test_wrong_signature_is_locked(self):
        now = time.time()
        self.write_raw({"v": 2, "unlocked_until": now + 60, "verified_at": now, "owner": "Ada", "sig": "00" * 32})
        self.assert_locked_and_blocks()

    def test_tampered_expiry_is_locked(self):
        get_unlock_manager().grant_unlock("Ada")
        path = self.data_dir / "unlock_state.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["unlocked_until"] += 3600
        path.write_text(json.dumps(record), encoding="utf-8")
        self.assert_locked_and_blocks()

    def test_validly_signed_but_overlong_window_is_locked(self):
        from omnihermes.unlock import write_unlock_state_atomic
        now = time.time()
        write_unlock_state_atomic(self.data_dir / "unlock_state.json",
                                  {"unlocked_until": now + 86400, "verified_at": now, "owner": "Ada"})
        self.assert_locked_and_blocks()

    def test_future_verified_at_is_locked(self):
        from omnihermes.unlock import write_unlock_state_atomic
        now = time.time()
        write_unlock_state_atomic(self.data_dir / "unlock_state.json",
                                  {"unlocked_until": now + 3700, "verified_at": now + 3600, "owner": "Ada"})
        self.assert_locked_and_blocks()

    def test_genuine_grant_unlocks(self):
        get_unlock_manager().grant_unlock("Ada")
        self.assertTrue(get_unlock_manager().is_unlocked())
        self.assertEqual(self.hook("terminal", {"command": "rm -rf build"})["action"], "allow")


class TestReadOnlyAllowlist(unittest.TestCase):
    """Review point 2."""

    def test_rejected(self):
        for cmd in [
            "env", "env rm -rf /", "printenv", "printenv OPENAI_API_KEY", "time rm -rf x",
            "echo $(rm -rf x)", "echo `rm -rf x`", "cat <(rm -rf x)", "ls >(rm -rf x)",
            "git -c core.pager='rm -rf x' log", "git --config-env=core.pager=X status",
            "git --exec-path=/tmp/evil status", "git log --output=/tmp/x", "git diff --ext-diff",
            "GIT_PAGER='rm -rf x' git log", "PAGER=sh git log", "dir & del /q x", "ls & rm -rf x",
            "git branch evil", "git branch -D main", "git remote add evil https://x", "git remote remove origin",
            "hostname newname", "date -s 2020-01-01", "ls > out.txt",
        ]:
            self.assertFalse(is_terminal_command_readonly(cmd), cmd)

    def test_allowed(self):
        for cmd in [
            "ls -la", "pwd", "cat README.md", "git status", "git log --oneline -5", "git diff HEAD~1",
            "git branch -a", "git branch --show-current", "git remote -v", "git show HEAD",
            "grep -rn TODO src", "dir", "whoami", "ls | grep py", "uname -a",
        ]:
            self.assertTrue(is_terminal_command_readonly(cmd), cmd)


class TestUnlockDurationIsNotModelControlled(_GateTestBase):
    """Review point 3."""

    def test_grant_is_clamped_to_configured_window(self):
        res = get_unlock_manager().grant_unlock("Ada", duration_seconds=999999)
        self.assertEqual(res["duration_seconds"], 120)
        self.assertLessEqual(get_unlock_manager().get_remaining_seconds(), 120)

    def test_configured_window_is_read_in_code(self):
        get_policy().update_config({"unlock_window_seconds": 30})
        res = get_unlock_manager().grant_unlock("Ada")
        self.assertEqual(res["duration_seconds"], 30)

    def test_tool_ignores_model_duration_and_reports_real_value(self):
        get_policy().update_config({"unlock_window_seconds": 45})

        def fake_interactive(timeout=300, duration=None, camera_idx=0):
            self.assertIsNone(duration, "model-supplied duration must not reach the unlock flow")
            return get_unlock_manager().grant_unlock("Ada")["duration_seconds"]

        with patch.object(tools, "run_unlock_interactive", side_effect=fake_interactive):
            out = json.loads(tools.handle_omnihermes_unlock({"duration_seconds": 86400, "timeout_seconds": 1}))
        self.assertEqual(out["duration_seconds"], 45)
        self.assertIn("45 seconds", out["message"])
        self.assertLessEqual(get_unlock_manager().get_remaining_seconds(), 45)

    def test_schema_takes_no_duration(self):
        from omnihermes.schemas import OMNIHERMES_UNLOCK_SCHEMA
        self.assertEqual(OMNIHERMES_UNLOCK_SCHEMA["parameters"]["properties"], {})


class TestDesktopHalfRemoved(unittest.TestCase):
    """Review point 4."""

    def test_no_desktop_entry(self):
        self.assertFalse((REPO / "desktop" / "plugin.js").exists())
        self.assertNotIn("desktop:", (REPO / "plugin.yaml").read_text(encoding="utf-8"))


@unittest.skipUnless(POSIX, "POSIX file modes")
class TestFileModes(_GateTestBase):
    """Review point 5."""

    def mode(self, p):
        return stat.S_IMODE(os.stat(p).st_mode)

    def test_secret_key_profile_and_dir_modes(self):
        self.assertEqual(self.mode(self.data_dir / ".secret_key"), 0o600)
        self.assertEqual(self.mode(self.data_dir / "profile.enc"), 0o600)
        self.assertEqual(self.mode(self.data_dir), 0o700)

    def test_unlock_state_mode(self):
        get_unlock_manager().grant_unlock("Ada")
        self.assertEqual(self.mode(self.data_dir / "unlock_state.json"), 0o600)

    def test_private_file_helper(self):
        from omnihermes.models import write_private_file
        target = self.data_dir / "profile_backup_test.enc"
        write_private_file(target, b"x")
        self.assertEqual(self.mode(target), 0o600)


class TestNoHardCodedOwner(_GateTestBase):
    """Review point 6."""

    def test_no_hard_coded_name_in_plugin_sources(self):
        offenders = []
        for path in list(REPO.glob("*.py")) + list((REPO / "omnihermes").glob("*.py")) + list((REPO / "core").glob("*.py")):
            if "Elijah" in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(REPO)))
        self.assertEqual(offenders, [])

    def test_unlock_uses_enrolled_name(self):
        from omnihermes import unlock
        with patch("omnihermes.verify.run_verify", return_value=True), \
             patch.object(unlock, "UnlockManager", return_value=get_unlock_manager()):
            granted = unlock.run_unlock_interactive(timeout=1)
        self.assertEqual(granted, 120)
        self.assertEqual(get_unlock_manager().get_state()["owner"], "Ada")


class TestRecommendations(unittest.TestCase):
    def test_opencv_zoo_urls_pinned(self):
        from omnihermes.models import MODELS, OPENCV_ZOO_COMMIT
        self.assertEqual(len(OPENCV_ZOO_COMMIT), 40)
        for name in ("yunet", "sface"):
            self.assertIn(f"/opencv_zoo/{OPENCV_ZOO_COMMIT}/", MODELS[name]["url"])
            self.assertNotIn("/main/", MODELS[name]["url"])

    def test_data_dir_follows_hermes_home(self):
        from omnihermes import models
        with tempfile.TemporaryDirectory() as home:
            env = {k: v for k, v in os.environ.items() if k not in ("HERMES_PLUGIN_DATA_DIR", "OMNIHERMES_TEST_MODE")}
            env["HERMES_HOME"] = home
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(models, "_migrate_legacy_data", lambda p: None):
                sys.modules.pop("plugins.plugin_storage", None)
                d = models.get_default_data_dir()
            self.assertEqual(d.resolve(), (Path(home) / "plugin-data" / "omnihermes").resolve())


if __name__ == "__main__":
    unittest.main()
