"""Tests for pre_tool_call lifecycle interceptor."""

import unittest
from unittest.mock import patch, MagicMock

import __init__ as omnihermes_entry
from tools import get_policy, get_presence, get_biometrics, handle_omnihermes_enroll


class TestHookInterceptor(unittest.TestCase):
    def setUp(self):
        # Reset policy and presence
        get_policy().update_config({"enabled": True, "mode": "strict"})
        get_presence().mark_seen("Alice")

    def test_benign_tool_allowed_instantly(self):
        result = omnihermes_entry.on_pre_tool_call(
            tool_name="get_weather",
            arguments={"city": "London"},
        )
        self.assertEqual(result.get("action"), "allow")

    def test_omnihermes_self_tools_never_blocked(self):
        result = omnihermes_entry.on_pre_tool_call(
            tool_name="omnihermes_status",
            arguments={},
        )
        self.assertEqual(result.get("action"), "allow")

    def test_away_state_blocks_guarded_tool(self):
        # Force away state
        get_presence().mark_away()
        result = omnihermes_entry.on_pre_tool_call(
            tool_name="execute_command",
            arguments={"command": "rm -rf /"},
        )
        self.assertEqual(result.get("action"), "block")
        self.assertIn("Owner is away", result.get("message", ""))

    def test_cached_presence_mode(self):
        # Enroll user
        handle_omnihermes_enroll({"owner_name": "Alice"})
        get_presence().mark_seen("Alice")
        get_policy().update_config({"mode": "cached_presence"})

        result = omnihermes_entry.on_pre_tool_call(
            tool_name="make_payment",
            arguments={"amount": 49},
        )
        self.assertEqual(result.get("action"), "allow")


if __name__ == "__main__":
    unittest.main()
