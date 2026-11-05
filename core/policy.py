"""Policy Engine for Presence Gate.

Determines whether an intercepted tool call is high-risk and requires
face verification before execution. Real Hermes targets:
- `terminal` (destructive commands like rm -rf, del /s, npm publish, sudo, etc.)
- `write_file` and `patch` targeting paths outside the project root
- `delegate_task`
- Any MCP tool matching sensitive actions (pay, charge, transfer, refund, delete, send)
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from presence.models import get_default_data_dir

DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "mode": "strict",  # "strict" (always prompt), "cached_presence" (allow if owner seen within grace period)
    "cache_ttl_seconds": 60,
    "min_match_confidence": 0.363,  # OpenCV SFace recommended threshold
    "min_liveness_score": 0.80,
    "away_timeout_seconds": 45,
    "guarded_tools": [
        "terminal",
        "delegate_task",
    ],
    "file_tools": [
        "write_file",
        "patch",
    ],
    "dangerous_terminal_patterns": [
        r"(?i)\brm\s+-rf\b",
        r"(?i)\bdel\s+/[sfq]\b",
        r"(?i)\bgit\s+push\b.*--force\b",
        r"(?i)\bnpm\s+publish\b",
        r"(?i)\bcurl\b.*\|\s*(ba)?sh\b",
        r"(?i)\bsudo\b",
        r"(?i)\bformat\s+[a-z]:",
        r"(?i)\bdrop\s+database\b",
    ],
    "mcp_sensitive_regex": r"(?i)(?:^|[\W_])(pay|charge|transfer|refund|delete|send)(?:[\W_]|$)",
}


class PolicyEngine:
    """Evaluates incoming tool calls against the configured biometric policy."""

    def __init__(self, config_path: Optional[Path] = None, project_root: Optional[Path] = None):
        if config_path is None:
            base_dir = get_default_data_dir()
            config_path = base_dir / "config.json"
        self.config_path = Path(config_path)
        self.project_root = Path(project_root or os.getcwd()).resolve()
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from disk or return default."""
        if not self.config_path.exists():
            return dict(DEFAULT_CONFIG)
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            merged = dict(DEFAULT_CONFIG)
            merged.update(loaded)
            return merged
        except Exception:
            return dict(DEFAULT_CONFIG)

    def save_config(self) -> bool:
        """Persist current configuration to disk."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception:
            return False

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update and persist configuration."""
        self.config.update(updates)
        self.save_config()
        return self.config

    def is_path_outside_project(self, target_path_str: str) -> bool:
        """Check if a path string points outside the project root."""
        try:
            target = Path(target_path_str).resolve()
            # If target is inside project_root, relative_to succeeds
            target.relative_to(self.project_root)
            return False
        except (ValueError, Exception):
            # Outside project folder or drive mismatch
            return True

    def assess_risk(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Determine if tool execution requires biometric face authorization."""
        if not self.config.get("enabled", True):
            return {
                "requires_biometric": False,
                "risk_level": "DISABLED",
                "reason": "Presence Gate enforcement is disabled in settings.",
            }

        # 1. Terminal / Shell command inspection
        if tool_name in ["terminal", "bash", "shell", "run_command", "execute_command"]:
            cmd = str(arguments.get("command", "") or arguments.get("cmd", "") or "")
            for pattern in self.config.get("dangerous_terminal_patterns", []):
                if re.search(pattern, cmd):
                    return {
                        "requires_biometric": True,
                        "risk_level": "HIGH",
                        "reason": f"Terminal command matches protected pattern '{pattern}'",
                    }
            return {
                "requires_biometric": False,
                "risk_level": "LOW",
                "reason": "Terminal command does not match dangerous patterns.",
            }

        # 2. File write tools outside project folder
        if tool_name in self.config.get("file_tools", ["write_file", "patch"]):
            path_arg = str(arguments.get("path", "") or arguments.get("file_path", "") or "")
            if path_arg and self.is_path_outside_project(path_arg):
                return {
                    "requires_biometric": True,
                    "risk_level": "HIGH",
                    "reason": f"File tool '{tool_name}' target '{path_arg}' is outside project directory.",
                }
            return {
                "requires_biometric": False,
                "risk_level": "LOW",
                "reason": "File modification is within current project boundaries.",
            }

        # 3. Task delegation
        if tool_name in ["delegate_task", "subagent_spawn", "invoke_agent"]:
            return {
                "requires_biometric": True,
                "risk_level": "MEDIUM",
                "reason": f"Tool '{tool_name}' delegates autonomous execution to subagents.",
            }

        # 4. MCP sensitive tools (matching pay|charge|transfer|refund|delete|send)
        mcp_pattern = self.config.get("mcp_sensitive_regex", r"(?i)\b(pay|charge|transfer|refund|delete|send)\b")
        if re.search(mcp_pattern, tool_name):
            return {
                "requires_biometric": True,
                "risk_level": "HIGH",
                "reason": f"MCP tool '{tool_name}' matches sensitive action pattern.",
            }

        # 5. Check explicitly listed guarded tools
        if tool_name in self.config.get("guarded_tools", []):
            return {
                "requires_biometric": True,
                "risk_level": "HIGH",
                "reason": f"Tool '{tool_name}' is explicitly configured as guarded.",
            }

        return {
            "requires_biometric": False,
            "risk_level": "LOW",
            "reason": "Benign tool call.",
        }
