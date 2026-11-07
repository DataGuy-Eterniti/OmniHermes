"""Policy Engine for OmniHermes.

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

try:
    from omnihermes.models import get_default_data_dir, assert_not_real_data_dir
except (ImportError, ValueError):
    from .models import get_default_data_dir, assert_not_real_data_dir

READONLY_TERMINAL_COMMANDS = {
    "ls", "dir", "pwd", "cd", "cat", "type", "head", "tail", "echo",
    "whoami", "where", "which", "git", "date", "time", "hostname", "uname",
    "clear", "cls", "env", "printenv", "id", "findstr", "grep", "wc"
}

READONLY_GIT_SUBCOMMANDS = {
    "status", "log", "diff", "branch", "show", "remote", "version", "help"
}


def is_terminal_command_readonly(cmd: str) -> bool:
    """Evaluate whether a shell command is strictly read-only.
    
    Default-deny: while locked, all terminal calls are HIGH risk unless every
    piped/chained segment is explicitly in the read-only allowlist.
    Disallows file-writing redirects (> >>), shell execution pipes (| sh), etc.
    """
    if not cmd or not cmd.strip():
        return False

    raw = cmd.strip()

    # Reject any write redirection (> or >>)
    if ">" in raw:
        return False

    # Split command into chained/piped segments: &&, ||, ;, |, \n
    segments = re.split(r"&&|\|\||;|\||\n", raw)

    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue

        # Remove leading env vars (e.g. "FOO=1 ls" or "$env:FOO='1';")
        parts = [p.strip("\"'") for p in seg.split() if p.strip("\"'")]
        while parts and "=" in parts[0] and not parts[0].startswith("-"):
            parts.pop(0)

        if not parts:
            return False

        # Extract base executable name
        base_cmd = parts[0].replace("\\", "/").split("/")[-1].lower()
        if base_cmd.endswith(".exe"):
            base_cmd = base_cmd[:-4]

        # Check against allowed commands
        if base_cmd not in READONLY_TERMINAL_COMMANDS:
            return False

        # If base command is git, verify the subcommand is read-only
        if base_cmd == "git":
            subcmd = None
            for p in parts[1:]:
                if not p.startswith("-"):
                    subcmd = p.lower()
                    break
            if not subcmd or subcmd not in READONLY_GIT_SUBCOMMANDS:
                return False

    return True


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
        # 1. POSIX recursive deletion (rm -rf, rm -r, rm -fr, MSYS paths)
        r"(?i)\brm\s+-[a-z]*r[a-z]*\b",
        # 2. Windows folder removal: rmdir /s, rd /s, /q
        r"(?i)\b(?:rmdir|rd)\b.*?(?:/[sfq]|-[sfq])",
        # 3. Windows file deletion: del /s, del /q, del /f
        r"(?i)\bdel\b.*?(?:/[sfq]|-[sfq])",
        # 4. Windows / DOS erase
        r"(?i)\berase\b",
        # 5. PowerShell Remove-Item (-Recurse, -Force, and aliases ri)
        r"(?i)\bRemove-Item\b.*?(?:-(?:r|recurse|force))\b",
        r"(?i)\b(?:ri)\b.*?(?:-(?:r|recurse|force))\b",
        # 6. Disk partitioning and formatting
        r"(?i)\bformat\b",
        r"(?i)\bdiskpart\b",
        # 7. Destructive git commands
        r"(?i)\bgit\s+push\b.*?--force\b",
        r"(?i)\bgit\s+reset\b.*?--hard\b",
        # 8. Package publishing
        r"(?i)\bnpm\s+publish\b",
        # 9. Remote shell pipe execution
        r"(?i)\bcurl\b.*?\|\s*(?:ba|z)?sh\b",
        r"(?i)(?:iwr|Invoke-WebRequest|Invoke-RestMethod|irm)\b.*?\|\s*(?:iex|Invoke-Expression)\b",
        # 10. Privilege escalation
        r"(?i)\bsudo\b",
        # 11. Database drops
        r"(?i)\bdrop\s+database\b",
        r"(?i)\btruncate\s+table\b",
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
        """Load configuration from disk or create default."""
        if not self.config_path.exists():
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.save_config(DEFAULT_CONFIG)
            return dict(DEFAULT_CONFIG)

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            # Merge with defaults to ensure all keys exist
            config = dict(DEFAULT_CONFIG)
            config.update(loaded)

            # Ensure all mandatory default security patterns are present
            default_patterns = DEFAULT_CONFIG.get("dangerous_terminal_patterns", [])
            existing_patterns = list(config.get("dangerous_terminal_patterns", []))
            for pat in default_patterns:
                if pat not in existing_patterns:
                    existing_patterns.append(pat)
            config["dangerous_terminal_patterns"] = existing_patterns
            return config
        except Exception:
            return dict(DEFAULT_CONFIG)

    def save_config(self, config_to_save: Optional[Dict[str, Any]] = None) -> bool:
        """Persist configuration to disk."""
        assert_not_real_data_dir(self.config_path, operation="save_policy_config")
        if config_to_save is not None:
            self.config = config_to_save
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
                "reason": "OmniHermes enforcement is disabled in settings.",
            }

        # 1. Terminal / Shell command inspection (Default-Deny while locked)
        if tool_name in ["terminal", "bash", "shell", "run_command", "execute_command"]:
            cmd_val = (
                arguments.get("command")
                or arguments.get("cmd")
                or arguments.get("args")
                or arguments.get("script")
                or arguments.get("input")
                or ""
            )
            if isinstance(cmd_val, dict):
                cmd_val = (
                    cmd_val.get("command")
                    or cmd_val.get("cmd")
                    or cmd_val.get("args")
                    or json.dumps(cmd_val)
                )
            elif isinstance(cmd_val, (list, tuple)):
                cmd_val = " ".join(str(x) for x in cmd_val)
            cmd = str(cmd_val or "").strip()

            if is_terminal_command_readonly(cmd):
                return {
                    "requires_biometric": False,
                    "risk_level": "LOW",
                    "reason": "Allowlisted read-only terminal command.",
                }

            return {
                "requires_biometric": True,
                "risk_level": "HIGH",
                "reason": "Action requires biometric face verification.",
            }

        # 2. Code execution tools are guarded by default
        if tool_name in ["execute_code", "code_execution", "run_code"]:
            return {
                "requires_biometric": True,
                "risk_level": "HIGH",
                "reason": "Action requires biometric face verification.",
            }

        # 3. File write tools outside project folder
        if tool_name in self.config.get("file_tools", ["write_file", "patch"]):
            path_arg = str(arguments.get("path", "") or arguments.get("file_path", "") or "")
            if path_arg and self.is_path_outside_project(path_arg):
                return {
                    "requires_biometric": True,
                    "risk_level": "CRITICAL",
                    "reason": "Action touches file outside project boundary.",
                }
            return {
                "requires_biometric": False,
                "risk_level": "LOW",
                "reason": "File operation is within project boundary.",
            }

        # 4. Direct guarded tools (e.g. delegate_task)
        if tool_name in self.config.get("guarded_tools", ["delegate_task"]):
            return {
                "requires_biometric": True,
                "risk_level": "HIGH",
                "reason": "Action requires biometric face verification.",
            }

        # 4. MCP Tools - Sensitive keywords inspection
        mcp_pattern = self.config.get("mcp_sensitive_regex", "")
        if mcp_pattern and re.search(mcp_pattern, tool_name):
            return {
                "requires_biometric": True,
                "risk_level": "HIGH",
                "reason": f"MCP tool name '{tool_name}' matches sensitive keyword pattern.",
            }

        # Arguments inspection for sensitive patterns in MCP tools
        args_str = json.dumps(arguments)
        for pattern in self.config.get("dangerous_terminal_patterns", []):
            if re.search(pattern, args_str):
                return {
                    "requires_biometric": True,
                    "risk_level": "HIGH",
                    "reason": f"Tool arguments match sensitive pattern '{pattern}'",
                }

        # Safe benign tool
        return {
            "requires_biometric": False,
            "risk_level": "LOW",
            "reason": f"Tool '{tool_name}' is classified as low risk.",
        }
