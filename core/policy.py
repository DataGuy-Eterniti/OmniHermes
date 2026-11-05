"""Policy Engine for Omnihermes.

Determines whether an intercepted tool call is high-risk and enforces biometric
authorization policies based on tool name, risk score, and payload inspection.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    "mode": "strict",  # "strict" (always prompt), "cached_presence" (allow if owner present within grace period)
    "cache_ttl_seconds": 60,
    "min_match_confidence": 0.75,
    "min_liveness_score": 0.80,
    "away_timeout_seconds": 45,
    "guarded_tools": [
        "execute_command",
        "bash",
        "shell",
        "run_command",
        "delete_file",
        "make_payment",
        "crypto_transfer",
        "send_message",
        "post_tweet",
        "send_email",
        "send_sms",
    ],
    "dangerous_argument_patterns": [
        r"(?i)\brm\s+-rf\b",
        r"(?i)\bsudo\b",
        r"(?i)\bdrop\s+database\b",
        r"(?i)\bformat\s+[a-z]:\b",
        r"(?i)\b(transfer|pay|amount)\b.*[1-9]",
        r"(?i)\bapi[-_]?key\b",
        r"(?i)\bpassword\b",
    ],
}


class PolicyEngine:
    """Evaluates incoming tool calls against the configured biometric policy."""

    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            base_dir = Path.home() / ".hermes" / "omnihermes"
            base_dir.mkdir(parents=True, exist_ok=True)
            config_path = base_dir / "config.json"
        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from disk or create default."""
        if not self.config_path.exists():
            self._save_config(DEFAULT_CONFIG)
            return dict(DEFAULT_CONFIG)
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                merged = dict(DEFAULT_CONFIG)
                merged.update(data)
                return merged
        except Exception:
            return dict(DEFAULT_CONFIG)

    def _save_config(self, cfg: Dict[str, Any]) -> None:
        """Save configuration to disk."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update policy parameters."""
        self.config.update(updates)
        self._save_config(self.config)
        return self.config

    def assess_risk(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate whether a tool invocation requires biometric authorization.
        
        Returns:
            Dict containing:
                requires_biometric: bool
                risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
                reasons: List[str]
        """
        if not self.config.get("enabled", True):
            return {"requires_biometric": False, "risk_level": "LOW", "reasons": ["Omnihermes disabled"]}

        reasons: List[str] = []
        risk_score = 0

        # Check guarded tools list
        guarded_tools = self.config.get("guarded_tools", [])
        if tool_name in guarded_tools:
            risk_score += 2
            reasons.append(f"Tool '{tool_name}' is in guarded tools policy")

        # Inspect argument values against dangerous patterns
        args_str = json.dumps(arguments)
        patterns = self.config.get("dangerous_argument_patterns", [])
        for pattern in patterns:
            match = re.search(pattern, args_str)
            if match:
                risk_score += 3
                reasons.append(f"Dangerous pattern matched: '{match.group(0)}'")

        if risk_score >= 3:
            level = "CRITICAL" if risk_score >= 5 else "HIGH"
            return {"requires_biometric": True, "risk_level": level, "reasons": reasons}
        elif risk_score >= 2:
            return {"requires_biometric": True, "risk_level": "MEDIUM", "reasons": reasons}
        else:
            return {"requires_biometric": False, "risk_level": "LOW", "reasons": []}
