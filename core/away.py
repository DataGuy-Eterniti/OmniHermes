"""Away Detection and Continuous Presence Monitor for Omnihermes.

Monitors owner presence in front of the workstation. If the owner departs
for longer than `away_timeout_seconds`, all high-risk actions are automatically
quarantined until physical presence is re-verified.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

from omnihermes.models import assert_not_real_data_dir, get_default_data_dir


class PresenceMonitor:
    """Tracks continuous owner presence and away states synchronized across processes."""

    def __init__(self, timeout_seconds: int = 45, data_dir: Optional[Path] = None):
        self.timeout_seconds = timeout_seconds
        self.data_dir = data_dir or get_default_data_dir()
        self.state_file = self.data_dir / "presence_state.json"
        self._last_seen_timestamp: float = time.time()
        self._is_monitoring: bool = False
        self._last_verified_user: Optional[str] = None
        self._load_state()

    def _load_state(self) -> None:
        """Load presence state from disk to synchronize across CLI and gateway processes."""
        if not self.state_file.exists():
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._last_seen_timestamp = float(data.get("last_seen_timestamp", self._last_seen_timestamp))
            self._last_verified_user = data.get("verified_user", self._last_verified_user)
        except Exception:
            pass

    def _save_state(self) -> None:
        """Persist presence state to disk."""
        assert_not_real_data_dir(self.state_file, operation="save_presence_state")
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "last_seen_timestamp": self._last_seen_timestamp,
                        "verified_user": self._last_verified_user,
                    },
                    f,
                    indent=2,
                )
        except Exception:
            pass

    def mark_seen(self, user_name: Optional[str] = None) -> None:
        """Update last seen timestamp when owner face is positively detected."""
        self._last_seen_timestamp = time.time()
        if user_name:
            self._last_verified_user = user_name
        self._save_state()

    def mark_away(self) -> None:
        """Explicitly trigger away state (e.g. on screen lock or manual away button)."""
        self._last_seen_timestamp = 0.0
        self._save_state()

    def is_away(self) -> bool:
        """Check if the owner is currently considered away from the desk."""
        self._load_state()
        elapsed = time.time() - self._last_seen_timestamp
        return elapsed > self.timeout_seconds

    def get_status(self) -> Dict[str, Any]:
        """Return current presence monitor status."""
        self._load_state()
        elapsed = time.time() - self._last_seen_timestamp
        away = self.is_away()
        return {
            "status": "AWAY" if away else "PRESENT",
            "last_seen_seconds_ago": round(max(0.0, elapsed), 1),
            "timeout_threshold_seconds": self.timeout_seconds,
            "verified_user": self._last_verified_user,
        }

