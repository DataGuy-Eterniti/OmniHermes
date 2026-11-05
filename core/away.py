"""Away Detection and Continuous Presence Monitor for Omnihermes.

Monitors owner presence in front of the workstation. If the owner departs
for longer than `away_timeout_seconds`, all high-risk actions are automatically
quarantined until physical presence is re-verified.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional


class PresenceMonitor:
    """Tracks continuous owner presence and away states."""

    def __init__(self, timeout_seconds: int = 45):
        self.timeout_seconds = timeout_seconds
        self._last_seen_timestamp: float = time.time()
        self._is_monitoring: bool = False
        self._last_verified_user: Optional[str] = None

    def mark_seen(self, user_name: Optional[str] = None) -> None:
        """Update last seen timestamp when owner face is positively detected."""
        self._last_seen_timestamp = time.time()
        if user_name:
            self._last_verified_user = user_name

    def mark_away(self) -> None:
        """Explicitly trigger away state (e.g. on screen lock or manual away button)."""
        self._last_seen_timestamp = 0.0

    def is_away(self) -> bool:
        """Check if the owner is currently considered away from the desk."""
        elapsed = time.time() - self._last_seen_timestamp
        return elapsed > self.timeout_seconds

    def get_status(self) -> Dict[str, Any]:
        """Return current presence monitor status."""
        elapsed = time.time() - self._last_seen_timestamp
        away = self.is_away()
        return {
            "status": "AWAY" if away else "PRESENT",
            "last_seen_seconds_ago": round(elapsed, 1),
            "timeout_threshold_seconds": self.timeout_seconds,
            "verified_user": self._last_verified_user,
        }

