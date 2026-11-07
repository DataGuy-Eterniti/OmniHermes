"""Unlock Window Manager and Standalone CLI for OmniHermes.

Allows the owner to perform biometric verification in a relaxed 5-minute window
and grants a temporary execution grace period (default 120s) for high-risk commands.
Ends immediately if away-detection observes the owner leaving the desk.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from omnihermes.audit import AuditLogger
from omnihermes.models import get_default_data_dir, assert_not_real_data_dir


class UnlockManager:
    """Manages temporary unlock grace windows."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or get_default_data_dir()
        self.state_file = self.data_dir / "unlock_state.json"
        self._unlocked_until: float = 0.0
        self._unlocked_by: str = ""
        self._load_state()

    def _load_state(self) -> None:
        if not self.state_file.exists():
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._unlocked_until = float(data.get("unlocked_until", 0.0))
            self._unlocked_by = str(data.get("unlocked_by", ""))
        except Exception:
            self._unlocked_until = 0.0

    def _save_state(self) -> None:
        assert_not_real_data_dir(self.state_file, operation="save_unlock_state")
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(
                    {"unlocked_until": self._unlocked_until, "unlocked_by": self._unlocked_by},
                    f,
                    indent=2,
                )
        except Exception:
            pass

    def is_unlocked(self, is_away: bool = False) -> bool:
        """Check if unlock window is currently active. Revokes if away."""
        now = time.time()
        if now >= self._unlocked_until:
            return False

        if is_away:
            self.revoke(reason="OWNER_AWAY_DETECTED")
            return False

        return True

    def get_remaining_seconds(self) -> int:
        """Get seconds remaining on active unlock window."""
        remaining = int(self._unlocked_until - time.time())
        return max(0, remaining)

    def grant_unlock(self, user_name: str, duration_seconds: int = 120) -> Dict[str, Any]:
        """Grant an execution unlock window and log to audit ledger."""
        now = time.time()
        self._unlocked_until = now + duration_seconds
        self._unlocked_by = user_name
        self._save_state()

        audit = AuditLogger(data_dir=self.data_dir)
        audit.log_event(
            event_type="UNLOCK_GRANTED",
            user_name=user_name,
            action=f"Grant {duration_seconds}s execution window",
            result="UNLOCKED",
            details={"duration_seconds": duration_seconds, "expires_at": self._unlocked_until},
        )

        return {
            "unlocked": True,
            "duration_seconds": duration_seconds,
            "expires_at": self._unlocked_until,
            "unlocked_by": user_name,
        }

    def revoke(self, reason: str = "EXPIRED") -> None:
        """Revoke active unlock window immediately."""
        if self._unlocked_until > 0.0:
            audit = AuditLogger(data_dir=self.data_dir)
            audit.log_event(
                event_type="UNLOCK_REVOKED",
                user_name=self._unlocked_by or "System",
                action="Revoke execution window",
                result=reason,
                details={"reason": reason},
            )
        self._unlocked_until = 0.0
        self._unlocked_by = ""
        self._save_state()


def run_unlock_interactive(timeout: int = 300, duration: int = 120, camera_idx: int = 0) -> bool:
    """Run interactive biometric unlock with relaxed 300-second timeout."""
    from omnihermes.verify import run_verify
    from omnihermes.tools import get_presence

    print("=" * 60)
    print("OMNIHERMES: INTERACTIVE WORKSTATION UNLOCK")
    print(f"• Verification Timeout: {timeout}s")
    print(f"• Unlock Duration on Success: {duration}s (2 minutes)")
    print("=" * 60)

    # Run verification diagnostic with extended 300s window
    passed = run_verify(timeout=timeout, camera_idx=camera_idx)
    if passed:
        manager = UnlockManager()
        res = manager.grant_unlock("Elijah", duration_seconds=duration)
        get_presence().mark_seen("Elijah")

        print("\n" + "=" * 60)
        print("✔ WORKSTATION UNLOCKED SUCCESSFULLY!")
        print(f"• Execution Window: {duration} seconds active")
        print("• High-risk actions will proceed without biometric prompts")
        print("• Window ends early immediately if you step away from your desk")
        print("=" * 60)
        return True
    else:
        print("\n[FAILED] Workstation unlock was not completed.")
        return False


def main():
    parser = argparse.ArgumentParser(description="OmniHermes - Workstation Unlock")
    parser.add_argument("--timeout", type=int, default=300, help="Verification timeout in seconds (default: 300s)")
    parser.add_argument("--duration", type=int, default=120, help="Unlock duration in seconds (default: 120s)")
    parser.add_argument("--camera", type=int, default=0, help="Camera device index (default: 0)")

    args = parser.parse_args()
    success = run_unlock_interactive(timeout=args.timeout, duration=args.duration, camera_idx=args.camera)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

