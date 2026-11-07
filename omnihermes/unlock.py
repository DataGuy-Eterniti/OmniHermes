"""Unlock Window Manager and Standalone CLI for OmniHermes.

Allows the owner to perform biometric verification in a relaxed 5-minute window
and grants a temporary execution grace period (default 120s) for high-risk commands.
Ends immediately if away-detection observes the owner leaving the desk.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

from omnihermes.audit import AuditLogger
from omnihermes.models import get_default_data_dir, assert_not_real_data_dir


def read_unlock_state(state_file: Path) -> Dict[str, Any]:
    """Read unlock state from disk on demand. Zero in-memory caching."""
    if not state_file.exists():
        return {"unlocked_until": 0.0, "verified_at": 0.0, "owner": ""}
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "unlocked_until": float(data.get("unlocked_until", 0.0)),
            "verified_at": float(data.get("verified_at", 0.0)),
            "owner": str(data.get("owner", data.get("unlocked_by", ""))),
        }
    except Exception:
        return {"unlocked_until": 0.0, "verified_at": 0.0, "owner": ""}


def write_unlock_state_atomic(state_file: Path, data: Dict[str, Any]) -> None:
    """Write unlock state atomically using a temp file on the same directory + os.replace."""
    assert_not_real_data_dir(state_file, operation="save_unlock_state")
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        temp_fd, temp_path = tempfile.mkstemp(
            dir=str(state_file.parent), prefix="unlock_", suffix=".tmp"
        )
        with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(temp_path, state_file)
    except Exception:
        pass


class UnlockManager:
    """Manages temporary unlock grace windows backed by a durable on-disk file."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or get_default_data_dir()
        self.state_file = self.data_dir / "unlock_state.json"

    def get_state(self) -> Dict[str, Any]:
        """Read the state file fresh from disk on every call. No in-memory caching."""
        return read_unlock_state(self.state_file)

    def is_unlocked(self, is_away: bool = False) -> bool:
        """Check if unlock window is currently active. Always re-reads state file on every call."""
        state = self.get_state()
        now = time.time()
        unlocked_until = state["unlocked_until"]
        if now >= unlocked_until:
            return False

        if is_away:
            self.revoke(reason="OWNER_AWAY_DETECTED")
            return False

        return True

    def get_remaining_seconds(self) -> int:
        """Get seconds remaining on active unlock window."""
        state = self.get_state()
        now = time.time()
        remaining = int(state["unlocked_until"] - now)
        return max(0, remaining)

    def grant_unlock(self, user_name: str, duration_seconds: int = 120) -> Dict[str, Any]:
        """Grant an execution unlock window and persist atomically."""
        now = time.time()
        unlocked_until = now + duration_seconds
        state_data = {
            "unlocked_until": unlocked_until,
            "verified_at": now,
            "owner": user_name,
        }
        write_unlock_state_atomic(self.state_file, state_data)

        # Successful verification resets away-detection to PRESENT
        try:
            from core.away import PresenceMonitor
            pres = PresenceMonitor(data_dir=self.data_dir)
            pres.mark_seen(user_name=user_name)
        except Exception:
            pass

        audit = AuditLogger(data_dir=self.data_dir)
        audit.log_event(
            event_type="UNLOCK_GRANTED",
            user_name=user_name,
            action=f"Grant {duration_seconds}s execution window",
            result="UNLOCKED",
            details={"duration_seconds": duration_seconds, "expires_at": unlocked_until},
        )

        return {
            "unlocked": True,
            "duration_seconds": duration_seconds,
            "expires_at": unlocked_until,
            "owner": user_name,
        }

    def revoke(self, reason: str = "EXPIRED") -> None:
        """Revoke active unlock window immediately."""
        state = self.get_state()
        if state["unlocked_until"] > 0.0:
            audit = AuditLogger(data_dir=self.data_dir)
            audit.log_event(
                event_type="UNLOCK_REVOKED",
                user_name=state["owner"] or "System",
                action="Revoke execution window",
                result=reason,
                details={"reason": reason},
            )
        write_unlock_state_atomic(self.state_file, {
            "unlocked_until": 0.0,
            "verified_at": 0.0,
            "owner": "",
        })


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

