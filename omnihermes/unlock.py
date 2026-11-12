"""Unlock Window Manager and Standalone CLI for OmniHermes.

Allows the owner to perform biometric verification in a relaxed 5-minute window
and grants a temporary execution grace period for high-risk commands. The length
of that period comes from the `unlock_window_seconds` setting, never from the
model. Ends immediately if away-detection observes the owner leaving the desk.

The unlock state is shared between the Hermes CLI and gateway processes through
a file in the plugin data directory. Every state is HMAC-signed with a key that
only exists in that (protected) directory, so a file the model writes or copies
cannot unlock the gate: unsigned, mis-signed or over-long states read as locked.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from omnihermes.audit import AuditLogger
from omnihermes.crypto import sign_state, verify_state
from omnihermes.models import get_default_data_dir, assert_not_real_data_dir, write_private_file
from omnihermes.settings import get_enrolled_owner_name, get_unlock_window_seconds

STATE_VERSION = 2
CLOCK_SKEW_SECONDS = 5.0

_LOCKED: Dict[str, Any] = {"unlocked_until": 0.0, "verified_at": 0.0, "owner": "", "valid": False}


def _signed_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "v": STATE_VERSION,
        "unlocked_until": float(data.get("unlocked_until", 0.0)),
        "verified_at": float(data.get("verified_at", 0.0)),
        "owner": str(data.get("owner", "")),
    }


def read_unlock_state(state_file: Path, data_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Read and authenticate the unlock state. Anything not provably ours reads as locked."""
    data_dir = data_dir or state_file.parent
    if not state_file.exists():
        return dict(_LOCKED)
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        fields = _signed_fields(data)
        if data.get("v") != STATE_VERSION or not verify_state(fields, data.get("sig", ""), data_dir=data_dir):
            return dict(_LOCKED)

        now = time.time()
        max_window = get_unlock_window_seconds(data_dir=data_dir)
        # A genuine grant is never issued in the future and never longer than the configured window.
        if fields["verified_at"] > now + CLOCK_SKEW_SECONDS:
            return dict(_LOCKED)
        if fields["unlocked_until"] - fields["verified_at"] > max_window + CLOCK_SKEW_SECONDS:
            return dict(_LOCKED)

        return {
            "unlocked_until": fields["unlocked_until"],
            "verified_at": fields["verified_at"],
            "owner": fields["owner"],
            "valid": True,
        }
    except Exception:
        return dict(_LOCKED)


def write_unlock_state_atomic(state_file: Path, data: Dict[str, Any], data_dir: Optional[Path] = None) -> None:
    """Sign and write the unlock state atomically with mode 0600."""
    assert_not_real_data_dir(state_file, operation="save_unlock_state")
    data_dir = data_dir or state_file.parent
    fields = _signed_fields(data)
    record = dict(fields)
    record["sig"] = sign_state(fields, data_dir=data_dir)
    try:
        write_private_file(state_file, json.dumps(record, indent=2).encode("utf-8"))
    except Exception:
        pass


class UnlockManager:
    """Manages temporary unlock grace windows backed by a signed on-disk file."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or get_default_data_dir()
        self.state_file = self.data_dir / "unlock_state.json"

    def get_state(self) -> Dict[str, Any]:
        """Read and verify the state file fresh from disk on every call. No in-memory caching."""
        return read_unlock_state(self.state_file, data_dir=self.data_dir)

    def window_seconds(self) -> int:
        return get_unlock_window_seconds(data_dir=self.data_dir)

    def is_unlocked(self, is_away: bool = False) -> bool:
        """Check if unlock window is currently active. Always re-reads state file on every call."""
        state = self.get_state()
        if not state["valid"] or time.time() >= state["unlocked_until"]:
            return False

        if is_away:
            self.revoke(reason="OWNER_AWAY_DETECTED")
            return False

        return True

    def get_remaining_seconds(self) -> int:
        """Get seconds remaining on active unlock window."""
        state = self.get_state()
        if not state["valid"]:
            return 0
        return max(0, int(state["unlocked_until"] - time.time()))

    def grant_unlock(self, user_name: str, duration_seconds: Optional[int] = None) -> Dict[str, Any]:
        """Grant an execution unlock window and persist it, signed.

        The duration is the configured window. A caller may ask for less, never more.
        """
        window = self.window_seconds()
        duration = window if duration_seconds is None else max(1, min(int(duration_seconds), window))

        now = time.time()
        unlocked_until = now + duration
        write_unlock_state_atomic(
            self.state_file,
            {"unlocked_until": unlocked_until, "verified_at": now, "owner": user_name},
            data_dir=self.data_dir,
        )

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
            action=f"Grant {duration}s execution window",
            result="UNLOCKED",
            details={"duration_seconds": duration, "expires_at": unlocked_until},
        )

        return {
            "unlocked": True,
            "duration_seconds": duration,
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
        write_unlock_state_atomic(
            self.state_file,
            {"unlocked_until": 0.0, "verified_at": 0.0, "owner": ""},
            data_dir=self.data_dir,
        )


def run_unlock_interactive(timeout: int = 300, duration: Optional[int] = None, camera_idx: int = 0) -> Optional[int]:
    """Run interactive biometric unlock with a relaxed verification timeout.

    Returns the number of seconds actually granted, or None if verification failed.
    """
    from omnihermes.verify import run_verify
    from omnihermes.tools import get_presence

    manager = UnlockManager()
    window = manager.window_seconds()
    planned = window if duration is None else max(1, min(int(duration), window))

    print("=" * 60)
    print("OMNIHERMES: INTERACTIVE WORKSTATION UNLOCK")
    print(f"• Verification Timeout: {timeout}s")
    print(f"• Unlock Duration on Success: {planned}s")
    print("=" * 60)

    passed = run_verify(timeout=timeout, camera_idx=camera_idx)
    if not passed:
        print("\n[FAILED] Workstation unlock was not completed.")
        return None

    owner = get_enrolled_owner_name(manager.data_dir) or "Owner"
    res = manager.grant_unlock(owner, duration_seconds=planned)
    get_presence().mark_seen(owner)
    granted = int(res["duration_seconds"])

    print("\n" + "=" * 60)
    print("✔ WORKSTATION UNLOCKED SUCCESSFULLY!")
    print(f"• Execution Window: {granted} seconds active")
    print("• High-risk actions will proceed without biometric prompts")
    print("• Window ends early immediately if you step away from your desk")
    print("=" * 60)
    return granted


def main():
    parser = argparse.ArgumentParser(description="OmniHermes - Workstation Unlock")
    parser.add_argument("--timeout", type=int, default=300, help="Verification timeout in seconds (default: 300s)")
    parser.add_argument(
        "--duration", type=int, default=None,
        help="Unlock duration in seconds (default and maximum: the unlock_window_seconds setting)",
    )
    parser.add_argument("--camera", type=int, default=0, help="Camera device index (default: 0)")

    args = parser.parse_args()
    granted = run_unlock_interactive(timeout=args.timeout, duration=args.duration, camera_idx=args.camera)
    sys.exit(0 if granted else 1)


if __name__ == "__main__":
    main()
