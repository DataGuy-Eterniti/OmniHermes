"""Tool handlers for OmniHermes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

try:
    from .audit import AuditLogger
    from .unlock import UnlockManager
    from core.policy import PolicyEngine
    from core.away import PresenceMonitor
except (ImportError, ValueError):
    from omnihermes.audit import AuditLogger
    from omnihermes.unlock import UnlockManager
    from core.policy import PolicyEngine
    from core.away import PresenceMonitor

if TYPE_CHECKING:
    from omnihermes.biometrics import BiometricEngine


def run_enrollment(*args: Any, **kwargs: Any) -> bool:
    """Lazily import and invoke interactive camera enrollment."""
    from omnihermes.enroll import run_enrollment as _impl
    return _impl(*args, **kwargs)


def run_unlock_interactive(*args: Any, **kwargs: Any) -> bool:
    """Lazily import and invoke interactive camera unlock."""
    from omnihermes.unlock import run_unlock_interactive as _impl
    return _impl(*args, **kwargs)


# Shared singletons
_biometrics: Optional[BiometricEngine] = None
_policy: Optional[PolicyEngine] = None
_audit: Optional[AuditLogger] = None
_presence: Optional[PresenceMonitor] = None
_unlock_manager: Optional[UnlockManager] = None


def reset_singletons(data_dir: Optional[Path] = None) -> None:
    """Reset shared singletons. If data_dir is provided, binds all engines to it for isolated tests."""
    global _biometrics, _policy, _audit, _presence, _unlock_manager
    if data_dir is not None:
        from omnihermes.biometrics import BiometricEngine
        p = Path(data_dir)
        _biometrics = BiometricEngine(data_dir=p)
        _policy = PolicyEngine(config_path=p / "config.json", project_root=p)
        _audit = AuditLogger(data_dir=p)
        _presence = PresenceMonitor(timeout_seconds=45)
        _unlock_manager = UnlockManager(data_dir=p)
    else:
        _biometrics = None
        _policy = None
        _audit = None
        _presence = None
        _unlock_manager = None


def get_unlock_manager() -> UnlockManager:
    global _unlock_manager
    if _unlock_manager is None:
        _unlock_manager = UnlockManager()
    return _unlock_manager


def get_biometrics() -> BiometricEngine:
    global _biometrics
    if _biometrics is None:
        from omnihermes.biometrics import BiometricEngine
        _biometrics = BiometricEngine()
    return _biometrics


def get_policy() -> PolicyEngine:
    global _policy
    if _policy is None:
        _policy = PolicyEngine()
    return _policy


def get_audit() -> AuditLogger:
    global _audit
    if _audit is None:
        _audit = AuditLogger()
    return _audit


def get_presence() -> PresenceMonitor:
    global _presence
    if _presence is None:
        timeout = get_policy().config.get("away_timeout_seconds", 45)
        _presence = PresenceMonitor(timeout_seconds=timeout)
    return _presence


def handle_omnihermes_status(arguments: Dict[str, Any]) -> str:
    """Report overall security status of OmniHermes.
    
    Returns strictly lock state, time remaining, and owner name.
    Does not expose rules, patterns, or configuration details to the model.
    """
    bio = get_biometrics()
    pres = get_presence()
    unlock_mgr = get_unlock_manager()

    owner_name = "None"
    if bio.is_enrolled():
        owner_info = bio.get_owner_info()
        owner_name = owner_info.get("owner_name", "Unknown") if owner_info else "Unknown"

    unlocked = unlock_mgr.is_unlocked(is_away=pres.is_away())
    remaining_seconds = unlock_mgr.get_remaining_seconds() if unlocked else 0

    result = {
        "status": "unlocked" if unlocked else "locked",
        "locked": not unlocked,
        "unlocked": unlocked,
        "remaining_seconds": remaining_seconds,
        "owner_name": owner_name,
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


def handle_omnihermes_enroll(arguments: Dict[str, Any]) -> str:
    """Enroll an owner's face profile using webcam and active liveness."""
    owner_name = arguments.get("owner_name", "Elijah")
    is_primary = arguments.get("primary", True)
    test_embedding = arguments.get("test_embedding")

    if test_embedding is not None:
        import numpy as np
        bio = get_biometrics()
        bio.save_profile(owner_name, np.array(test_embedding, dtype=np.float32), is_primary=is_primary)
        get_presence().mark_seen(owner_name)
        result = {
            "status": "success",
            "message": f"Enrolled '{owner_name}' with provided test embedding (mock/test mode).",
        }
        return json.dumps(result, ensure_ascii=False, indent=2)

    try:
        success = run_enrollment(name=owner_name, is_primary=is_primary)
        if success:
            get_presence().mark_seen(owner_name)
            result = {
                "status": "success",
                "message": f"Successfully enrolled primary owner '{owner_name}' with encrypted SFace 128-d embedding.",
            }
        else:
            result = {
                "status": "error",
                "message": "Enrollment was cancelled or failed to capture 8 verified frames.",
            }
    except Exception as e:
        result = {
            "status": "error",
            "message": f"Webcam enrollment failed: {str(e)}. Run 'python -m omnihermes.enroll --name \"{owner_name}\" --primary' from terminal.",
        }
    return json.dumps(result, ensure_ascii=False, indent=2)


def handle_omnihermes_configure(arguments: Dict[str, Any]) -> str:
    """Configure policy rules."""
    pol = get_policy()
    audit = get_audit()

    updated = pol.update_config(arguments)

    audit.log_event(
        event_type="CONFIGURATION_CHANGE",
        user_name="PrimaryOwner",
        action="Security policy updated",
        result="SUCCESS",
        details={"updated_keys": list(arguments.keys())},
    )

    result = {
        "status": "success",
        "message": "Policy configuration successfully updated.",
        "config": updated,
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


def handle_omnihermes_audit_logs(arguments: Dict[str, Any]) -> str:
    """Retrieve audit history and chain integrity."""
    limit = int(arguments.get("limit", 10))
    verify_chain = bool(arguments.get("verify_chain", True))

    audit = get_audit()
    recent = []
    if audit.log_path.exists():
        with open(audit.log_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
            for line in lines[-limit:]:
                try:
                    recent.append(json.loads(line))
                except Exception:
                    pass

    res: Dict[str, Any] = {"recent_events": recent, "count": len(recent)}
    if verify_chain:
        res["integrity_check"] = audit.verify_integrity()

    return json.dumps(res, ensure_ascii=False, indent=2)


def handle_omnihermes_unlock(arguments: Dict[str, Any]) -> str:
    """Unlock workstation for temporary execution window."""
    duration = int(arguments.get("duration_seconds", 120))
    timeout = int(arguments.get("timeout_seconds", 300))
    try:
        success = run_unlock_interactive(timeout=timeout, duration=duration)
    except Exception as e:
        success = False
        reason = f"Error: {str(e)}"
    else:
        reason = "Biometric verification failed or was cancelled."

    if success:
        result = {
            "status": "success",
            "message": "OmniHermes: face verified. Risky actions are allowed for the next 120 seconds, then the gate locks again.",
            "unlocked": True,
            "duration_seconds": duration,
        }
    else:
        result = {
            "status": "failed",
            "message": "Biometric verification failed or was cancelled. Workstation remains locked.",
            "unlocked": False,
        }
    return json.dumps(result, ensure_ascii=False, indent=2)


# Compatibility aliases
handle_presence_status = handle_omnihermes_status
handle_presence_enroll = handle_omnihermes_enroll
handle_presence_configure = handle_omnihermes_configure
handle_presence_audit_logs = handle_omnihermes_audit_logs
handle_presence_unlock = handle_omnihermes_unlock
