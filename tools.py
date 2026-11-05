"""Tool handlers for Presence Gate / Omnihermes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np

from presence.audit import AuditLogger
from presence.biometrics import BiometricEngine
from presence.enroll import run_enrollment
from presence.unlock import UnlockManager, run_unlock_interactive
from core.policy import PolicyEngine
from core.away import PresenceMonitor


# Shared singletons
_biometrics: Optional[BiometricEngine] = None
_policy: Optional[PolicyEngine] = None
_audit: Optional[AuditLogger] = None
_presence: Optional[PresenceMonitor] = None
_unlock_manager: Optional[UnlockManager] = None


def get_unlock_manager() -> UnlockManager:
    global _unlock_manager
    if _unlock_manager is None:
        _unlock_manager = UnlockManager()
    return _unlock_manager


def get_biometrics() -> BiometricEngine:
    global _biometrics
    if _biometrics is None:
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


def handle_presence_status(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Report overall security status of Presence Gate."""
    bio = get_biometrics()
    pol = get_policy()
    audit = get_audit()
    pres = get_presence()

    integrity = audit.verify_integrity()
    presence_status = pres.get_status()
    owner_info = bio.get_owner_info() if bio.is_enrolled() else None

    return {
        "status": "active" if pol.config.get("enabled", True) else "disabled",
        "enrolled": bio.is_enrolled(),
        "owner_info": owner_info,
        "policy": {
            "mode": pol.config.get("mode", "strict"),
            "guarded_tools_count": len(pol.config.get("guarded_tools", [])),
            "guarded_tools": pol.config.get("guarded_tools", []),
            "min_match_confidence": bio.cosine_threshold,
            "min_liveness_score": pol.config.get("min_liveness_score", 0.80),
        },
        "presence": presence_status,
        "audit_chain": {
            "valid": integrity["valid"],
            "count": integrity.get("count", 0),
            "message": integrity.get("message", ""),
        },
    }


def handle_presence_enroll(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Enroll an owner's face profile using webcam and active liveness."""
    owner_name = arguments.get("owner_name", "Elijah")
    is_primary = arguments.get("primary", True)
    test_embedding = arguments.get("test_embedding")

    if test_embedding is not None:
        bio = get_biometrics()
        bio.save_profile(owner_name, np.array(test_embedding, dtype=np.float32), is_primary=is_primary)
        get_presence().mark_seen(owner_name)
        return {
            "status": "success",
            "message": f"Enrolled '{owner_name}' with provided test embedding (mock/test mode).",
        }

    try:
        success = run_enrollment(name=owner_name, is_primary=is_primary)
        if success:
            get_presence().mark_seen(owner_name)
            return {
                "status": "success",
                "message": f"Successfully enrolled primary owner '{owner_name}' with encrypted SFace 128-d embedding.",
            }
        else:
            return {
                "status": "error",
                "message": "Enrollment was cancelled or failed to capture 5 verified frames.",
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Webcam enrollment failed: {str(e)}. Run 'python -m presence.enroll --name \"{owner_name}\" --primary' from terminal.",
        }


def handle_presence_configure(arguments: Dict[str, Any]) -> Dict[str, Any]:
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

    return {
        "status": "success",
        "message": "Policy configuration successfully updated.",
        "config": updated,
    }


def handle_presence_audit_logs(arguments: Dict[str, Any]) -> Dict[str, Any]:
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

    return res


def handle_presence_unlock(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Unlock workstation for temporary execution window."""
    duration = int(arguments.get("duration_seconds", 120))
    success = run_unlock_interactive(timeout=300, duration=duration)
    if success:
        return {
            "status": "success",
            "message": f"Workstation unlocked. High-risk actions will execute without prompt for {duration} seconds.",
            "unlocked": True,
            "duration_seconds": duration,
        }
    return {
        "status": "failed",
        "message": "Biometric verification failed or was cancelled. Workstation remains locked.",
        "unlocked": False,
    }


# Backward compatibility aliases
handle_omnihermes_status = handle_presence_status
handle_omnihermes_enroll = handle_presence_enroll
handle_omnihermes_configure = handle_presence_configure
handle_omnihermes_audit_logs = handle_presence_audit_logs
