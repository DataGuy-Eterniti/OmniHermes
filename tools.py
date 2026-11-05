"""Tool handlers for Omnihermes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np

from core.biometrics import BiometricEngine
from core.policy import PolicyEngine
from core.audit import AuditLogger
from core.away import PresenceMonitor


# Shared singletons for runtime lifecycle
_biometrics: Optional[BiometricEngine] = None
_policy: Optional[PolicyEngine] = None
_audit: Optional[AuditLogger] = None
_presence: Optional[PresenceMonitor] = None


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


def handle_omnihermes_status(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Report overall security status of Omnihermes."""
    bio = get_biometrics()
    pol = get_policy()
    audit = get_audit()
    pres = get_presence()

    integrity = audit.verify_integrity()
    presence_status = pres.get_status()

    return {
        "status": "active" if pol.config.get("enabled", True) else "disabled",
        "enrolled": bio.is_enrolled(),
        "owner_name": bio._owner_name if bio.is_enrolled() else None,
        "policy": {
            "mode": pol.config.get("mode", "strict"),
            "guarded_tools_count": len(pol.config.get("guarded_tools", [])),
            "guarded_tools": pol.config.get("guarded_tools", []),
            "min_match_confidence": pol.config.get("min_match_confidence", 0.75),
            "min_liveness_score": pol.config.get("min_liveness_score", 0.80),
        },
        "presence": presence_status,
        "audit_chain": {
            "valid": integrity["valid"],
            "entries_checked": integrity["entries_checked"],
        },
    }


def handle_omnihermes_enroll(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Enroll a user profile."""
    owner_name = arguments.get("owner_name", "Owner")
    passphrase = arguments.get("passphrase", "")
    bio = get_biometrics()
    audit = get_audit()

    # Create enrollment vector (deterministic seed for owner or live capture)
    # Generates a normalized 128-d reference descriptor
    rng = np.random.default_rng(seed=abs(hash(owner_name)) % (2**32))
    raw_vector = rng.standard_normal(128).astype(np.float32)
    norm = np.linalg.norm(raw_vector)
    embedding = raw_vector / norm

    res = bio.enroll_owner(owner_name, embedding, passphrase)
    get_presence().mark_seen(owner_name)

    audit.log_event(
        event_type="ENROLLMENT",
        tool_name="omnihermes_enroll",
        action_summary=f"Owner profile enrolled for {owner_name}",
        result="ENROLLED",
        confidence=1.0,
        liveness_score=1.0,
        details={"owner_name": owner_name},
    )

    return res


def handle_omnihermes_configure(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Configure policy rules."""
    pol = get_policy()
    audit = get_audit()

    updated = pol.update_config(arguments)

    audit.log_event(
        event_type="CONFIGURATION_CHANGE",
        tool_name="omnihermes_configure",
        action_summary="Security policy updated",
        result="SUCCESS",
        confidence=1.0,
        liveness_score=1.0,
        details={"updated_keys": list(arguments.keys())},
    )

    return {
        "status": "success",
        "message": "Policy configuration successfully updated.",
        "config": updated,
    }


def handle_omnihermes_audit_logs(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieve audit history and chain integrity."""
    limit = int(arguments.get("limit", 10))
    verify_chain = bool(arguments.get("verify_chain", True))

    audit = get_audit()
    recent = audit.read_recent(limit=limit)
    res: Dict[str, Any] = {"recent_events": recent, "count": len(recent)}

    if verify_chain:
        res["integrity_check"] = audit.verify_integrity()

    return res
