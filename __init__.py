"""Omnihermes: Biometric Presence & Face-Verified Security Gate for Hermes Agent.

Provides on-device biometric presence and face-verified authorization for high-risk actions.
Intercepts guarded tools via the `pre_tool_call` lifecycle hook.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from schemas import (
    OMNIHERMES_STATUS_SCHEMA,
    OMNIHERMES_ENROLL_SCHEMA,
    OMNIHERMES_CONFIGURE_SCHEMA,
    OMNIHERMES_AUDIT_LOGS_SCHEMA,
)
from tools import (
    handle_omnihermes_status,
    handle_omnihermes_enroll,
    handle_omnihermes_configure,
    handle_omnihermes_audit_logs,
    get_biometrics,
    get_policy,
    get_audit,
    get_presence,
)
from core.ui import BiometricAuthDialog


def on_pre_tool_call(**kwargs) -> Optional[Dict[str, Any]]:
    """Intercept tool executions before they dispatch.
    
    Evaluates risk and enforces physical biometric verification when necessary.
    """
    tool_name = kwargs.get("tool_name", "")
    arguments = kwargs.get("arguments", {})

    # Don't intercept Omnihermes management tools
    if tool_name.startswith("omnihermes_"):
        return {"action": "allow"}

    policy = get_policy()
    audit = get_audit()
    presence = get_presence()
    biometrics = get_biometrics()

    risk_assessment = policy.assess_risk(tool_name, arguments)
    if not risk_assessment["requires_biometric"]:
        return {"action": "allow"}

    risk_level = risk_assessment["risk_level"]
    action_summary = f"{tool_name} with params: {json.dumps(arguments, ensure_ascii=False)[:200]}"

    # Check 1: Away detection
    if presence.is_away():
        audit.log_event(
            event_type="INTERCEPT_BLOCKED",
            tool_name=tool_name,
            action_summary=action_summary,
            result="REJECTED_AWAY",
            confidence=0.0,
            liveness_score=0.0,
            details={"risk_level": risk_level, "reason": "Owner away from desk"},
        )
        return {
            "action": "block",
            "message": (
                f"🔒 [Omnihermes Intercept] Action '{tool_name}' ({risk_level} Risk) was paused: "
                f"Owner is away from the workstation. Biometric presence must be confirmed in person."
            ),
        }

    # Check 2: Profile enrollment
    if not biometrics.is_enrolled():
        audit.log_event(
            event_type="INTERCEPT_BLOCKED",
            tool_name=tool_name,
            action_summary=action_summary,
            result="REJECTED_NO_PROFILE",
            confidence=0.0,
            liveness_score=0.0,
            details={"risk_level": risk_level, "reason": "No enrolled biometric profile"},
        )
        return {
            "action": "block",
            "message": (
                f"🔒 [Omnihermes Intercept] Action '{tool_name}' ({risk_level} Risk) requires biometric approval, "
                f"but no owner profile is enrolled. Please run 'omnihermes_enroll' first."
            ),
        }

    # Check 3: Check cached presence mode (if enabled and within grace window)
    if policy.config.get("mode") == "cached_presence" and not presence.is_away():
        audit.log_event(
            event_type="INTERCEPT_APPROVED_CACHED",
            tool_name=tool_name,
            action_summary=action_summary,
            result="APPROVED_CACHED",
            confidence=1.0,
            liveness_score=1.0,
            details={"risk_level": risk_level},
        )
        return {"action": "allow"}

    # Check 4: Launch Biometric Challenge Dialog
    dialog = BiometricAuthDialog(
        tool_name=tool_name,
        action_summary=action_summary,
        risk_level=risk_level,
        engine=biometrics,
        timeout_seconds=20,
    )
    auth_result = dialog.run_dialog()

    if auth_result.get("approved"):
        presence.mark_seen(user_name=auth_result.get("owner_name", "Owner"))
        audit.log_event(
            event_type="INTERCEPT_APPROVED",
            tool_name=tool_name,
            action_summary=action_summary,
            result="APPROVED",
            confidence=auth_result.get("confidence", 1.0),
            liveness_score=auth_result.get("liveness_score", 1.0),
            details={"risk_level": risk_level},
        )
        return {"action": "allow"}
    else:
        reason = auth_result.get("reason", "VERIFICATION_FAILED")
        msg = auth_result.get("message", "Biometric verification failed.")
        audit.log_event(
            event_type="INTERCEPT_REJECTED",
            tool_name=tool_name,
            action_summary=action_summary,
            result=reason,
            confidence=auth_result.get("confidence", 0.0),
            liveness_score=auth_result.get("liveness_score", 0.0),
            details={"risk_level": risk_level, "message": msg},
        )
        return {
            "action": "block",
            "message": f"🔒 [Omnihermes Intercept] Biometric approval denied for '{tool_name}'. Reason: {msg}",
        }


def register(ctx):
    """Hermes Agent plugin registration entrypoint."""
    # Register tool handlers and schemas
    ctx.register_tool(OMNIHERMES_STATUS_SCHEMA, handle_omnihermes_status)
    ctx.register_tool(OMNIHERMES_ENROLL_SCHEMA, handle_omnihermes_enroll)
    ctx.register_tool(OMNIHERMES_CONFIGURE_SCHEMA, handle_omnihermes_configure)
    ctx.register_tool(OMNIHERMES_AUDIT_LOGS_SCHEMA, handle_omnihermes_audit_logs)

    # Register lifecycle pre_tool_call hook
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
