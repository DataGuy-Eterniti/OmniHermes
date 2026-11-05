"""Presence Gate: On-Device Biometric Presence & Face-Verified Security Gate.

Intercepts high-risk operations via the `pre_tool_call` lifecycle hook.
Fails closed on any error, missing camera, missing enrollment, headless execution, or timeout.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional

# Ensure plugin directory is at the front of sys.path so plugin modules resolve before core names
_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if not sys.path or sys.path[0] != _PLUGIN_DIR:
    if _PLUGIN_DIR in sys.path:
        sys.path.remove(_PLUGIN_DIR)
    sys.path.insert(0, _PLUGIN_DIR)

try:
    from .schemas import (
        PRESENCE_STATUS_SCHEMA,
        PRESENCE_ENROLL_SCHEMA,
        PRESENCE_CONFIGURE_SCHEMA,
        PRESENCE_AUDIT_LOGS_SCHEMA,
        PRESENCE_UNLOCK_SCHEMA,
    )
    from .tools import (
        handle_presence_status,
        handle_presence_enroll,
        handle_presence_configure,
        handle_presence_audit_logs,
        handle_presence_unlock,
        get_biometrics,
        get_policy,
        get_audit,
        get_presence,
        get_unlock_manager,
    )
except (ImportError, ValueError):
    from schemas import (
        PRESENCE_STATUS_SCHEMA,
        PRESENCE_ENROLL_SCHEMA,
        PRESENCE_CONFIGURE_SCHEMA,
        PRESENCE_AUDIT_LOGS_SCHEMA,
        PRESENCE_UNLOCK_SCHEMA,
    )
    from tools import (
        handle_presence_status,
        handle_presence_enroll,
        handle_presence_configure,
        handle_presence_audit_logs,
        handle_presence_unlock,
        get_biometrics,
        get_policy,
        get_audit,
        get_presence,
        get_unlock_manager,
    )


def is_headless_or_gateway(kwargs: Dict[str, Any]) -> bool:
    """Detect if running in a headless, cron, Telegram, or gateway environment."""
    ctx = kwargs.get("context") or kwargs.get("ctx")
    if ctx is not None:
        if hasattr(ctx, "current_cron_execution") and ctx.current_cron_execution() is not None:
            return True
        if getattr(ctx, "is_headless", False):
            return True
        if getattr(ctx, "channel", "") in ["telegram", "discord", "slack", "gateway"]:
            return True

    if os.environ.get("HERMES_CRON") or os.environ.get("HERMES_HEADLESS"):
        return True
    if os.environ.get("HERMES_CHANNEL") in ["telegram", "discord", "slack", "gateway"]:
        return True

    # On POSIX, check DISPLAY
    if os.name != "nt" and not os.environ.get("DISPLAY"):
        return True

    return False


def on_pre_tool_call(**kwargs) -> Dict[str, Any]:
    """Intercept tool executions before they dispatch.
    
    Fail-closed: Returns {"action": "block", ...} on any exception, missing camera,
    missing enrollment, headless session, or decision timeout.
    """
    try:
        tool_name = kwargs.get("tool_name", "")
        arguments = kwargs.get("arguments", {})

        # Never intercept our own management tools
        if tool_name.startswith("presence_") or tool_name.startswith("omnihermes_"):
            return {"action": "allow"}

        policy = get_policy()
        audit = get_audit()
        presence = get_presence()
        biometrics = get_biometrics()
        unlock_mgr = get_unlock_manager()

        risk_assessment = policy.assess_risk(tool_name, arguments)
        if not risk_assessment["requires_biometric"]:
            return {"action": "allow"}

        risk_level = risk_assessment["risk_level"]
        action_summary = f"{tool_name} with params: {json.dumps(arguments, ensure_ascii=False)[:200]}"

        # 1. Check if running under cron, gateway, or headless environment (no physical display)
        if is_headless_or_gateway(kwargs):
            audit.log_event(
                event_type="INTERCEPT_BLOCKED",
                user_name="System",
                tool_name=tool_name,
                action_summary=action_summary,
                result="REJECTED_NO_DISPLAY",
                details={"reason": "Cron or headless environment"},
            )
            return {
                "action": "block",
                "message": "Presence: this action needs face verification at Elijah's computer.",
            }

        # 2. Check profile enrollment: fail-closed if no owner profile is enrolled
        if not biometrics.is_enrolled():
            audit.log_event(
                event_type="INTERCEPT_BLOCKED",
                user_name="Unenrolled",
                tool_name=tool_name,
                action_summary=action_summary,
                result="REJECTED_NO_PROFILE",
                details={"risk_level": risk_level, "reason": "No enrolled biometric profile"},
            )
            return {
                "action": "block",
                "message": (
                    f"Presence: action '{tool_name}' ({risk_level} Risk) requires face verification, "
                    f"but no owner profile is enrolled. Please run 'python -m presence.enroll --name \"Elijah\" --primary' to enroll."
                ),
            }

        # 3. Check active unlock grace window (ends early if owner is away)
        if unlock_mgr.is_unlocked(is_away=presence.is_away()):
            audit.log_event(
                event_type="INTERCEPT_APPROVED_UNLOCKED",
                user_name="PrimaryOwner",
                tool_name=tool_name,
                action_summary=action_summary,
                result="APPROVED_UNLOCKED",
                similarity_score=1.0,
                liveness_score=1.0,
                details={"risk_level": risk_level, "remaining_seconds": unlock_mgr.get_remaining_seconds()},
            )
            return {"action": "allow"}

        # 4. Desk away detection
        if presence.is_away():
            audit.log_event(
                event_type="INTERCEPT_BLOCKED",
                user_name="PrimaryOwner",
                tool_name=tool_name,
                action_summary=action_summary,
                result="REJECTED_AWAY",
                details={"risk_level": risk_level, "reason": "Owner away from desk"},
            )
            return {
                "action": "block",
                "message": (
                    f"Presence: action '{tool_name}' ({risk_level} Risk) was paused: "
                    f"workstation owner is away. Biometric presence must be confirmed in person."
                ),
            }

        # 5. Cached presence mode (if enabled and within grace window)
        if policy.config.get("mode") == "cached_presence" and not presence.is_away():
            audit.log_event(
                event_type="INTERCEPT_APPROVED_CACHED",
                user_name="PrimaryOwner",
                tool_name=tool_name,
                action_summary=action_summary,
                result="APPROVED_CACHED",
                similarity_score=1.0,
                liveness_score=1.0,
                details={"risk_level": risk_level},
            )
            return {"action": "allow"}

        # 6. Launch Biometric Challenge Dialog with strict internal timeout (22s < 25s)
        try:
            from .core.ui import BiometricAuthDialog
        except (ImportError, ValueError):
            from core.ui import BiometricAuthDialog

        dialog = BiometricAuthDialog(
            tool_name=tool_name,
            action_summary=action_summary,
            risk_level=risk_level,
            engine=biometrics,
            timeout_seconds=22,
        )
        auth_result = dialog.run_dialog()

        if auth_result.get("approved"):
            owner = auth_result.get("owner_name", "Elijah")
            presence.mark_seen(user_name=owner)
            audit.log_event(
                event_type="INTERCEPT_APPROVED",
                user_name=owner,
                tool_name=tool_name,
                action_summary=action_summary,
                result="APPROVED",
                similarity_score=auth_result.get("confidence", 1.0),
                liveness_score=auth_result.get("liveness_score", 1.0),
                details={"risk_level": risk_level},
            )
            return {"action": "allow"}
        else:
            reason = auth_result.get("reason", "VERIFICATION_FAILED")
            msg = auth_result.get("message", "Biometric verification failed.")

            audit.log_event(
                event_type="INTERCEPT_REJECTED",
                user_name="Candidate",
                tool_name=tool_name,
                action_summary=action_summary,
                result=reason,
                similarity_score=auth_result.get("confidence", 0.0),
                liveness_score=auth_result.get("liveness_score", 0.0),
                details={"risk_level": risk_level, "message": msg},
            )

            # If timed out, guide user to unlock flow
            if reason == "TIMEOUT":
                return {
                    "action": "block",
                    "message": "Presence: verify with /presence unlock, then ask me to retry.",
                }

            return {
                "action": "block",
                "message": f"Presence: face verification denied for '{tool_name}'. Reason: {msg}",
            }

    except Exception as e:
        # Ultimate fail-closed catch-all
        try:
            get_audit().log_event(
                event_type="INTERCEPT_EXCEPTION",
                user_name="System",
                tool_name=kwargs.get("tool_name", "unknown"),
                action_summary="Exception in hook",
                result="ERROR_BLOCKED",
                details={"exception": str(e)},
            )
        except Exception:
            pass

        return {
            "action": "block",
            "message": f"Presence: unexpected error during verification check ({str(e)}). Action blocked fail-closed.",
        }


def register(ctx: Any) -> None:
    """Hermes Agent plugin registration entrypoint."""
    # Register tool handlers and schemas
    ctx.register_tool(
        name="presence_status",
        toolset="presence-gate",
        schema=PRESENCE_STATUS_SCHEMA,
        handler=handle_presence_status,
    )
    ctx.register_tool(
        name="presence_enroll",
        toolset="presence-gate",
        schema=PRESENCE_ENROLL_SCHEMA,
        handler=handle_presence_enroll,
    )
    ctx.register_tool(
        name="presence_configure",
        toolset="presence-gate",
        schema=PRESENCE_CONFIGURE_SCHEMA,
        handler=handle_presence_configure,
    )
    ctx.register_tool(
        name="presence_audit_logs",
        toolset="presence-gate",
        schema=PRESENCE_AUDIT_LOGS_SCHEMA,
        handler=handle_presence_audit_logs,
    )
    ctx.register_tool(
        name="presence_unlock",
        toolset="presence-gate",
        schema=PRESENCE_UNLOCK_SCHEMA,
        handler=handle_presence_unlock,
    )

    # Register lifecycle hooks
    ctx.register_hook("pre_tool_call", on_pre_tool_call)

    # Secret retrieval if secret_scope available
    if hasattr(ctx, "agent") and hasattr(ctx.agent, "secret_scope"):
        secret = ctx.agent.secret_scope.get_secret("PRESENCE_ENCRYPTION_KEY")
        if secret:
            from presence.crypto import get_or_generate_key
            get_or_generate_key(explicit_key=secret)
