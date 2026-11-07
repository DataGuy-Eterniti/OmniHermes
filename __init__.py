"""OmniHermes: On-Device Biometric Presence & Face-Verified Security Gate.

Intercepts high-risk operations via the `pre_tool_call` lifecycle hook.
Fails closed on any error, missing camera, missing enrollment, headless execution, or timeout.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

# Ensure plugin directory is at the front of sys.path so plugin modules resolve before core names
_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if not sys.path or sys.path[0] != _PLUGIN_DIR:
    if _PLUGIN_DIR in sys.path:
        sys.path.remove(_PLUGIN_DIR)
    sys.path.insert(0, _PLUGIN_DIR)

try:
    from omnihermes.schemas import (
        OMNIHERMES_STATUS_SCHEMA,
        OMNIHERMES_ENROLL_SCHEMA,
        OMNIHERMES_CONFIGURE_SCHEMA,
        OMNIHERMES_AUDIT_LOGS_SCHEMA,
        OMNIHERMES_UNLOCK_SCHEMA,
        PRESENCE_STATUS_SCHEMA,
        PRESENCE_ENROLL_SCHEMA,
        PRESENCE_CONFIGURE_SCHEMA,
        PRESENCE_AUDIT_LOGS_SCHEMA,
        PRESENCE_UNLOCK_SCHEMA,
    )
    from omnihermes.tools import (
        handle_omnihermes_status,
        handle_omnihermes_enroll,
        handle_omnihermes_configure,
        handle_omnihermes_audit_logs,
        handle_omnihermes_unlock,
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
    from .omnihermes.schemas import (
        OMNIHERMES_STATUS_SCHEMA,
        OMNIHERMES_ENROLL_SCHEMA,
        OMNIHERMES_CONFIGURE_SCHEMA,
        OMNIHERMES_AUDIT_LOGS_SCHEMA,
        OMNIHERMES_UNLOCK_SCHEMA,
        PRESENCE_STATUS_SCHEMA,
        PRESENCE_ENROLL_SCHEMA,
        PRESENCE_CONFIGURE_SCHEMA,
        PRESENCE_AUDIT_LOGS_SCHEMA,
        PRESENCE_UNLOCK_SCHEMA,
    )
    from .omnihermes.tools import (
        handle_omnihermes_status,
        handle_omnihermes_enroll,
        handle_omnihermes_configure,
        handle_omnihermes_audit_logs,
        handle_omnihermes_unlock,
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

DEBUG_LOG_PATH = Path.home() / ".hermes" / "omnihermes" / "hook_debug.log"


def log_hook_debug(
    tool_name: str,
    summary: str,
    risk_decision: str,
    display_detected: bool,
    return_value: Dict[str, Any],
) -> None:
    """Append one debug line to hook_debug.log on every hook invocation. Never logs face data."""
    try:
        DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        pid = os.getpid()
        clean_summary = summary.replace("\n", " ").replace("\r", "")[:150]
        line = (
            f"[{ts}] [PID:{pid}] tool='{tool_name}' "
            f"summary='{clean_summary}' "
            f"risk='{risk_decision}' "
            f"display_detected={display_detected} "
            f"return={json.dumps(return_value, ensure_ascii=False)}\n"
        )
        with open(DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


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


def is_display_detected(kwargs: Dict[str, Any]) -> bool:
    """Return whether an interactive desktop display is available for UI dialogs."""
    return not is_headless_or_gateway(kwargs)


def on_pre_tool_call(tool_name: str = "", args: Any = None, task_id: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """Intercept tool executions before they dispatch.
    
    Fail-closed: Returns {"action": "block", ...} on any exception, missing camera,
    missing enrollment, headless session, or decision timeout.
    """
    cmd_summary = f"{tool_name} with params: {str(args)[:120]}"
    risk_decision = "UNKNOWN"
    display_detected = False
    return_val: Dict[str, Any] = {"action": "block", "message": "OmniHermes: unhandled security check."}

    try:
        raw_args = args if args is not None else kwargs.get("arguments") or kwargs.get("function_args")
        if isinstance(raw_args, dict):
            arguments = dict(raw_args)
        elif isinstance(raw_args, str):
            arguments = {"command": raw_args}
        elif isinstance(raw_args, (list, tuple)):
            arguments = {"args": list(raw_args), "command": " ".join(str(x) for x in raw_args)}
        else:
            arguments = {}
        for k in ("command", "cmd", "script", "code", "input"):
            if k in kwargs and k not in arguments:
                arguments[k] = kwargs[k]

        display_detected = is_display_detected(kwargs)
        cmd_summary = f"{tool_name} with params: {json.dumps(arguments, ensure_ascii=False)[:120]}"

        # Never intercept our own management tools
        if tool_name.startswith("omnihermes_") or tool_name.startswith("presence_"):
            risk_decision = "MANAGEMENT_TOOL"
            return_val = {"action": "allow"}
            return return_val

        policy = get_policy()
        audit = get_audit()
        presence = get_presence()
        biometrics = get_biometrics()
        unlock_mgr = get_unlock_manager()

        risk_assessment = policy.assess_risk(tool_name, arguments)
        if not risk_assessment["requires_biometric"]:
            risk_decision = "LOW_RISK"
            return_val = {"action": "allow"}
            return return_val

        risk_level = risk_assessment["risk_level"]
        risk_decision = f"{risk_level}_RISK"
        action_summary = f"{tool_name} with params: {json.dumps(arguments, ensure_ascii=False)[:200]}"

        # 1. Check if running under cron, gateway, or headless environment (no physical display)
        if not display_detected:
            audit.log_event(
                event_type="INTERCEPT_BLOCKED",
                user_name="System",
                tool_name=tool_name,
                action_summary=action_summary,
                result="REJECTED_NO_DISPLAY",
                details={"reason": "Cron or headless environment"},
            )
            return_val = {
                "action": "block",
                "message": "OmniHermes: verify with /omnihermes unlock, then ask me to retry.",
            }
            return return_val

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
            return_val = {
                "action": "block",
                "message": (
                    f"OmniHermes: action '{tool_name}' ({risk_level} Risk) requires face verification, "
                    f"but no owner profile is enrolled. Please run 'python -m omnihermes.enroll --name \"Elijah\" --primary' to enroll."
                ),
            }
            return return_val

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
            return_val = {"action": "allow"}
            return return_val

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
            return_val = {
                "action": "block",
                "message": (
                    f"OmniHermes: action '{tool_name}' ({risk_level} Risk) was paused: "
                    f"workstation owner is away. OmniHermes: verify with /omnihermes unlock, then ask me to retry."
                ),
            }
            return return_val

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
            return_val = {"action": "allow"}
            return return_val

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
            return_val = {"action": "allow"}
            return return_val
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

            # If timed out or user cancelled, guide user to unlock flow
            if reason in ["TIMEOUT", "USER_REJECTED", "HEADLESS_OR_NO_DISPLAY", "NO_DISPLAY_FOUND"]:
                return_val = {
                    "action": "block",
                    "message": "OmniHermes: verify with /omnihermes unlock, then ask me to retry.",
                }
                return return_val

            return_val = {
                "action": "block",
                "message": f"OmniHermes: face verification denied for '{tool_name}'. Reason: {msg}",
            }
            return return_val

    except Exception as e:
        # Ultimate fail-closed catch-all
        try:
            get_audit().log_event(
                event_type="INTERCEPT_EXCEPTION",
                user_name="System",
                tool_name=tool_name or "unknown",
                action_summary=cmd_summary,
                result="ERROR_BLOCKED",
                details={"exception": str(e)},
            )
        except Exception:
            pass

        return_val = {
            "action": "block",
            "message": f"OmniHermes: unexpected error during verification check ({str(e)}). Action blocked fail-closed.",
        }
        return return_val

    finally:
        log_hook_debug(
            tool_name=tool_name,
            summary=cmd_summary,
            risk_decision=risk_decision,
            display_detected=display_detected,
            return_value=return_val,
        )


def handle_omnihermes_slash_command(raw_args: str = "", **kwargs: Any) -> str:
    """Hermes Agent slash command handler for /omnihermes."""
    cmd = (raw_args or "").strip().lower()
    subcmd = cmd.split()[0] if cmd else "status"

    if subcmd == "status":
        res = handle_omnihermes_status({})
        enrolled = res.get("enrolled", False)
        owner_name = res.get("owner_info", {}).get("owner_name", "None") if enrolled else "None"
        policy_mode = res.get("policy", {}).get("mode", "strict")
        unlocked = res.get("unlock_window", {}).get("unlocked", False)
        rem = res.get("unlock_window", {}).get("remaining_seconds", 0)
        audit_valid = res.get("audit_chain", {}).get("valid", False)
        audit_count = res.get("audit_chain", {}).get("count", 0)

        lines = [
            "🛡️ OmniHermes Security Gate Status:",
            f"• Enrolled Owner: {owner_name} (Enrolled: {enrolled})",
            f"• Policy Mode: {policy_mode}",
            f"• Execution Window: {'ACTIVE (' + str(rem) + 's remaining)' if unlocked else 'Locked'}",
            f"• Cryptographic Audit Chain: {'VERIFIED ✔' if audit_valid else 'INVALID ✖'} ({audit_count} entries)",
        ]
        return "\n".join(lines)

    elif subcmd == "unlock":
        from omnihermes.unlock import run_unlock_interactive
        success = run_unlock_interactive(timeout=300, duration=120)
        if success:
            return "✔ OmniHermes: Workstation unlocked for 120 seconds. Risky commands will execute without prompt."
        return "✖ OmniHermes: Biometric unlock failed or was cancelled."

    elif subcmd == "enroll":
        from omnihermes.enroll import run_enrollment
        success = run_enrollment(name="Elijah", is_primary=True)
        if success:
            return "✔ OmniHermes: Biometric enrollment completed successfully."
        return "✖ OmniHermes: Biometric enrollment failed or was cancelled."

    else:
        return (
            "OmniHermes Biometric Security Gate:\n"
            "Usage:\n"
            "  /omnihermes status  - View enrolled profile, unlock window, and audit status\n"
            "  /omnihermes unlock  - Launch face verification dialog to unlock workstation (2 mins)\n"
            "  /omnihermes enroll  - Launch camera enrollment to register primary owner\n"
        )


def register(ctx: Any) -> None:
    """Hermes Agent plugin registration entrypoint."""
    # Register tool handlers and schemas
    ctx.register_tool(
        name="omnihermes_status",
        toolset="omnihermes",
        schema=OMNIHERMES_STATUS_SCHEMA,
        handler=handle_omnihermes_status,
    )
    ctx.register_tool(
        name="omnihermes_enroll",
        toolset="omnihermes",
        schema=OMNIHERMES_ENROLL_SCHEMA,
        handler=handle_omnihermes_enroll,
    )
    ctx.register_tool(
        name="omnihermes_configure",
        toolset="omnihermes",
        schema=OMNIHERMES_CONFIGURE_SCHEMA,
        handler=handle_omnihermes_configure,
    )
    ctx.register_tool(
        name="omnihermes_audit_logs",
        toolset="omnihermes",
        schema=OMNIHERMES_AUDIT_LOGS_SCHEMA,
        handler=handle_omnihermes_audit_logs,
    )
    ctx.register_tool(
        name="omnihermes_unlock",
        toolset="omnihermes",
        schema=OMNIHERMES_UNLOCK_SCHEMA,
        handler=handle_omnihermes_unlock,
    )

    # Register slash command /omnihermes and alias /presence
    if hasattr(ctx, "register_command"):
        ctx.register_command(
            name="omnihermes",
            handler=handle_omnihermes_slash_command,
            description="OmniHermes biometric security gate commands",
            args_hint="[status|unlock|enroll]",
        )
        ctx.register_command(
            name="presence",
            handler=handle_omnihermes_slash_command,
            description="Alias for /omnihermes biometric security gate commands",
            args_hint="[status|unlock|enroll]",
        )

    # Register lifecycle hooks
    ctx.register_hook("pre_tool_call", on_pre_tool_call)

    # Record registration build timestamp to hook_debug.log
    try:
        DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        pid = os.getpid()
        with open(DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [PID:{pid}] OmniHermes plugin v1.0.0 (build 2026-11-07.0848) registered in process\n")
    except Exception:
        pass

    # Secret retrieval if secret_scope available
    if hasattr(ctx, "agent") and hasattr(ctx.agent, "secret_scope"):
        secret = ctx.agent.secret_scope.get_secret("OMNIHERMES_ENCRYPTION_KEY")
        if secret:
            from omnihermes.crypto import get_or_generate_key
            get_or_generate_key(explicit_key=secret)
