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

try:
    from omnihermes.settings import bind_hermes_context, get_enrolled_owner_name, default_owner_name
    from omnihermes.models import get_default_data_dir
except (ImportError, ValueError):
    from .omnihermes.settings import bind_hermes_context, get_enrolled_owner_name, default_owner_name
    from .omnihermes.models import get_default_data_dir

# Only these model-callable tools skip the gate. Anything else named omnihermes_* is gated like any tool.
_OWN_TOOLS = frozenset({"omnihermes_status", "omnihermes_unlock"})

BLOCK_MESSAGE = "OmniHermes: this action needs face verification. Run /omnihermes unlock, then ask me to retry."
PROTECTED_BLOCK_MESSAGE = "OmniHermes: this action is not permitted."


# Optional override (tests); by default the log lives in the plugin data directory.
DEBUG_LOG_PATH: Optional[Path] = None


def _debug_log_path() -> Path:
    if DEBUG_LOG_PATH is not None:
        Path(DEBUG_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        return Path(DEBUG_LOG_PATH)
    try:
        return get_default_data_dir() / "hook_debug.log"
    except Exception:
        return Path(os.devnull)


def is_debug_logging_enabled() -> bool:
    """Check if debug logging is enabled via environment or config. Off by default."""
    if os.environ.get("OMNIHERMES_DEBUG") in ("1", "true", "True") or os.environ.get("OMNIHERMES_TEST_MODE") == "1":
        return True
    try:
        policy = get_policy()
        return bool(policy.config.get("debug_logging", False))
    except Exception:
        return False


def log_hook_telemetry(
    tool: str,
    decision: str,
    state_file: Any,
    unlocked_until: float,
    now: float,
    seconds_left: float,
    away_status: str,
) -> None:
    """Log structured hook telemetry line per user requirement:
    tool, decision, state file path, unlocked_until, now, seconds left, away status.
    """
    if not is_debug_logging_enabled():
        return
    try:
        log_path = _debug_log_path()
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        pid = os.getpid()
        clean_state_file = str(state_file).replace("\\", "/")
        line = (
            f"[{ts}] [PID:{pid}] tool='{tool}' decision='{decision}' "
            f"state_file='{clean_state_file}' unlocked_until={unlocked_until:.2f} "
            f"now={now:.2f} seconds_left={seconds_left:.1f} away_status='{away_status}'\n"
        )
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def log_hook_debug(
    tool_name: str,
    summary: str,
    risk_decision: str,
    display_detected: bool,
    return_value: Dict[str, Any],
) -> None:
    """Append one debug line to hook_debug.log on every hook invocation. Never logs face data."""
    if not is_debug_logging_enabled():
        return
    try:
        log_path = _debug_log_path()
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
        with open(log_path, "a", encoding="utf-8") as f:
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

    now_ts = time.time()
    unlocked_until_ts = 0.0
    seconds_left = 0.0
    away_status = "UNKNOWN"
    state_file_path: Any = "unlock_state.json"

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

        # Never intercept our own two model-callable tools (exact names only)
        if tool_name in _OWN_TOOLS:
            risk_decision = "MANAGEMENT_TOOL"
            return_val = {"action": "allow"}
            return return_val

        policy = get_policy()
        audit = get_audit()
        presence = get_presence()
        biometrics = get_biometrics()
        unlock_mgr = get_unlock_manager()

        # Re-read unlock state fresh from disk on every call (zero in-memory caching)
        unlock_state = unlock_mgr.get_state()
        state_file_path = unlock_mgr.state_file
        now_ts = time.time()
        unlocked_until_ts = float(unlock_state.get("unlocked_until", 0.0))
        seconds_left = max(0.0, unlocked_until_ts - now_ts)
        is_away = presence.is_away()
        away_status = "AWAY" if is_away else "PRESENT"

        risk_assessment = policy.assess_risk(tool_name, arguments)
        if not risk_assessment["requires_biometric"]:
            risk_decision = "LOW_RISK"
            return_val = {"action": "allow"}
            return return_val

        risk_level = risk_assessment["risk_level"]
        risk_decision = f"{risk_level}_RISK"
        action_summary = f"{tool_name} with params: {json.dumps(arguments, ensure_ascii=False)[:200]}"

        # 0. The gate's own files are never touched by the model: no unlock window,
        #    no cached presence and no face check can authorise it.
        if risk_assessment.get("protected"):
            risk_decision = "PROTECTED_STATE"
            audit.log_event(
                event_type="INTERCEPT_BLOCKED",
                user_name="System",
                tool_name=tool_name,
                action_summary=action_summary,
                result="REJECTED_PROTECTED_STATE",
                details={"risk_level": risk_level},
            )
            return_val = {"action": "block", "message": PROTECTED_BLOCK_MESSAGE}
            return return_val

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
                "message": "OmniHermes: this action needs face verification. Run /omnihermes unlock, then ask me to retry.",
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
                    f"but no owner profile is enrolled. The owner should run /omnihermes enroll (or python -m omnihermes.enroll)."
                ),
            }
            return return_val

        # 3. Check active unlock grace window (ends early if owner is confirmed away)
        # Durable disk file check re-evaluated on every call
        if unlock_mgr.is_unlocked(is_away=is_away):
            rem_s = unlock_mgr.get_remaining_seconds()
            log_msg = f"allowed: unlock window active, {rem_s} s left"
            risk_decision = log_msg
            audit.log_event(
                event_type="INTERCEPT_APPROVED_UNLOCKED",
                user_name=unlock_state.get("owner", "PrimaryOwner"),
                tool_name=tool_name,
                action_summary=action_summary,
                result="APPROVED_UNLOCKED",
                similarity_score=1.0,
                liveness_score=1.0,
                details={"risk_level": risk_level, "remaining_seconds": rem_s, "message": log_msg},
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
                "message": "OmniHermes: this action needs face verification. Run /omnihermes unlock, then ask me to retry.",
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

        # 6. Locked: block immediately. The camera is never opened from inside a tool call:
        #    loading models and showing a window can outlast Hermes's hook timeout (and the
        #    gateway process may have no visible desktop), which would stall every later call.
        #    The owner verifies with /omnihermes unlock, which grants the configured window.
        audit.log_event(
            event_type="INTERCEPT_BLOCKED",
            user_name="System",
            tool_name=tool_name,
            action_summary=action_summary,
            result="REJECTED_LOCKED",
            details={"risk_level": risk_level},
        )
        return_val = {"action": "block", "message": BLOCK_MESSAGE}
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
            "message": "OmniHermes: unexpected error during verification check. Action blocked fail-closed.",
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
        log_hook_telemetry(
            tool=tool_name,
            decision=return_val.get("action", "unknown"),
            state_file=state_file_path,
            unlocked_until=unlocked_until_ts,
            now=now_ts,
            seconds_left=seconds_left,
            away_status=away_status,
        )


def handle_omnihermes_slash_command(raw_args: str = "", **kwargs: Any) -> str:
    """Hermes Agent slash command handler for /omnihermes."""
    cmd = (raw_args or "").strip().lower()
    subcmd = cmd.split()[0] if cmd else "status"

    if subcmd == "status":
        raw_res = handle_omnihermes_status({})
        res = json.loads(raw_res) if isinstance(raw_res, str) else raw_res
        owner_name = res.get("owner_name", "None")
        unlocked = res.get("unlocked", False)
        rem = res.get("remaining_seconds", 0)
        lock_state = f"Unlocked ({rem}s remaining)" if unlocked else "Locked"

        lines = [
            "🛡️ OmniHermes Security Gate Status:",
            f"• Gate State: {lock_state}",
            f"• Time Remaining: {rem}s" if unlocked else "• Time Remaining: 0s",
            f"• Enrolled Owner: {owner_name}",
        ]
        return "\n".join(lines)

    elif subcmd == "unlock":
        from omnihermes.unlock import run_unlock_interactive
        try:
            granted = run_unlock_interactive(timeout=300)
        except Exception:
            return "OmniHermes: Biometric unlock failed."
        if granted:
            return (
                f"OmniHermes: face verified. Risky actions are allowed for the next {int(granted)} seconds, "
                "then the gate locks again."
            )
        return "OmniHermes: Biometric unlock failed or was cancelled."

    elif subcmd == "enroll":
        from omnihermes.enroll import run_enrollment
        # /omnihermes enroll [name]  -> name given, else the currently enrolled name, else the OS user name
        original = (raw_args or "").strip().split(None, 1)
        name = original[1].strip() if len(original) > 1 else (get_enrolled_owner_name() or default_owner_name())
        try:
            success = run_enrollment(name=name, is_primary=True, replace=True)
        except Exception as e:
            return f"OmniHermes: Enrollment failed: {str(e)}"
        if success:
            return "OmniHermes: Biometric enrollment completed successfully."
        return "OmniHermes: Biometric enrollment failed or was cancelled."

    else:
        return (
            "OmniHermes Biometric Security Gate:\n"
            "Usage:\n"
            "  /omnihermes status  - View enrolled profile, unlock window, and audit status\n"
            "  /omnihermes unlock  - Launch face verification to unlock risky actions for the configured window\n"
            "  /omnihermes enroll [name] - Launch camera enrollment to register the primary owner\n"
        )


def register(ctx: Any) -> None:
    """Hermes Agent plugin registration entrypoint."""
    # Settings (unlock_window_seconds etc.) are read from Hermes's plugin settings when available.
    bind_hermes_context(ctx)
    # Register tool handlers exposed to the model (only status and unlock; agent cannot modify its own gate)
    ctx.register_tool(
        name="omnihermes_status",
        toolset="omnihermes",
        schema=OMNIHERMES_STATUS_SCHEMA,
        handler=handle_omnihermes_status,
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
            args_hint="[status|unlock|enroll [name]]",
        )
        ctx.register_command(
            name="presence",
            handler=handle_omnihermes_slash_command,
            description="Alias for /omnihermes biometric security gate commands",
            args_hint="[status|unlock|enroll]",
        )

    # Register lifecycle hooks
    ctx.register_hook("pre_tool_call", on_pre_tool_call)

    # Record registration build timestamp to hook_debug.log (when debug_logging enabled)
    if is_debug_logging_enabled():
        try:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            pid = os.getpid()
            with open(_debug_log_path(), "a", encoding="utf-8") as f:
                f.write(f"[{ts}] [PID:{pid}] OmniHermes plugin v1.1.0 registered in process\n")
        except Exception:
            pass

    # Secret retrieval if secret_scope available
    if hasattr(ctx, "agent") and hasattr(ctx.agent, "secret_scope"):
        secret = ctx.agent.secret_scope.get_secret("OMNIHERMES_ENCRYPTION_KEY")
        if secret:
            from omnihermes.crypto import get_or_generate_key
            get_or_generate_key(explicit_key=secret)
