"""Settings and identity helpers shared by the hook, tools and CLIs.

Settings come from Hermes (plugins.entries.omnihermes.settings, declared in
plugin.yaml config_schema) when the plugin is loaded by Hermes, falling back to
config.json in the plugin data directory, then to built-in defaults. The model
cannot change any of these: config.json lives in a protected directory, and no
model-callable tool writes settings.
"""

from __future__ import annotations

import getpass
import json
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_UNLOCK_WINDOW_SECONDS = 120
MIN_UNLOCK_WINDOW_SECONDS = 10
MAX_UNLOCK_WINDOW_SECONDS = 3600

# Populated from the Hermes plugin context at register() time.
_hermes_ctx: Any = None


def bind_hermes_context(ctx: Any) -> None:
    global _hermes_ctx
    _hermes_ctx = ctx


def _from_hermes(key: str) -> Any:
    ctx = _hermes_ctx
    if ctx is None or not hasattr(ctx, "get_config"):
        return None
    try:
        return ctx.get_config(key)
    except Exception:
        return None


def _from_config_json(key: str, data_dir: Optional[Path]) -> Any:
    try:
        if data_dir is None:
            from omnihermes.models import get_default_data_dir
            data_dir = get_default_data_dir()
        cfg = Path(data_dir) / "config.json"
        if cfg.exists():
            return json.loads(cfg.read_text(encoding="utf-8")).get(key)
    except Exception:
        return None
    return None


def get_setting(key: str, default: Any = None, data_dir: Optional[Path] = None) -> Any:
    value = _from_hermes(key)
    if value is None:
        value = _from_config_json(key, data_dir)
    return default if value is None else value


def get_unlock_window_seconds(data_dir: Optional[Path] = None) -> int:
    """The configured unlock window, clamped to a sane range. Never chosen by the model."""
    raw = get_setting("unlock_window_seconds", DEFAULT_UNLOCK_WINDOW_SECONDS, data_dir=data_dir)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = DEFAULT_UNLOCK_WINDOW_SECONDS
    return max(MIN_UNLOCK_WINDOW_SECONDS, min(MAX_UNLOCK_WINDOW_SECONDS, value))


def get_enrolled_owner_name(data_dir: Optional[Path] = None) -> Optional[str]:
    """Name stored in the encrypted enrolled profile, or None if nobody is enrolled."""
    try:
        from omnihermes.biometrics import BiometricEngine
        engine = BiometricEngine(data_dir=data_dir)
        if not engine.is_enrolled():
            return None
        info = engine.get_owner_info() or {}
        name = str(info.get("owner_name") or "").strip()
        return name or None
    except Exception:
        return None


def default_owner_name() -> str:
    """Fallback display name for a new enrollment: the OS account name."""
    try:
        return getpass.getuser() or "Owner"
    except Exception:
        return "Owner"
