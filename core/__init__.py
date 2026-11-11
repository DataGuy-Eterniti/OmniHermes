"""Omnihermes core modules. Uses lazy imports to avoid loading heavy CV deps at import time."""

from __future__ import annotations

import importlib
from typing import Any

_LAZY_EXPORTS = {
    "encrypt_payload": ("core.crypto", "encrypt_payload"),
    "decrypt_payload": ("core.crypto", "decrypt_payload"),
    "AuditLogger": ("core.audit", "AuditLogger"),
    "PolicyEngine": ("core.policy", "PolicyEngine"),
    "BiometricEngine": ("core.biometrics", "BiometricEngine"),
    "PresenceMonitor": ("core.away", "PresenceMonitor"),
}

__all__ = list(_LAZY_EXPORTS.keys())


def __getattr__(name: str) -> Any:
    if name in _LAZY_EXPORTS:
        module_path, attr_name = _LAZY_EXPORTS[name]
        mod = importlib.import_module(module_path)
        val = getattr(mod, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
