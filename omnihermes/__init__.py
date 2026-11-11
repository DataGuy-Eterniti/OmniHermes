"""OmniHermes: On-Device Biometric Presence & Face-Verified Security Gate.

Built for Hermes Agent. Uses lazy imports to guarantee instant plugin load (<50ms).
"""

from __future__ import annotations

import importlib
from typing import Any

_LAZY_EXPORTS = {
    "BiometricEngine": ("omnihermes.biometrics", "BiometricEngine"),
    "DEFAULT_COSINE_THRESHOLD": ("omnihermes.biometrics", "DEFAULT_COSINE_THRESHOLD"),
    "LivenessSession": ("omnihermes.liveness", "LivenessSession"),
    "AntiSpoofEngine": ("omnihermes.antispoof", "AntiSpoofEngine"),
    "AntiSpoofSession": ("omnihermes.antispoof", "AntiSpoofSession"),
    "UnlockManager": ("omnihermes.unlock", "UnlockManager"),
    "AuditLogger": ("omnihermes.audit", "AuditLogger"),
    "encrypt_payload": ("omnihermes.crypto", "encrypt_payload"),
    "decrypt_payload": ("omnihermes.crypto", "decrypt_payload"),
    "get_or_generate_key": ("omnihermes.crypto", "get_or_generate_key"),
    "ensure_models": ("omnihermes.models", "ensure_models"),
    "get_default_data_dir": ("omnihermes.models", "get_default_data_dir"),
    "assert_not_real_data_dir": ("omnihermes.models", "assert_not_real_data_dir"),
    "is_real_data_dir": ("omnihermes.models", "is_real_data_dir"),
    "reset_singletons": ("omnihermes.tools", "reset_singletons"),
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
