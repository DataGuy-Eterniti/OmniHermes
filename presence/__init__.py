"""Presence Gate: On-Device Biometric Presence & Face-Verified Security Gate.

Built for Hermes Agent.
"""

from presence.biometrics import BiometricEngine, DEFAULT_COSINE_THRESHOLD
from presence.liveness import LivenessSession
from presence.antispoof import AntiSpoofEngine, AntiSpoofSession
from presence.unlock import UnlockManager
from presence.audit import AuditLogger
from presence.crypto import encrypt_payload, decrypt_payload, get_or_generate_key
from presence.models import ensure_models, get_default_data_dir

__all__ = [
    "BiometricEngine",
    "LivenessSession",
    "AntiSpoofEngine",
    "AntiSpoofSession",
    "UnlockManager",
    "AuditLogger",
    "encrypt_payload",
    "decrypt_payload",
    "get_or_generate_key",
    "ensure_models",
    "get_default_data_dir",
    "DEFAULT_COSINE_THRESHOLD",
]

