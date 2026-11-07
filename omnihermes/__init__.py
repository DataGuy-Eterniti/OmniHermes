"""OmniHermes: On-Device Biometric Presence & Face-Verified Security Gate.

Built for Hermes Agent.
"""

from omnihermes.biometrics import BiometricEngine, DEFAULT_COSINE_THRESHOLD
from omnihermes.liveness import LivenessSession
from omnihermes.antispoof import AntiSpoofEngine, AntiSpoofSession
from omnihermes.unlock import UnlockManager
from omnihermes.audit import AuditLogger
from omnihermes.crypto import encrypt_payload, decrypt_payload, get_or_generate_key
from omnihermes.models import ensure_models, get_default_data_dir

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

