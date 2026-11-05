"""Biometric engine bridge to presence package."""

try:
    from ..presence.biometrics import BiometricEngine, DEFAULT_COSINE_THRESHOLD
except (ImportError, ValueError):
    from presence.biometrics import BiometricEngine, DEFAULT_COSINE_THRESHOLD

__all__ = ["BiometricEngine", "DEFAULT_COSINE_THRESHOLD"]
