"""Biometric engine bridge to omnihermes package."""

try:
    from ..omnihermes.biometrics import BiometricEngine, DEFAULT_COSINE_THRESHOLD
except (ImportError, ValueError):
    from omnihermes.biometrics import BiometricEngine, DEFAULT_COSINE_THRESHOLD

__all__ = ["BiometricEngine", "DEFAULT_COSINE_THRESHOLD"]
