"""Crypto utilities bridge to omnihermes package."""

try:
    from ..omnihermes.crypto import encrypt_payload, decrypt_payload, get_or_generate_key, derive_key
except (ImportError, ValueError):
    from omnihermes.crypto import encrypt_payload, decrypt_payload, get_or_generate_key, derive_key

__all__ = ["encrypt_payload", "decrypt_payload", "get_or_generate_key", "derive_key"]
