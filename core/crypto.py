"""Crypto utilities bridge to presence package."""

try:
    from ..presence.crypto import encrypt_payload, decrypt_payload, get_or_generate_key, derive_key
except (ImportError, ValueError):
    from presence.crypto import encrypt_payload, decrypt_payload, get_or_generate_key, derive_key

__all__ = ["encrypt_payload", "decrypt_payload", "get_or_generate_key", "derive_key"]
