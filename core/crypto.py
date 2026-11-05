"""Cryptographic utilities for Omnihermes.

Ensures zero raw biometric images are stored on disk.
Face feature embeddings are encrypted with AES-256-GCM using a key derived from
the local machine identity and an optional user passphrase.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
from typing import Any, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def _get_machine_fingerprint() -> bytes:
    """Generate a consistent machine fingerprint for local key derivation."""
    raw = f"{platform.node()}-{platform.machine()}-{os.getenv('USERNAME', os.getenv('USER', 'default'))}"
    return raw.encode("utf-8")


def derive_key(salt: bytes, user_passphrase: str = "") -> bytes:
    """Derive a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    secret = _get_machine_fingerprint() + user_passphrase.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(secret)


def encrypt_payload(data: Dict[str, Any], user_passphrase: str = "") -> Dict[str, str]:
    """Encrypt a dictionary payload (e.g. embeddings) using AES-256-GCM.
    
    Returns base64 encoded salt, nonce, and ciphertext.
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(salt, user_passphrase)
    
    aesgcm = AESGCM(key)
    plaintext = json.dumps(data).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    return {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "version": "1.0",
    }


def decrypt_payload(encrypted_dict: Dict[str, str], user_passphrase: str = "") -> Dict[str, Any]:
    """Decrypt an encrypted dictionary payload."""
    salt = base64.b64decode(encrypted_dict["salt"])
    nonce = base64.b64decode(encrypted_dict["nonce"])
    ciphertext = base64.b64decode(encrypted_dict["ciphertext"])
    
    key = derive_key(salt, user_passphrase)
    aesgcm = AESGCM(key)
    
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))
