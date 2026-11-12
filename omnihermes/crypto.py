"""AES-256-GCM encryption for face embeddings.

No raw face images are ever stored on disk. Only encrypted 128-d vectors.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from omnihermes.models import get_default_data_dir, assert_not_real_data_dir, write_private_file


def derive_key(salt: bytes, user_passphrase: str = "") -> bytes:
    """Derive a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(user_passphrase.encode("utf-8"))


def get_or_generate_key(data_dir: Optional[Path] = None, explicit_key: Optional[str] = None) -> bytes:
    """Retrieve or generate a 256-bit AES key.
    
    Does NOT use OS keychain or credential store. Key is stored locally in plugin data dir.
    """
    if explicit_key:
        if len(explicit_key) == 32:
            return explicit_key.encode("utf-8")
        try:
            decoded = base64.b64decode(explicit_key)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        import hashlib
        return hashlib.sha256(explicit_key.encode("utf-8")).digest()

    base_dir = data_dir or get_default_data_dir()
    key_file = base_dir / ".secret_key"
    if key_file.exists():
        try:
            os.chmod(key_file, 0o600)  # tighten keys created by older versions
        except OSError:
            pass
        key_data = key_file.read_bytes()
        if len(key_data) == 32:
            return key_data
        # If it was text-encoded or had trailing whitespace/newlines
        stripped = key_data.strip()
        if len(stripped) == 32:
            return stripped
        try:
            decoded = base64.b64decode(stripped)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass

    # Generate new random 256-bit key
    assert_not_real_data_dir(key_file, operation="generate_secret_key")
    new_key = os.urandom(32)
    write_private_file(key_file, new_key)
    return new_key


def _state_mac_key(data_dir: Optional[Path] = None) -> bytes:
    """Derive a dedicated HMAC key for signing gate state from the local secret key."""
    base = get_or_generate_key(data_dir=data_dir)
    return hmac.new(base, b"omnihermes/unlock-state/v2", hashlib.sha256).digest()


def sign_state(fields: Dict[str, Any], data_dir: Optional[Path] = None) -> str:
    """Return a hex HMAC-SHA256 over the canonical JSON of the given fields."""
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(_state_mac_key(data_dir), payload, hashlib.sha256).hexdigest()


def verify_state(fields: Dict[str, Any], signature: str, data_dir: Optional[Path] = None) -> bool:
    """Constant-time check that a state signature was produced with the local key."""
    if not signature or not isinstance(signature, str):
        return False
    try:
        return hmac.compare_digest(sign_state(fields, data_dir=data_dir), signature)
    except Exception:
        return False


def encrypt_payload(
    data: Dict[str, Any],
    data_dir: Optional[Path] = None,
    key: Optional[bytes] = None,
    user_passphrase: str = "",
) -> Dict[str, str]:
    """Encrypt dictionary data using AES-256-GCM."""
    salt = os.urandom(16)
    if user_passphrase:
        aes_key = derive_key(salt, user_passphrase)
    else:
        aes_key = key or get_or_generate_key(data_dir=data_dir)

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    plaintext = json.dumps(data).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "version": "1.0",
    }


def decrypt_payload(
    encrypted_dict: Dict[str, str],
    data_dir: Optional[Path] = None,
    key: Optional[bytes] = None,
    user_passphrase: str = "",
) -> Dict[str, Any]:
    """Decrypt dictionary data using AES-256-GCM."""
    salt = base64.b64decode(encrypted_dict.get("salt", "")) if "salt" in encrypted_dict else b""
    if user_passphrase and salt:
        aes_key = derive_key(salt, user_passphrase)
    else:
        aes_key = key or get_or_generate_key(data_dir=data_dir)

    aesgcm = AESGCM(aes_key)
    nonce = base64.b64decode(encrypted_dict["nonce"])
    ciphertext = base64.b64decode(encrypted_dict["ciphertext"])

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))

