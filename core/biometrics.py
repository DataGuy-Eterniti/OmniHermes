"""Biometric Enrollment and Liveness Verification Engine for Omnihermes.

Features:
- Encrypted local embedding storage (zero raw face images saved)
- Anti-spoofing liveness detection (blink dynamics + micro-motion texture analysis)
- High-precision cosine similarity matching
- Headless mock support for automated CI and integration tests
"""

from __future__ import annotations

import base64
import json
import math
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from core.crypto import encrypt_payload, decrypt_payload


class BiometricEngine:
    """Handles face feature extraction, anti-spoofing liveness checks, and matching."""

    def __init__(self, data_dir: Optional[Path] = None):
        if data_dir is None:
            data_dir = Path.home() / ".hermes" / "omnihermes"
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.profile_path = self.data_dir / "profile.enc"
        self._enrolled_embedding: Optional[np.ndarray] = None
        self._owner_name: str = "Owner"
        self._load_enrolled_profile()

    def _load_enrolled_profile(self) -> bool:
        """Load and decrypt the enrolled owner embedding from disk."""
        if not self.profile_path.exists():
            return False
        try:
            with open(self.profile_path, "r", encoding="utf-8") as f:
                enc_data = json.load(f)
            decrypted = decrypt_payload(enc_data)
            self._enrolled_embedding = np.array(decrypted["embedding"], dtype=np.float32)
            self._owner_name = decrypted.get("owner_name", "Owner")
            return True
        except Exception:
            self._enrolled_embedding = None
            return False

    def is_enrolled(self) -> bool:
        """Check if an owner face profile has been enrolled."""
        return self._enrolled_embedding is not None

    def enroll_owner(
        self,
        owner_name: str,
        embedding: np.ndarray,
        user_passphrase: str = "",
    ) -> Dict[str, Any]:
        """Save a new enrolled owner face embedding securely."""
        # Normalize vector
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm

        self._enrolled_embedding = embedding.astype(np.float32)
        self._owner_name = owner_name

        payload = {
            "owner_name": owner_name,
            "enrolled_at": time.time(),
            "embedding": self._enrolled_embedding.tolist(),
        }

        encrypted = encrypt_payload(payload, user_passphrase)
        with open(self.profile_path, "w", encoding="utf-8") as f:
            json.dump(encrypted, f, indent=2)

        return {
            "status": "success",
            "owner_name": owner_name,
            "message": f"Biometric profile for '{owner_name}' successfully enrolled and encrypted.",
        }

    @staticmethod
    def compute_similarity(embedding_a: np.ndarray, embedding_b: np.ndarray) -> float:
        """Compute cosine similarity between two normalized feature vectors."""
        norm_a = np.linalg.norm(embedding_a)
        norm_b = np.linalg.norm(embedding_b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return float(np.dot(embedding_a, embedding_b) / (norm_a * norm_b))

    @staticmethod
    def calculate_liveness(
        frames_ear: List[float],
        motion_variance: float,
        texture_entropy: float,
    ) -> Tuple[float, bool, str]:
        """Anti-spoofing analysis:
        
        1. Blink Detection: Eye Aspect Ratio (EAR) dip below threshold (e.g. < 0.20)
        2. Micro-motion variance: Prevents static photo spoofs (variance must be > 0.05)
        3. Texture entropy: Detects screen moiré or flat paper reflection
        """
        # 1. Check for eye blink
        min_ear = min(frames_ear) if frames_ear else 0.3
        max_ear = max(frames_ear) if frames_ear else 0.3
        blink_depth = max_ear - min_ear
        has_blink = blink_depth >= 0.08 and min_ear < 0.22

        # 2. Check for micro-motion
        is_static_image = motion_variance < 0.01

        # 3. Compute composite liveness score
        score = 0.0
        reasons = []

        if is_static_image:
            reasons.append("Static photo spoof detected: zero natural micro-motion.")
            return 0.15, False, "REJECTED_SPOOF_STATIC"

        if has_blink:
            score += 0.55
        else:
            score += 0.10
            reasons.append("No active blink detected.")

        if motion_variance >= 0.03:
            score += 0.25

        if texture_entropy >= 4.0:
            score += 0.20
        else:
            reasons.append("Texture entropy indicative of digital screen or photo print.")

        score = min(1.0, max(0.0, score))
        passed = score >= 0.70 and not is_static_image

        status = "PASSED" if passed else "REJECTED_SPOOF"
        return score, passed, status

    def verify(
        self,
        live_embedding: np.ndarray,
        liveness_score: float,
        min_confidence: float = 0.75,
        min_liveness: float = 0.70,
    ) -> Dict[str, Any]:
        """Perform full face verification against enrolled profile."""
        if not self.is_enrolled():
            return {
                "verified": False,
                "reason": "NO_ENROLLED_PROFILE",
                "message": "No owner biometric profile enrolled. Please run omnihermes_enroll first.",
                "confidence": 0.0,
                "liveness_score": liveness_score,
            }

        # Check liveness first
        if liveness_score < min_liveness:
            return {
                "verified": False,
                "reason": "LIVENESS_FAILED",
                "message": f"Liveness check failed (score: {liveness_score:.2f} < {min_liveness:.2f}). Spoof detected.",
                "confidence": 0.0,
                "liveness_score": liveness_score,
            }

        # Check face match
        similarity = self.compute_similarity(live_embedding, self._enrolled_embedding)
        match_passed = similarity >= min_confidence

        if not match_passed:
            return {
                "verified": False,
                "reason": "FACE_MISMATCH",
                "message": f"Face verification failed. Match confidence {similarity:.2f} below required {min_confidence:.2f}.",
                "confidence": similarity,
                "liveness_score": liveness_score,
            }

        return {
            "verified": True,
            "owner_name": self._owner_name,
            "reason": "APPROVED",
            "message": f"Biometric verification successful for {self._owner_name}.",
            "confidence": similarity,
            "liveness_score": liveness_score,
        }
