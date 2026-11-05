"""Real Face Detection & 128-d SFace Recognition Engine.

Uses official OpenCV YuNet (FaceDetectorYN) and SFace (FaceRecognizerSF).
Cosine similarity with OpenCV recommended SFace threshold (0.363).
Zero raw face images saved.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np

from presence.crypto import decrypt_payload, encrypt_payload
from presence.models import ensure_models, get_default_data_dir

# OpenCV recommended threshold for SFace cosine similarity is 0.363
DEFAULT_COSINE_THRESHOLD = 0.363


class BiometricEngine:
    """Manages YuNet face detection and SFace feature extraction."""

    def __init__(self, data_dir: Optional[Path] = None, cosine_threshold: float = DEFAULT_COSINE_THRESHOLD):
        self.data_dir = data_dir or get_default_data_dir()
        self.cosine_threshold = cosine_threshold
        self.profile_path = self.data_dir / "profile.enc"

        # Ensure ONNX model files are downloaded & verified
        self.models = ensure_models(self.data_dir)
        self.yunet_path = str(self.models["yunet"])
        self.sface_path = str(self.models["sface"])

        # Initialize OpenCV DNN models
        self.detector = cv2.FaceDetectorYN.create(
            self.yunet_path,
            "",
            (320, 320),
            score_threshold=0.6,
            nms_threshold=0.3,
            top_k=5000,
        )
        self.recognizer = cv2.FaceRecognizerSF.create(self.sface_path, "")

        self._enrolled_profile: Optional[Dict[str, Any]] = None
        self._load_profile()

    def _load_profile(self) -> bool:
        """Load and decrypt enrolled owner profile."""
        if not self.profile_path.exists():
            self._enrolled_profile = None
            return False
        try:
            with open(self.profile_path, "r", encoding="utf-8") as f:
                enc_data = json.load(f)
            decrypted = decrypt_payload(enc_data, data_dir=self.data_dir)
            decrypted["embedding"] = np.array(decrypted["embedding"], dtype=np.float32).reshape(1, 128)
            self._enrolled_profile = decrypted
            return True
        except Exception as e:
            print(f"[Presence] Warning: Failed to decrypt profile: {e}")
            self._enrolled_profile = None
            return False

    def is_enrolled(self) -> bool:
        """Check if an owner profile is currently enrolled."""
        return self._enrolled_profile is not None

    def get_owner_info(self) -> Optional[Dict[str, Any]]:
        """Return metadata for the currently enrolled owner."""
        if not self._enrolled_profile:
            return None
        return {
            "owner_name": self._enrolled_profile.get("owner_name", "Unknown"),
            "role": self._enrolled_profile.get("role", "PRIMARY_OWNER"),
            "is_primary": self._enrolled_profile.get("is_primary", True),
            "created_at": self._enrolled_profile.get("created_at", 0),
            "model": self._enrolled_profile.get("model", "sface_2021dec"),
        }

    def detect_faces(self, frame: np.ndarray) -> List[np.ndarray]:
        """Detect faces in frame using YuNet."""
        h, w = frame.shape[:2]
        self.detector.setInputSize((w, h))
        ret, faces = self.detector.detect(frame)
        if faces is None or len(faces) == 0:
            return []
        # Sort by bounding box area (largest face first)
        faces_list = [f for f in faces]
        faces_list.sort(key=lambda f: f[2] * f[3], reverse=True)
        return faces_list

    def extract_embedding(self, frame: np.ndarray, face: np.ndarray) -> np.ndarray:
        """Crop, align, and extract 128-d normalized embedding using SFace."""
        aligned = self.recognizer.alignCrop(frame, face)
        embedding = self.recognizer.feature(aligned)
        # Normalize to unit length
        norm = np.linalg.norm(embedding)
        if norm > 1e-6:
            embedding = embedding / norm
        return embedding.astype(np.float32)

    def compute_similarity(self, emb1: np.ndarray, emb2: np.ndarray) -> float:
        """Compute cosine similarity between two 128-d embeddings."""
        emb1 = emb1.reshape(1, 128).astype(np.float32)
        emb2 = emb2.reshape(1, 128).astype(np.float32)
        score = self.recognizer.match(emb1, emb2, cv2.FaceRecognizerSF_FR_COSINE)
        return float(score)

    def match_against_owner(self, candidate_emb: np.ndarray) -> Tuple[bool, float]:
        """Compare candidate embedding against the enrolled owner."""
        if not self._enrolled_profile:
            return False, 0.0
        owner_emb = self._enrolled_profile["embedding"]
        score = self.compute_similarity(candidate_emb, owner_emb)
        passed = score >= self.cosine_threshold
        return passed, score

    def save_profile(self, owner_name: str, embedding: np.ndarray, is_primary: bool = True) -> Dict[str, Any]:
        """Encrypt and save the owner profile."""
        norm_emb = embedding.reshape(1, 128).astype(np.float32)
        norm = np.linalg.norm(norm_emb)
        if norm > 1e-6:
            norm_emb = norm_emb / norm

        profile_data = {
            "owner_name": owner_name,
            "role": "PRIMARY_OWNER" if is_primary else "MEMBER",
            "is_primary": is_primary,
            "created_at": Path().stat().st_ctime if Path().exists() else 0,
            "model": "sface_2021dec",
            "embedding_dim": 128,
            "embedding": norm_emb.flatten().tolist(),
        }

        enc = encrypt_payload(profile_data, data_dir=self.data_dir)
        self.profile_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.profile_path, "w", encoding="utf-8") as f:
            json.dump(enc, f, indent=2)

        self._load_profile()
        return profile_data

    def enroll_owner(self, owner_name: str, embedding: np.ndarray, passphrase: str = "") -> Dict[str, Any]:
        """Convenience method to enroll an owner embedding."""
        self.save_profile(owner_name, embedding, is_primary=True)
        return {"status": "success", "owner_name": owner_name}

    def verify(self, candidate_emb: np.ndarray, liveness_score: float = 1.0) -> Dict[str, Any]:
        """Verify candidate embedding and liveness score against enrolled profile."""
        matched, score = self.match_against_owner(candidate_emb)
        verified = matched and liveness_score >= 0.80
        reason = "VERIFIED" if verified else ("FACE_MISMATCH" if not matched else "LIVENESS_FAILED")
        return {
            "verified": verified,
            "confidence": score,
            "liveness_score": liveness_score,
            "reason": reason,
        }

    @classmethod
    def calculate_liveness(
        cls,
        frames_ear: Optional[List[float]] = None,
        motion_variance: float = 0.0,
        texture_entropy: float = 0.0,
        **kwargs: Any,
    ) -> Tuple[float, bool, str]:
        """Diagnostic helper for evaluating liveness scores."""
        frames = frames_ear or []
        has_blink = any(e < 0.20 for e in frames) if frames else False
        is_live = has_blink and motion_variance > 0.02 and texture_entropy > 3.0

        if not is_live and motion_variance < 0.01:
            return 0.12, False, "REJECTED_SPOOF_STATIC"
        elif is_live:
            return 0.95, True, "PASSED"
        else:
            return 0.45, False, "REJECTED_INCONCLUSIVE"


