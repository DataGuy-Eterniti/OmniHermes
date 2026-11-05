"""Passive Face Anti-Spoofing Engine (MiniFASNetV2-SE).

Runs on-device via cv2.dnn without external deep learning frameworks.
Defeats printed photos, digital screen replays, and cut-out masks.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np

from presence.models import ensure_models, get_default_data_dir


def crop_face_square(img: np.ndarray, bbox: Tuple[int, int, int, int], expansion: float = 1.5) -> np.ndarray:
    """Extract expanded square face crop with reflection padding, resized to 128x128."""
    x, y, w, h = bbox
    max_dim = max(w, h)
    cx, cy = x + w / 2.0, y + h / 2.0
    crop_sz = int(max_dim * expansion)
    x1 = int(cx - crop_sz / 2.0)
    y1 = int(cy - crop_sz / 2.0)

    H, W = img.shape[:2]
    top_pad = max(0, -y1)
    left_pad = max(0, -x1)
    bottom_pad = max(0, (y1 + crop_sz) - H)
    right_pad = max(0, (x1 + crop_sz) - W)

    cr = img[max(0, y1) : min(H, y1 + crop_sz), max(0, x1) : min(W, x1 + crop_sz)]
    if top_pad or bottom_pad or left_pad or right_pad:
        cr = cv2.copyMakeBorder(cr, top_pad, bottom_pad, left_pad, right_pad, cv2.BORDER_REFLECT_101)

    return cv2.resize(cr, (128, 128), interpolation=cv2.INTER_AREA)


class AntiSpoofEngine:
    """Loads and executes MiniFASNetV2-SE via OpenCV DNN."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or get_default_data_dir()
        models = ensure_models(self.data_dir)
        model_path = str(models["minifasnet"])
        self.net = cv2.dnn.readNetFromONNX(model_path)

    def predict_crop(self, face_crop: np.ndarray) -> Tuple[float, float, bool]:
        """Predict whether a 128x128 face crop is a live human or spoof.
        
        Returns:
            (prob_real, logit_diff, is_spoof_frame)
        """
        blob = cv2.dnn.blobFromImage(
            face_crop,
            scalefactor=1.0 / 255.0,
            size=(128, 128),
            swapRB=False,
            crop=False,
        )
        self.net.setInput(blob)
        logits = self.net.forward()[0]
        real_logit, spoof_logit = float(logits[0]), float(logits[1])
        logit_diff = real_logit - spoof_logit

        # Sigmoid probability
        prob_real = 1.0 / (1.0 + math.exp(-max(min(logit_diff, 15.0), -15.0)))
        is_spoof = prob_real < 0.50

        return float(prob_real), float(logit_diff), is_spoof


class AntiSpoofSession:
    """Accumulates passive anti-spoofing evaluations across multiple frames."""

    def __init__(
        self,
        engine: Optional[AntiSpoofEngine] = None,
        data_dir: Optional[Path] = None,
        real_threshold: float = 0.60,
        min_frames: int = 10,
        max_allowed_spoofs: int = 2,
    ):
        self.engine = engine or AntiSpoofEngine(data_dir=data_dir)
        self.real_threshold = real_threshold
        self.min_frames = min_frames
        self.max_allowed_spoofs = max_allowed_spoofs

        self.scores: List[float] = []
        self.spoof_flags: List[bool] = []

    def evaluate_frame(self, frame: np.ndarray, bbox: Tuple[int, int, int, int]) -> Dict[str, Any]:
        """Process one camera frame, crop face, and record anti-spoofing prediction."""
        crop = crop_face_square(frame, bbox)
        prob_real, logit_diff, is_spoof = self.engine.predict_crop(crop)

        self.scores.append(prob_real)
        self.spoof_flags.append(is_spoof)

        return {
            "prob_real": prob_real,
            "logit_diff": logit_diff,
            "is_spoof": is_spoof,
            "frames_analyzed": len(self.scores),
        }

    def get_summary(self) -> Dict[str, Any]:
        """Evaluate accumulated frames against anti-spoofing criteria."""
        total = len(self.scores)
        if total == 0:
            return {
                "passed": False,
                "avg_real_score": 0.0,
                "spoof_count": 0,
                "total_frames": 0,
                "reason": "No frames evaluated",
            }

        avg_real = sum(self.scores) / float(total)
        spoof_count = sum(1 for f in self.spoof_flags if f)

        # Check conditions
        has_enough_frames = total >= self.min_frames
        passes_avg = avg_real >= self.real_threshold
        passes_spoof_ceiling = spoof_count <= self.max_allowed_spoofs

        passed = has_enough_frames and passes_avg and passes_spoof_ceiling

        if not has_enough_frames:
            reason = f"Insufficient frames ({total}/{self.min_frames})"
        elif not passes_avg:
            reason = f"Average real score {avg_real:.4f} is below threshold {self.real_threshold:.4f}"
        elif not passes_spoof_ceiling:
            reason = f"Too many spoof frames detected ({spoof_count} > {self.max_allowed_spoofs})"
        else:
            reason = "PASSED"

        return {
            "passed": passed,
            "avg_real_score": round(avg_real, 4),
            "spoof_count": spoof_count,
            "total_frames": total,
            "threshold": self.real_threshold,
            "max_allowed_spoofs": self.max_allowed_spoofs,
            "reason": reason,
        }

