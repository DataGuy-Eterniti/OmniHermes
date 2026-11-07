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

from omnihermes.models import ensure_models, get_default_data_dir


def crop_face_square(img: np.ndarray, bbox: Tuple[int, int, int, int], expansion: float = 1.5) -> np.ndarray:
    """Extract expanded square face crop matching facenox/face-antispoof-onnx exactly.
    
    Ensures RGB channel order, letterbox resize to 128x128, and reflection padding.
    """
    original_height, original_width = img.shape[:2]
    x, y, w, h = bbox

    # Ensure w and h are width and height, or x2, y2 coordinates
    if w > x and h > y and w > original_width * 0.1:
        # bbox passed as (x1, y1, x2, y2)
        bw = w - x
        bh = h - y
    else:
        bw = w
        bh = h

    if bw <= 0 or bh <= 0:
        return np.zeros((128, 128, 3), dtype=img.dtype)

    max_dim = max(bw, bh)
    center_x = x + bw / 2.0
    center_y = y + bh / 2.0

    crop_x = int(center_x - max_dim * expansion / 2.0)
    crop_y = int(center_y - max_dim * expansion / 2.0)
    crop_size = int(max_dim * expansion)

    crop_x1 = max(0, crop_x)
    crop_y1 = max(0, crop_y)
    crop_x2 = min(original_width, crop_x + crop_size)
    crop_y2 = min(original_height, crop_y + crop_size)

    top_pad = int(max(0, -crop_y))
    left_pad = int(max(0, -crop_x))
    bottom_pad = int(max(0, (crop_y + crop_size) - original_height))
    right_pad = int(max(0, (crop_x + crop_size) - original_width))

    if crop_x2 > crop_x1 and crop_y2 > crop_y1:
        cropped = img[crop_y1:crop_y2, crop_x1:crop_x2, :]
    else:
        cropped = np.zeros((0, 0, 3), dtype=img.dtype)

    result = cv2.copyMakeBorder(
        cropped,
        top_pad,
        bottom_pad,
        left_pad,
        right_pad,
        cv2.BORDER_REFLECT_101,
    )

    # Letterbox resize with reflection padding to 128x128
    old_size = result.shape[:2]
    if old_size[0] == 0 or old_size[1] == 0:
        return np.zeros((128, 128, 3), dtype=img.dtype)

    ratio = 128.0 / max(old_size)
    scaled_shape = (int(old_size[1] * ratio), int(old_size[0] * ratio))
    interpolation = cv2.INTER_LANCZOS4 if ratio > 1.0 else cv2.INTER_AREA
    resized = cv2.resize(result, scaled_shape, interpolation=interpolation)

    delta_w = 128 - scaled_shape[0]
    delta_h = 128 - scaled_shape[1]
    top, bottom = delta_h // 2, delta_h - (delta_h // 2)
    left, right = delta_w // 2, delta_w - (delta_w // 2)

    letterboxed = cv2.copyMakeBorder(resized, top, bottom, left, right, cv2.BORDER_REFLECT_101)
    return letterboxed


class AntiSpoofEngine:
    """Loads and executes MiniFASNetV2-SE via OpenCV DNN."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or get_default_data_dir()
        models = ensure_models(self.data_dir)
        model_path = str(models["minifasnet"])
        self.net = cv2.dnn.readNetFromONNX(model_path)

    def predict_crop(self, face_crop: np.ndarray) -> Tuple[float, float, bool]:
        """Predict whether a 128x128 face crop is a live human or spoof.
        
        Matches facenox/face-antispoof-onnx:
        - Output Index 0: Spoof Logit
        - Output Index 1: Real Logit
        
        Returns:
            (prob_real, logit_diff, is_spoof_frame)
        """
        blob = cv2.dnn.blobFromImage(
            face_crop,
            scalefactor=1.0 / 255.0,
            size=(128, 128),
            swapRB=False,  # RGB handled during crop/frame extraction
            crop=False,
        )
        self.net.setInput(blob)
        logits = self.net.forward()[0]
        # Reference mapping: logits[0] = Spoof, logits[1] = Real
        spoof_logit, real_logit = float(logits[0]), float(logits[1])
        logit_diff = real_logit - spoof_logit

        # Sigmoid / Softmax probability for Real class
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
        if len(frame.shape) == 3 and frame.shape[2] == 3:
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        else:
            frame_rgb = frame
        crop = crop_face_square(frame_rgb, bbox)
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

