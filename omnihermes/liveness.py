"""Real Liveness Engine with Passive MiniFASNet Anti-Spoofing and 3D Parallax Consistency.

Defeats:
1. Static photos (MiniFASNet + mandatory blink verification)
2. Screen/video replays (unpredictable two-challenge sequence)
3. Rotated flat photo attacks (3D non-planar parallax consistency check)
"""

from __future__ import annotations

import collections
import math
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import cv2
import mediapipe as mp
import numpy as np
from mediapipe.tasks import python as mp_python
from mediapipe.tasks.python import vision

from omnihermes.antispoof import AntiSpoofEngine, AntiSpoofSession
from omnihermes.models import ensure_models, get_default_data_dir


def euclidean_dist(p1: Tuple[float, float], p2: Tuple[float, float]) -> float:
    return math.hypot(p1[0] - p2[0], p1[1] - p2[1])


def calculate_ear(landmarks: Any, eye_indices: List[int], img_w: int, img_h: int) -> float:
    """Calculate Eye Aspect Ratio (EAR) given 6 landmark indices."""
    pts = [(landmarks[idx].x * img_w, landmarks[idx].y * img_h) for idx in eye_indices]
    v1 = euclidean_dist(pts[1], pts[5])
    v2 = euclidean_dist(pts[2], pts[4])
    h = euclidean_dist(pts[0], pts[3])
    if h < 1e-4:
        return 0.0
    return (v1 + v2) / (2.0 * h)


MODEL_3D_POINTS = np.array([
    (0.0, 0.0, 0.0),             # Nose tip (1)
    (0.0, -330.0, -65.0),        # Chin (152)
    (-225.0, 170.0, -135.0),     # Right eye outer (33)
    (225.0, 170.0, -135.0),      # Left eye outer (263)
    (-150.0, -150.0, -125.0),    # Right mouth corner (61)
    (150.0, -150.0, -125.0),     # Left mouth corner (291)
], dtype=np.float64)


def estimate_head_pose(landmarks: Any, img_w: int, img_h: int) -> Tuple[float, float, float]:
    """Estimate head pose (pitch, yaw, roll) in degrees using cv2.solvePnP."""
    indices = [1, 152, 33, 263, 61, 291]
    image_points = np.array([
        (landmarks[idx].x * img_w, landmarks[idx].y * img_h) for idx in indices
    ], dtype=np.float64)

    focal_length = float(img_w)
    center = (img_w / 2.0, img_h / 2.0)
    camera_matrix = np.array([
        [focal_length, 0, center[0]],
        [0, focal_length, center[1]],
        [0, 0, 1],
    ], dtype=np.float64)
    dist_coeffs = np.zeros((4, 1), dtype=np.float64)

    success, rvec, _ = cv2.solvePnP(
        MODEL_3D_POINTS, image_points, camera_matrix, dist_coeffs, flags=cv2.SOLVEPNP_ITERATIVE
    )
    if not success:
        return 0.0, 0.0, 0.0

    rmat, _ = cv2.Rodrigues(rvec)
    angles, _, _, _, _, _ = cv2.RQDecomp3x3(rmat)
    pitch, yaw, roll = angles[0], angles[1], angles[2]
    if yaw > 90:
        yaw = yaw - 180
    elif yaw < -90:
        yaw = yaw + 180
    return float(pitch), float(yaw), float(roll)


SECONDARY_CHALLENGES = ["turn_left", "turn_right", "nod_down"]
CHALLENGE_PROMPTS = {
    "blink_twice": "Step 1 of 2: Blink twice",
    "turn_left": "Step 2 of 2: Turn head left",
    "turn_right": "Step 2 of 2: Turn head right",
    "nod_down": "Step 2 of 2: Nod head down",
}

# Detection thresholds relative to user's personalized baseline
ANGLE_THRESHOLD_DEG = 8.5       # 8.5 degrees change from baseline
NOD_ANGLE_THRESHOLD_DEG = 8.0   # 8.0 degrees pitch change from baseline
RATIO_THRESHOLD = 0.035         # Equivalent facial landmark ratio change
PARALLAX_MIN_THRESHOLD = 0.025  # True 3D depth differential (flat photos produce ~0.000)


class LivenessSession:
    """Two-challenge active liveness session with baseline relative measurement."""

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        secondary_challenge: Optional[str] = None,
        antispoof_engine: Optional[AntiSpoofEngine] = None,
    ):
        self.data_dir = data_dir or get_default_data_dir()
        models = ensure_models(self.data_dir)
        task_path = str(models["face_landmarker"])

        base_options = mp_python.BaseOptions(model_asset_path=task_path)
        options = vision.FaceLandmarkerOptions(
            base_options=base_options,
            running_mode=vision.RunningMode.IMAGE,
            num_faces=1,
            output_face_blendshapes=True,
        )
        self.landmarker = vision.FaceLandmarker.create_from_options(options)

        # Passive MiniFASNet anti-spoofing session
        self.antispoof = AntiSpoofSession(
            engine=antispoof_engine,
            data_dir=self.data_dir,
            real_threshold=0.60,
            min_frames=10,
            max_allowed_spoofs=2,
        )

        # Sequence configuration
        self.challenge_1 = "blink_twice"
        self.challenge_2 = secondary_challenge or random.choice(SECONDARY_CHALLENGES)
        self.current_phase = 1  # 1 = blink_twice, 2 = challenge_2, 3 = completed

        # Blink tracking
        self.blink_count = 0
        self.eye_closed = False
        self.min_ear_observed = 1.0
        self.last_ear = 0.30

        # Baseline tracking (calibrated per-user at challenge start)
        self.phase2_start_time: Optional[float] = None
        self.baseline_frames: List[Tuple[float, float, float, float]] = []
        self.baseline_established = False
        self.baseline_yaw: Optional[float] = None
        self.baseline_pitch: Optional[float] = None
        self.baseline_turn_ratio: Optional[float] = None
        self.baseline_nod_ratio: Optional[float] = None

        # Challenge 2 timing and retry handling (15 seconds per challenge)
        self.challenge_duration = 15.0
        self.challenge_retries = 0
        self.max_retries = 2
        self.challenge_failed = False

        # Movement and parallax tracking
        self.hold_frames = 0
        self.head_movement_reached = False
        self.parallax_passed = False
        self.max_parallax_shift: float = 0.0
        self.turn_progress = 0.0

        # Rolling history for smoothing (3-5 frames)
        self.frames_analyzed = 0
        self.yaw_history = collections.deque(maxlen=5)
        self.pitch_history = collections.deque(maxlen=5)
        self.turn_ratio_history = collections.deque(maxlen=5)
        self.nod_ratio_history = collections.deque(maxlen=5)

        self.smoothed_yaw = 0.0
        self.smoothed_pitch = 0.0
        self.smoothed_turn_ratio = 0.50
        self.smoothed_nod_ratio = 0.45

    @property
    def neutral_ratio_baseline(self) -> Optional[float]:
        return self.baseline_turn_ratio

    @neutral_ratio_baseline.setter
    def neutral_ratio_baseline(self, val: Optional[float]) -> None:
        self.baseline_turn_ratio = val

    @property
    def current_prompt(self) -> str:
        if self.current_phase == 1:
            return CHALLENGE_PROMPTS["blink_twice"]
        elif self.current_phase == 2:
            return CHALLENGE_PROMPTS.get(self.challenge_2, "Step 2 of 2: Follow prompt")
        return "Checking face match..."

    def process_frame(self, frame_bgr: np.ndarray) -> Dict[str, Any]:
        """Process one camera frame for passive spoof score, blinks, and relative movement."""
        h, w = frame_bgr.shape[:2]
        rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
        mp_img = mp.Image(image_format=mp.ImageFormat.SRGB, data=rgb)
        result = self.landmarker.detect(mp_img)

        if not result.face_landmarks or len(result.face_landmarks) == 0:
            return {
                "face_detected": False,
                "completed": False,
                "current_phase": self.current_phase,
                "prompt": self.current_prompt,
                "liveness_score": 0.0,
                "message": "No face detected in camera view",
            }

        self.frames_analyzed += 1
        landmarks = result.face_landmarks[0]

        # 1. Bounding box computation for MiniFASNet (x1, y1, x2, y2)
        xs = [l.x * w for l in landmarks]
        ys = [l.y * h for l in landmarks]
        min_x, max_x = max(0, int(min(xs))), min(w, int(max(xs)))
        min_y, max_y = max(0, int(min(ys))), min(h, int(max(ys)))
        bbox = (min_x, min_y, max_x, max_y)

        # 2. Passive anti-spoof evaluation (sample across frames)
        if self.frames_analyzed % 2 == 0 or len(self.antispoof.scores) < 10:
            self.antispoof.evaluate_frame(frame_bgr, bbox)

        # 3. Eye Aspect Ratio (EAR) computation
        left_eye_indices = [362, 385, 387, 263, 373, 380]
        right_eye_indices = [33, 160, 158, 133, 153, 144]
        ear_left = calculate_ear(landmarks, left_eye_indices, w, h)
        ear_right = calculate_ear(landmarks, right_eye_indices, w, h)
        avg_ear = (ear_left + ear_right) / 2.0
        self.last_ear = avg_ear
        self.min_ear_observed = min(self.min_ear_observed, avg_ear)

        # 4. Blink detection state machine
        if avg_ear < 0.18:
            self.eye_closed = True
        elif avg_ear > 0.22 and self.eye_closed:
            self.blink_count += 1
            self.eye_closed = False

        # Transition to Phase 2
        if self.current_phase == 1 and self.blink_count >= 2:
            self.current_phase = 2
            self.phase2_start_time = time.time()
            self.baseline_frames = []
            self.baseline_established = False

        if self.current_phase == 2 and self.phase2_start_time is None:
            self.phase2_start_time = time.time()

        # 5. Extract raw angles and simple landmark ratios
        pitch, yaw, roll = estimate_head_pose(landmarks, w, h)

        # Horizontal turn ratio: nose tip (1) relative to outer eye corners (33, 263)
        x_nose = landmarks[1].x
        x_right_eye = landmarks[33].x
        x_left_eye = landmarks[263].x
        eye_span = abs(x_left_eye - x_right_eye)
        if eye_span > 1e-4:
            turn_ratio = (x_nose - min(x_right_eye, x_left_eye)) / eye_span
        else:
            turn_ratio = 0.50

        # Vertical nod ratio: nose tip (1) relative to eye line and chin (152)
        y_nose = landmarks[1].y
        y_eye_line = (landmarks[33].y + landmarks[263].y) / 2.0
        y_chin = landmarks[152].y
        face_span = y_chin - y_eye_line
        if face_span > 1e-4:
            nod_ratio = (y_nose - y_eye_line) / face_span
        else:
            nod_ratio = 0.45

        # Update smoothing queues (3-5 frames)
        self.yaw_history.append(yaw)
        self.pitch_history.append(pitch)
        self.turn_ratio_history.append(turn_ratio)
        self.nod_ratio_history.append(nod_ratio)

        self.smoothed_yaw = float(np.mean(self.yaw_history))
        self.smoothed_pitch = float(np.mean(self.pitch_history))
        self.smoothed_turn_ratio = float(np.mean(self.turn_ratio_history))
        self.smoothed_nod_ratio = float(np.mean(self.nod_ratio_history))

        # Calibrate baseline from first ~10 frames of Phase 2
        if self.current_phase == 2:
            if not self.baseline_established:
                self.baseline_frames.append((
                    self.smoothed_yaw,
                    self.smoothed_pitch,
                    self.smoothed_turn_ratio,
                    self.smoothed_nod_ratio,
                ))
                self.baseline_yaw = float(np.mean([f[0] for f in self.baseline_frames]))
                self.baseline_pitch = float(np.mean([f[1] for f in self.baseline_frames]))
                self.baseline_turn_ratio = float(np.mean([f[2] for f in self.baseline_frames]))
                self.baseline_nod_ratio = float(np.mean([f[3] for f in self.baseline_frames]))
                if len(self.baseline_frames) >= 10:
                    self.baseline_established = True

        base_yaw = self.baseline_yaw if self.baseline_yaw is not None else self.smoothed_yaw
        base_pitch = self.baseline_pitch if self.baseline_pitch is not None else self.smoothed_pitch
        base_turn_r = self.baseline_turn_ratio if self.baseline_turn_ratio is not None else self.smoothed_turn_ratio
        base_nod_r = self.baseline_nod_ratio if self.baseline_nod_ratio is not None else self.smoothed_nod_ratio

        # Measure relative change from user's own starting position
        delta_yaw = self.smoothed_yaw - base_yaw
        delta_pitch = self.smoothed_pitch - base_pitch
        delta_turn_ratio = self.smoothed_turn_ratio - base_turn_r
        delta_nod_ratio = self.smoothed_nod_ratio - base_nod_r

        # Parallax tracking (differential horizontal displacement vs baseline)
        shift = abs(self.smoothed_turn_ratio - base_turn_r)
        self.max_parallax_shift = max(self.max_parallax_shift, shift)

        angle_met = False
        ratio_met = False
        progress = 0.0
        time_in_challenge = (time.time() - self.phase2_start_time) if self.phase2_start_time else 0.0

        # Phase 2 Challenge Detection
        if self.current_phase == 2:
            # 15-second timeout and retry with different challenge
            if time_in_challenge > self.challenge_duration and not self.head_movement_reached:
                if self.challenge_retries < self.max_retries:
                    self.challenge_retries += 1
                    prev_c = self.challenge_2
                    candidates = [c for c in SECONDARY_CHALLENGES if c != prev_c]
                    self.challenge_2 = random.choice(candidates)
                    self.phase2_start_time = time.time()
                    self.baseline_frames = []
                    self.baseline_established = False
                    self.hold_frames = 0
                    self.turn_progress = 0.0
                else:
                    self.challenge_failed = True

            if self.challenge_2 == "turn_left":
                p_angle = max(0.0, min(1.0, delta_yaw / ANGLE_THRESHOLD_DEG))
                p_ratio = max(0.0, min(1.0, delta_turn_ratio / RATIO_THRESHOLD))
                progress = max(p_angle, p_ratio)
                angle_met = delta_yaw >= ANGLE_THRESHOLD_DEG
                ratio_met = delta_turn_ratio >= RATIO_THRESHOLD

            elif self.challenge_2 == "turn_right":
                p_angle = max(0.0, min(1.0, (-delta_yaw) / ANGLE_THRESHOLD_DEG))
                p_ratio = max(0.0, min(1.0, (-delta_turn_ratio) / RATIO_THRESHOLD))
                progress = max(p_angle, p_ratio)
                angle_met = delta_yaw <= -ANGLE_THRESHOLD_DEG
                ratio_met = delta_turn_ratio <= -RATIO_THRESHOLD

            elif self.challenge_2 == "nod_down":
                p_angle = max(0.0, min(1.0, delta_pitch / NOD_ANGLE_THRESHOLD_DEG))
                p_ratio = max(0.0, min(1.0, delta_nod_ratio / RATIO_THRESHOLD))
                progress = max(p_angle, p_ratio)
                angle_met = delta_pitch >= NOD_ANGLE_THRESHOLD_DEG
                ratio_met = delta_nod_ratio >= RATIO_THRESHOLD

            # Pass if either signal crosses its threshold, held for at least 2 frames
            if angle_met or ratio_met:
                self.hold_frames += 1
            else:
                self.hold_frames = max(0, self.hold_frames - 1)

            if self.hold_frames >= 2:
                self.head_movement_reached = True
                self.turn_progress = 1.0
                # Real 3D head movement exhibits parallax >= 0.025; rotated 2D photo has ~0.000
                if self.max_parallax_shift >= PARALLAX_MIN_THRESHOLD:
                    self.parallax_passed = True
                    self.current_phase = 3
            else:
                self.turn_progress = progress

        # 6. Compute true evidence-based liveness score
        as_summary = self.antispoof.get_summary()
        minifas_score = as_summary["avg_real_score"]
        blink_evidence = min(1.0, self.blink_count / 2.0)
        parallax_evidence = min(1.0, self.max_parallax_shift / 0.06)

        evidence_liveness = (0.50 * minifas_score) + (0.30 * blink_evidence) + (0.20 * parallax_evidence)
        completed = self.current_phase == 3 and as_summary.get("spoof_count", 0) <= self.antispoof.max_allowed_spoofs

        return {
            "face_detected": True,
            "completed": completed,
            "current_phase": self.current_phase,
            "prompt": self.current_prompt,
            "liveness_score": round(float(evidence_liveness), 4),
            "minifas_score": round(float(minifas_score), 4),
            "minifas_passed": as_summary["passed"],
            "blink_count": self.blink_count,
            "min_ear": round(float(self.min_ear_observed), 4),
            "current_ear": round(float(self.last_ear), 4),
            "max_parallax_shift": round(float(self.max_parallax_shift), 4),
            "parallax_passed": self.parallax_passed,
            "yaw": round(float(yaw), 2),
            "pitch": round(float(pitch), 2),
            "smoothed_yaw": round(float(self.smoothed_yaw), 2),
            "smoothed_pitch": round(float(self.smoothed_pitch), 2),
            "baseline_yaw": round(float(base_yaw), 2),
            "baseline_pitch": round(float(base_pitch), 2),
            "delta_yaw": round(float(delta_yaw), 2),
            "delta_pitch": round(float(delta_pitch), 2),
            "turn_ratio": round(float(turn_ratio), 4),
            "nod_ratio": round(float(nod_ratio), 4),
            "baseline_turn_ratio": round(float(base_turn_r), 4),
            "baseline_nod_ratio": round(float(base_nod_r), 4),
            "delta_turn_ratio": round(float(delta_turn_ratio), 4),
            "delta_nod_ratio": round(float(delta_nod_ratio), 4),
            "angle_threshold_met": angle_met,
            "ratio_threshold_met": ratio_met,
            "hold_frames": self.hold_frames,
            "turn_progress": round(float(self.turn_progress), 2),
            "challenge_time_remaining": max(0, int(self.challenge_duration - time_in_challenge)) if self.current_phase == 2 else 15,
            "challenge_retries": self.challenge_retries,
            "challenge_failed": self.challenge_failed,
            "challenge_1": self.challenge_1,
            "challenge_2": self.challenge_2,
            "landmarks": landmarks,
            "bbox": bbox,
        }

    def get_verdict_decision(self) -> Tuple[bool, str, Dict[str, Any]]:
        """Evaluate final liveness decision and determine specific rejection reason."""
        as_summary = self.antispoof.get_summary()

        if not as_summary["passed"] and as_summary["total_frames"] >= 5:
            return False, "REJECTED_SPOOF_DETECTED", {
                "reason": f"MiniFASNet passive anti-spoofing triggered: {as_summary['reason']}",
                "avg_real_score": as_summary["avg_real_score"],
                "spoof_count": as_summary["spoof_count"],
            }

        if self.blink_count < 2:
            return False, "REJECTED_NO_BLINK", {
                "reason": f"Required 2 deliberate eye blinks, detected {self.blink_count}",
                "min_ear": self.min_ear_observed,
            }

        if self.challenge_failed:
            return False, "REJECTED_CHALLENGE_FAILED", {
                "reason": f"Active challenge '{self.challenge_2}' failed after {self.challenge_retries + 1} attempts",
            }

        if not self.head_movement_reached:
            return False, "REJECTED_CHALLENGE_INCOMPLETE", {
                "reason": f"Active challenge '{self.challenge_2}' was not completed",
            }

        if not self.parallax_passed or self.max_parallax_shift < PARALLAX_MIN_THRESHOLD:
            return False, "REJECTED_NO_PARALLAX", {
                "reason": (
                    f"3D parallax consistency check failed (shift: {self.max_parallax_shift:.4f} < {PARALLAX_MIN_THRESHOLD:.4f}). "
                    "Planar rotation detected (printed photo or screen replay)."
                ),
                "parallax_shift": self.max_parallax_shift,
            }

        return True, "PASSED", {
            "minifas_score": as_summary["avg_real_score"],
            "blink_count": self.blink_count,
            "parallax_shift": self.max_parallax_shift,
        }
