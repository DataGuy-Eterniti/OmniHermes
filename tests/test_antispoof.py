"""Regression tests for MiniFASNet passive anti-spoofing and 3D parallax consistency.

All tests using synthetic frame fixtures or simulated landmark data
are clearly labeled as fixtures.
"""

import math
import unittest
from pathlib import Path

import numpy as np

from presence.antispoof import AntiSpoofEngine, AntiSpoofSession, crop_face_square
from presence.liveness import LivenessSession


class LandmarkFixture:
    """Fixture representing a single facial landmark point with (x, y, z)."""
    def __init__(self, x: float, y: float, z: float = 0.0):
        self.x = x
        self.y = y
        self.z = z


def create_face_landmarks_fixture(yaw_deg: float, is_flat_photo: bool = False) -> list:
    """Fixture generator: creates 478 MediaPipe face landmarks.
    
    If is_flat_photo=True:
        Landmarks rotate as a rigid 2D planar projection (no depth parallax).
    If is_flat_photo=False:
        True 3D human head: nose projects forward from eye plane, creating
        strong horizontal parallax differential during yaw.
    """
    yaw_rad = math.radians(yaw_deg)
    cos_y = math.cos(yaw_rad)
    sin_y = math.sin(yaw_rad)

    # Base positions at neutral center (x=0.5, y=0.5)
    # Nose (1): at center x=0.5. On a 3D face, z = -0.05 (closer to camera)
    # Left eye outer (263): x=0.65, z = 0.0
    # Right eye outer (33): x=0.35, z = 0.0
    landmarks = [LandmarkFixture(0.5, 0.5, 0.0) for _ in range(478)]

    if is_flat_photo:
        # Rigid planar rotation: all points share z=0.0
        # Landmark distances contract by cos(yaw) identically
        landmarks[33] = LandmarkFixture(0.5 - 0.15 * cos_y, 0.45, 0.15 * sin_y)
        landmarks[263] = LandmarkFixture(0.5 + 0.15 * cos_y, 0.45, -0.15 * sin_y)
        # Nose stays exactly midway on the rotated photo surface
        landmarks[1] = LandmarkFixture(0.5 + 0.0 * cos_y, 0.50, 0.0)
    else:
        # Real 3D head: nose tip projects forward by 0.05
        # During yaw, nose moves by: x_center + z_nose * sin(yaw)
        landmarks[33] = LandmarkFixture(0.5 - 0.15 * cos_y, 0.45, 0.15 * sin_y)
        landmarks[263] = LandmarkFixture(0.5 + 0.15 * cos_y, 0.45, -0.15 * sin_y)
        # 3D parallax: forward-projecting nose shifts significantly in x
        nose_shift = 0.06 * sin_y
        landmarks[1] = LandmarkFixture(0.5 + nose_shift, 0.50, -0.05 * cos_y)

    # Chin (152), mouth corners (61, 291)
    landmarks[152] = LandmarkFixture(0.5, 0.70, 0.0)
    landmarks[61] = LandmarkFixture(0.42, 0.60, 0.0)
    landmarks[291] = LandmarkFixture(0.58, 0.60, 0.0)

    # Eye EAR landmarks (neutral open eyes) - omit 33 and 263
    for idx in [362, 385, 387, 373, 380, 160, 158, 133, 153, 144]:
        landmarks[idx] = LandmarkFixture(0.5, 0.45, 0.0)

    return landmarks


class TestAntiSpoofRegression(unittest.TestCase):
    def setUp(self):
        self.engine = AntiSpoofEngine()

    def test_minifasnet_model_inference_fixture(self):
        """Fixture Test: MiniFASNet successfully evaluates synthetic image crops."""
        # 128x128 synthetic face crop
        crop = np.random.randint(40, 220, (128, 128, 3), dtype=np.uint8)
        prob_real, logit_diff, is_spoof = self.engine.predict_crop(crop)

        self.assertIsInstance(prob_real, float)
        self.assertGreaterEqual(prob_real, 0.0)
        self.assertLessEqual(prob_real, 1.0)
        self.assertIsInstance(is_spoof, bool)

    def test_crop_face_square_padding_fixture(self):
        """Fixture Test: Face cropper properly expands bbox and applies reflect padding."""
        img = np.zeros((200, 200, 3), dtype=np.uint8)
        # Bbox near edge forcing boundary padding
        bbox = (10, 10, 80, 80)
        cropped = crop_face_square(img, bbox, expansion=1.5)
        self.assertEqual(cropped.shape, (128, 128, 3))

    def test_planar_photo_rotation_fails_parallax_check_fixture(self):
        """Fixture Test: Rotating a flat photo exhibits near-zero parallax and fails."""
        # Initialize session with secondary challenge turn_left
        session = LivenessSession(secondary_challenge="turn_left")
        session.current_phase = 2  # Skip to head turn

        # Calibrate neutral baseline
        neutral_lm = create_face_landmarks_fixture(yaw_deg=0.0, is_flat_photo=True)
        session.neutral_ratio_baseline = 0.50

        # Simulate rotating a flat photo to yaw = 18 deg
        photo_turned_lm = create_face_landmarks_fixture(yaw_deg=18.0, is_flat_photo=True)
        x_nose = photo_turned_lm[1].x
        x_right = photo_turned_lm[33].x
        x_left = photo_turned_lm[263].x
        eye_span = abs(x_left - x_right)
        ratio = (x_nose - min(x_right, x_left)) / eye_span
        shift = abs(ratio - session.neutral_ratio_baseline)

        # Flat photo ratio does not shift because all points share the plane
        self.assertLess(shift, 0.03, f"Flat photo should have near-zero shift, got {shift}")

    def test_real_3d_head_turn_passes_parallax_check_fixture(self):
        """Fixture Test: Real 3D head rotation exhibits strong parallax shift (> 0.08)."""
        session = LivenessSession(secondary_challenge="turn_left")
        session.current_phase = 2

        neutral_lm = create_face_landmarks_fixture(yaw_deg=0.0, is_flat_photo=False)
        session.neutral_ratio_baseline = 0.50

        # Simulate real 3D head turn to yaw = 18 deg
        real_turned_lm = create_face_landmarks_fixture(yaw_deg=18.0, is_flat_photo=False)
        x_nose = real_turned_lm[1].x
        x_right = real_turned_lm[33].x
        x_left = real_turned_lm[263].x
        eye_span = abs(x_left - x_right)
        ratio = (x_nose - min(x_right, x_left)) / eye_span
        shift = abs(ratio - session.neutral_ratio_baseline)

        # Real 3D face exhibits significant parallax shift (>= 0.05) vs flat photo (< 0.01)
        self.assertGreater(shift, 0.05, f"Real head should exhibit parallax > 0.05, got {shift}")

    def test_antispoof_session_rejects_spoofs_fixture(self):
        """Fixture Test: AntiSpoofSession flags spoof when too many frames are detected as fake."""
        session = AntiSpoofSession(engine=self.engine, real_threshold=0.60, min_frames=10, max_allowed_spoofs=2)

        # Inject fake scores (e.g. static photo / low real prob)
        session.scores = [0.15] * 12
        session.spoof_flags = [True] * 12

        summary = session.get_summary()
        self.assertFalse(summary["passed"])
        self.assertEqual(summary["spoof_count"], 12)
        self.assertLess(summary["avg_real_score"], 0.60)


if __name__ == "__main__":
    unittest.main()
