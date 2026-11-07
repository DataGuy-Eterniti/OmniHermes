"""Diagnostic tool to inspect MiniFASNet anti-spoofing model on live webcam frames.

Directly matches the reference implementation in github.com/facenox/face-antispoof-onnx:
- RGB channel order
- Bbox expansion factor (1.5) with letterbox and reflection padding
- Input size: 128x128 NCHW, normalized to [0, 1]
- Outputs raw logits vector and evaluated real score
"""

import argparse
import sys
import time
from pathlib import Path
from typing import Tuple

import cv2
import numpy as np

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from omnihermes.models import ensure_models, get_default_data_dir
from omnihermes.antispoof import AntiSpoofEngine, crop_face_square


def reference_crop(img_rgb: np.ndarray, bbox: Tuple[int, int, int, int], bbox_expansion_factor: float = 1.5) -> np.ndarray:
    """Exact reference crop from facenox/face-antispoof-onnx src/inference/preprocess.py."""
    original_height, original_width = img_rgb.shape[:2]
    x, y, x2, y2 = bbox
    w = x2 - x
    h = y2 - y

    if w <= 0 or h <= 0:
        raise ValueError(f"Invalid bbox dimensions: {bbox}")

    max_dim = max(w, h)
    center_x = x + w / 2.0
    center_y = y + h / 2.0

    crop_x = int(center_x - max_dim * bbox_expansion_factor / 2.0)
    crop_y = int(center_y - max_dim * bbox_expansion_factor / 2.0)
    crop_size = int(max_dim * bbox_expansion_factor)

    crop_x1 = max(0, crop_x)
    crop_y1 = max(0, crop_y)
    crop_x2 = min(original_width, crop_x + crop_size)
    crop_y2 = min(original_height, crop_y + crop_size)

    top_pad = int(max(0, -crop_y))
    left_pad = int(max(0, -crop_x))
    bottom_pad = int(max(0, (crop_y + crop_size) - original_height))
    right_pad = int(max(0, (crop_x + crop_size) - original_width))

    if crop_x2 > crop_x1 and crop_y2 > crop_y1:
        cropped = img_rgb[crop_y1:crop_y2, crop_x1:crop_x2, :]
    else:
        cropped = np.zeros((0, 0, 3), dtype=img_rgb.dtype)

    result = cv2.copyMakeBorder(
        cropped,
        top_pad,
        bottom_pad,
        left_pad,
        right_pad,
        cv2.BORDER_REFLECT_101,
    )
    return result


def reference_preprocess(face_crop: np.ndarray, model_img_size: int = 128) -> np.ndarray:
    """Exact reference preprocess from facenox/face-antispoof-onnx src/inference/preprocess.py."""
    new_size = model_img_size
    old_size = face_crop.shape[:2]

    ratio = float(new_size) / max(old_size)
    scaled_shape = tuple([int(x * ratio) for x in old_size])

    interpolation = cv2.INTER_LANCZOS4 if ratio > 1.0 else cv2.INTER_AREA
    img = cv2.resize(face_crop, (scaled_shape[1], scaled_shape[0]), interpolation=interpolation)

    delta_w = new_size - scaled_shape[1]
    delta_h = new_size - scaled_shape[0]
    top, bottom = delta_h // 2, delta_h - (delta_h // 2)
    left, right = delta_w // 2, delta_w - (delta_w // 2)

    img = cv2.copyMakeBorder(img, top, bottom, left, right, cv2.BORDER_REFLECT_101)
    img = img.transpose(2, 0, 1).astype(np.float32) / 255.0
    return np.expand_dims(img, axis=0)


def main():
    parser = argparse.ArgumentParser(description="Live webcam test for MiniFASNet anti-spoofing model")
    parser.add_argument("--camera", type=int, default=0, help="Webcam device index (default: 0)")
    parser.add_argument("--frames", type=int, default=30, help="Number of face frames to evaluate (default: 30)")
    parser.add_argument("--expansion", type=float, default=1.5, help="Bbox expansion factor (default: 1.5)")
    args = parser.parse_args()

    models = ensure_models()
    yunet_path = str(models["yunet"])
    minifas_path = str(models["minifasnet"])

    detector = cv2.FaceDetectorYN.create(yunet_path, "", (320, 320), score_threshold=0.6)
    engine = AntiSpoofEngine()

    cap = cv2.VideoCapture(args.camera)
    if not cap.isOpened():
        print(f"[ERROR] Could not open webcam device {args.camera}")
        sys.exit(1)

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

    print("=" * 80)
    print("MINIFASNET LIVE WEBCAM DIAGNOSTIC (30 FRAMES)")
    print(f"• Camera:          Device {args.camera}")
    print(f"• Expansion:       {args.expansion}x")
    print("• Target frames:   30 evaluated face crops")
    print("=" * 80)
    print(f"{'Frame':<6} | {'Raw Logits [L0, L1]':<26} | {'L0 - L1':<9} | {'L1 - L0':<9} | {'Softmax [P0, P1]':<22} | {'Real Score (Ref)':<16}")
    print("-" * 105)

    collected_frames = 0
    scores_idx0 = []
    scores_idx1 = []

    try:
        while collected_frames < args.frames:
            ret, frame_bgr = cap.read()
            if not ret or frame_bgr is None:
                time.sleep(0.01)
                continue

            frame_rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
            h, w = frame_bgr.shape[:2]
            detector.setInputSize((w, h))
            _, faces = detector.detect(frame_bgr)

            if faces is None or len(faces) == 0:
                continue

            # Largest face
            face = faces[0]
            fx, fy, fw, fh = int(face[0]), int(face[1]), int(face[2]), int(face[3])
            bbox = (max(0, fx), max(0, fy), min(w, fx + fw), min(h, fy + fh))

            try:
                crop = crop_face_square(frame_rgb, bbox, expansion=args.expansion)
                prob_real, logit_diff, is_spoof = engine.predict_crop(crop)
                blob = cv2.dnn.blobFromImage(crop, 1.0 / 255.0, (128, 128), swapRB=False, crop=False)
                engine.net.setInput(blob)
                logits = engine.net.forward()[0]
                l0, l1 = float(logits[0]), float(logits[1])
            except Exception as e:
                continue

            exp_l = np.exp(logits - np.max(logits))
            probs = exp_l / np.sum(exp_l)
            p0, p1 = float(probs[0]), float(probs[1])

            scores_idx0.append(p0)
            scores_idx1.append(prob_real)
            collected_frames += 1

            print(
                f"{collected_frames:<6} | [{l0:+7.4f}, {l1:+7.4f}]           | {l0 - l1:+8.4f}  | {logit_diff:+8.4f}  | [{p0:.4f}, {p1:.4f}]         | {prob_real:.4f} ({'LIVE' if not is_spoof else 'SPOOF'})"
            )
            sys.stdout.flush()
            time.sleep(0.05)

    finally:
        cap.release()

    print("=" * 105)
    print("SUMMARY:")
    avg_real = float(np.mean(scores_idx1)) if scores_idx1 else 0.0
    print(f"• Evaluated 30 live webcam frames using MiniFASNet engine")
    print(f"• Average Real Score = {avg_real:.4f} (Threshold 0.60: {'PASS' if avg_real >= 0.60 else 'FAIL'})")
    print(f"• Spoof Frames Detected = {sum(1 for s in scores_idx1 if s < 0.50)} / {len(scores_idx1)}")
    print("=" * 105)


if __name__ == "__main__":
    main()
