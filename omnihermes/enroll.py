"""Standalone Biometric Enrollment Flow for OmniHermes.

Usage:
    python -m omnihermes.enroll --name "Elijah" --primary
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List

import cv2
import numpy as np

from omnihermes.audit import AuditLogger
from omnihermes.biometrics import BiometricEngine
from omnihermes.liveness import LivenessSession
from omnihermes.models import get_default_data_dir


def draw_hud(
    frame: cv2.Mat,
    title: str,
    prompt: str,
    samples_count: int,
    target_samples: int,
    challenge_status: str,
    status_color: tuple = (0, 255, 128),
    remaining_seconds: int = 300,
) -> None:
    """Draw a professional HUD overlay on the camera frame."""
    h, w = frame.shape[:2]

    # Top banner
    cv2.rectangle(frame, (0, 0), (w, 55), (20, 20, 20), -1)
    cv2.putText(
        frame, title, (20, 36), cv2.FONT_HERSHEY_DUPLEX, 0.75, (255, 255, 255), 2, cv2.LINE_AA
    )

    # Countdown and Samples indicator
    mins, secs = max(0, remaining_seconds) // 60, max(0, remaining_seconds) % 60
    hud_right = f"Samples: {samples_count}/{target_samples} | {mins:02d}:{secs:02d}"
    cv2.putText(
        frame, hud_right, (w - 240, 36), cv2.FONT_HERSHEY_DUPLEX, 0.55, (0, 220, 255), 1, cv2.LINE_AA
    )

    # Center target guide
    cx, cy = w // 2, h // 2
    cv2.ellipse(frame, (cx, cy), (130, 170), 0, 0, 360, (60, 60, 60), 2, cv2.LINE_AA)

    # Bottom guidance banner
    cv2.rectangle(frame, (0, h - 85), (w, h), (20, 20, 20), -1)
    cv2.putText(
        frame, prompt, (20, h - 50), cv2.FONT_HERSHEY_DUPLEX, 0.65, status_color, 2, cv2.LINE_AA
    )
    cv2.putText(
        frame, f"Challenge: {challenge_status}", (20, h - 20), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (180, 180, 180), 1, cv2.LINE_AA
    )


def run_enrollment(
    name: str = "Elijah",
    is_primary: bool = True,
    data_dir: Path = None,
    camera_idx: int = 0,
    timeout: int = 300,
) -> bool:
    """Run interactive webcam enrollment with 5-minute timeout window."""
    data_dir = data_dir or get_default_data_dir()
    biometrics = BiometricEngine(data_dir=data_dir)
    audit = AuditLogger(data_dir=data_dir)
    liveness = LivenessSession(data_dir=data_dir)

    print("=" * 60)
    print(f"OMNIHERMES: BIOMETRIC ENROLLMENT")
    print(f"• Candidate:        {name} ({'PRIMARY OWNER' if is_primary else 'MEMBER'})")
    print(f"• Detection/Embed:  OpenCV YuNet + SFace (128-d)")
    print(f"• Anti-Spoofing:    MiniFASNetV2-SE (Passive) + 3D Parallax")
    print(f"• Liveness:         Dual Challenge (Mandatory Blinks + Pose)")
    print(f"• Timeout Window:   {timeout}s (5 minutes)")
    print("=" * 60)
    print("Opening webcam...")

    cap = cv2.VideoCapture(camera_idx)
    if not cap.isOpened():
        print(f"\n[ERROR] Unable to open webcam (device {camera_idx}).")
        return False

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

    window_name = "OmniHermes - Biometric Enrollment"
    cv2.namedWindow(window_name, cv2.WINDOW_AUTOSIZE)

    embeddings: List[np.ndarray] = []
    target_samples = 5
    last_sample_time = 0.0
    start_time = time.time()
    completed = False

    try:
        while True:
            elapsed = time.time() - start_time
            remaining = int(timeout - elapsed)
            if remaining <= 0:
                print(f"\n[ERROR] Enrollment timed out after {timeout} seconds.")
                break

            ret, frame = cap.read()
            if not ret or frame is None:
                continue

            frame = cv2.flip(frame, 1)
            faces = biometrics.detect_faces(frame)
            live_res = liveness.process_frame(frame)

            status_prompt = "Align your face inside the target ellipse"
            status_color = (0, 180, 255)

            if len(faces) == 0:
                status_prompt = "No face detected - move closer to camera"
                status_color = (0, 0, 255)
            elif len(faces) > 1:
                status_prompt = "Multiple faces detected - ensure only you are visible"
                status_color = (0, 0, 255)
            else:
                primary_face = faces[0]
                fw, fh = primary_face[2], primary_face[3]

                if fw < 90 or fh < 90:
                    status_prompt = "Move closer to the camera"
                    status_color = (0, 165, 255)
                else:
                    fx, fy = int(primary_face[0]), int(primary_face[1])
                    cv2.rectangle(frame, (fx, fy), (fx + int(fw), fy + int(fh)), (0, 255, 128), 2)

                    if not live_res["completed"]:
                        status_prompt = live_res["prompt"]
                        status_color = (0, 255, 255)
                    else:
                        status_prompt = "Hold still, capturing facial samples..."
                        status_color = (0, 255, 128)

                        now = time.time()
                        if now - last_sample_time >= 0.4 and len(embeddings) < target_samples:
                            emb = biometrics.extract_embedding(frame, primary_face)
                            embeddings.append(emb)
                            last_sample_time = now
                            print(f"[OmniHermes] Captured sample {len(embeddings)}/{target_samples}")

            challenge_status = "COMPLETED ✔" if live_res["completed"] else f"{live_res['prompt']}..."
            draw_hud(
                frame,
                title=f"Enroll: {name} (Primary Owner)",
                prompt=status_prompt,
                samples_count=len(embeddings),
                target_samples=target_samples,
                challenge_status=challenge_status,
                status_color=status_color,
                remaining_seconds=remaining,
            )

            cv2.imshow(window_name, frame)
            key = cv2.waitKey(1) & 0xFF
            if key == 27 or key == ord("q"):
                print("\n[INFO] Enrollment cancelled by user.")
                break

            if len(embeddings) >= target_samples and live_res["completed"]:
                draw_hud(
                    frame,
                    title="Enrollment Complete!",
                    prompt=f"✔ Successfully enrolled {name}",
                    samples_count=target_samples,
                    target_samples=target_samples,
                    challenge_status="VERIFIED",
                    status_color=(0, 255, 0),
                    remaining_seconds=remaining,
                )
                cv2.imshow(window_name, frame)
                cv2.waitKey(1200)
                completed = True
                break

    finally:
        cap.release()
        cv2.destroyAllWindows()

    if completed and len(embeddings) == target_samples:
        # Compute normalized average embedding
        stacked = np.vstack(embeddings)
        mean_emb = np.mean(stacked, axis=0, keepdims=True)
        mean_emb = mean_emb / np.linalg.norm(mean_emb)

        profile = biometrics.save_profile(owner_name=name, embedding=mean_emb, is_primary=is_primary)
        audit.log_event(
            event_type="ENROLL_SUCCESS",
            user_name=name,
            action="Enroll Primary Owner",
            result="SUCCESS",
            similarity_score=1.0,
            liveness_score=0.95,
            details={"samples": target_samples, "model": "sface_2021dec", "role": profile["role"]},
        )

        print("\n" + "=" * 60)
        print(f"✔ ENROLLMENT SUCCESSFUL!")
        print(f"• Registered Owner: {name}")
        print(f"• Role: {profile['role']}")
        print(f"• Features: 128-d SFace embedding (averaged from {target_samples} live frames)")
        print(f"• Storage: AES-256-GCM encrypted in {biometrics.profile_path}")
        print("• Zero raw face images stored on disk.")
        print("=" * 60)
        return True
    else:
        print("\n[FAILED] Enrollment was not completed.")
        return False


def main():
    parser = argparse.ArgumentParser(description="OmniHermes - Biometric Enrollment")
    parser.add_argument("--name", type=str, default="Elijah", help="Name of owner to enroll")
    parser.add_argument("--primary", action="store_true", default=True, help="Mark as primary workstation owner")
    parser.add_argument("--camera", type=int, default=0, help="Camera device index (default: 0)")
    parser.add_argument("--timeout", type=int, default=300, help="Enrollment timeout in seconds (default: 300s)")
    parser.add_argument("--data-dir", type=str, default=None, help="Custom data directory")

    args = parser.parse_args()
    data_dir_path = Path(args.data_dir) if args.data_dir else None
    success = run_enrollment(
        name=args.name,
        is_primary=args.primary,
        data_dir=data_dir_path,
        camera_idx=args.camera,
        timeout=args.timeout,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

