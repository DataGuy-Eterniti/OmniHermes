"""Standalone Face Verification and Liveness Diagnostic Tool for OmniHermes.

Usage:
    python -m omnihermes.verify
    python -m omnihermes.verify --timeout 300
    python -m omnihermes.verify --unlock
    python -m omnihermes.verify --identity-only --image path/to/face.jpg
    python -m omnihermes.verify --source path/to/image_or_video
    python -m omnihermes.verify --list-cameras
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional

import cv2
import numpy as np

from omnihermes.audit import AuditLogger
from omnihermes.biometrics import BiometricEngine, DEFAULT_COSINE_THRESHOLD
from omnihermes.liveness import LivenessSession
from omnihermes.models import get_default_data_dir


def list_available_cameras(max_probe: int = 5) -> List[int]:
    """Probe system for available camera device indices."""
    available: List[int] = []
    print(f"[OmniHermes] Probing video capture devices (indices 0 to {max_probe - 1})...")
    for idx in range(max_probe):
        cap = cv2.VideoCapture(idx)
        if cap.isOpened():
            ret, _ = cap.read()
            if ret:
                available.append(idx)
            cap.release()
    return available


def verify_image_identity_only(image_path: Path, data_dir: Optional[Path] = None) -> bool:
    """Verify facial identity from a static image file without liveness checks."""
    data_dir = data_dir or get_default_data_dir()
    biometrics = BiometricEngine(data_dir=data_dir)

    if not biometrics.is_enrolled():
        print("[ERROR] No enrolled biometric profile found!")
        print("Run 'python -m omnihermes.enroll --name \"Elijah\" --primary' to enroll first.")
        return False

    owner_info = biometrics.get_owner_info()
    owner_name = owner_info.get("owner_name", "Owner")

    if not image_path.exists():
        print(f"[ERROR] Image file does not exist: {image_path}")
        return False

    img = cv2.imread(str(image_path))
    if img is None:
        print(f"[ERROR] Unable to decode image: {image_path}")
        return False

    faces = biometrics.detect_faces(img)
    if not faces:
        print("\n" + "=" * 60)
        print("OMNIHERMES — IDENTITY CHECK (IMAGE)")
        print("=" * 60)
        print(f"• File:             {image_path.name}")
        print(f"• Enrolled Owner:   {owner_name}")
        print("• Face Detected:    False")
        print("• VERDICT:          REJECTED_NO_FACE")
        print("=" * 60)
        return False

    emb = biometrics.extract_embedding(img, faces[0])
    passed, similarity = biometrics.match_against_owner(emb)

    print("\n" + "=" * 60)
    print("OMNIHERMES — IDENTITY CHECK (IMAGE)")
    print("=" * 60)
    print(f"• File:                   {image_path.name}")
    print(f"• Enrolled Owner:         {owner_name}")
    print(f"• Face Detected:          True")
    print(f"• SFace Cosine Similarity:{similarity: .4f}  (Threshold: {biometrics.cosine_threshold:.4f})")
    print(f"• Match Result:           {'PASS ✔' if passed else 'FAIL ✖'}")
    print(f"• VERDICT:                {'APPROVED' if passed else 'REJECTED_IMPOSTOR'}")
    print("=" * 60)
    return passed


def run_verify(
    timeout: int = 300,
    camera_idx: int = 0,
    source_file: Optional[Path] = None,
    data_dir: Optional[Path] = None,
) -> bool:
    """Run real face verification, MiniFASNet anti-spoofing, and 3D parallax check."""
    data_dir = data_dir or get_default_data_dir()
    biometrics = BiometricEngine(data_dir=data_dir)
    audit = AuditLogger(data_dir=data_dir)

    if not biometrics.is_enrolled():
        print("\n" + "=" * 60)
        print("[ERROR] No enrolled biometric profile found!")
        print("Please enroll first using:")
        print("    python -m omnihermes.enroll --name \"Elijah\" --primary")
        print("=" * 60)
        return False

    owner_info = biometrics.get_owner_info()
    owner_name = owner_info.get("owner_name", "Owner")
    liveness = LivenessSession(data_dir=data_dir)

    print("=" * 60)
    print("OMNIHERMES: LIVE VERIFICATION DIAGNOSTIC")
    print(f"• Enrolled Owner:               {owner_name} ({owner_info.get('role', 'PRIMARY_OWNER')})")
    print(f"• SFace Cosine Threshold:       {biometrics.cosine_threshold:.4f}")
    print(f"• Passive Anti-Spoofing:        MiniFASNetV2-SE (Threshold: 0.6000)")
    print(f"• Dual-Phase Challenges:        1. BLINK TWICE | 2. {liveness.challenge_2.upper()}")
    source_desc = f"File '{source_file}'" if source_file else f"Webcam Device {camera_idx}"
    print(f"• Input Source:                 {source_desc}")
    print(f"• Verification Timeout:         {timeout}s (Press 'q' to cancel)")
    print("=" * 60)

    # Static photo check (direct file or printed attack)
    if source_file and source_file.suffix.lower() in [".jpg", ".jpeg", ".png", ".bmp", ".webp"]:
        img = cv2.imread(str(source_file))
        if img is None:
            print(f"[ERROR] Could not read image file: {source_file}")
            return False
        faces = biometrics.detect_faces(img)
        live_res = liveness.process_frame(img)
        current_sim = 0.0
        face_matched = False
        if faces:
            emb = biometrics.extract_embedding(img, faces[0])
            face_matched, current_sim = biometrics.match_against_owner(emb)

        # Static photos ALWAYS fail blink and 3D parallax checks
        verdict = "REJECTED_NO_BLINK"
        reason = "Static image cannot complete dynamic eye blink challenge"
        if not face_matched:
            verdict = "REJECTED_IMPOSTOR"
            reason = f"Face similarity {current_sim:.4f} below threshold"

        print("\n" + "=" * 60)
        print("OMNIHERMES — STATIC SOURCE VERIFICATION")
        print("=" * 60)
        print(f"• Source File:            {source_file.name}")
        print(f"• Enrolled Owner:         {owner_name}")
        print(f"• Face Detected:          {len(faces) > 0}")
        print(f"• SFace Cosine Similarity:{current_sim: .4f}  (Threshold: {biometrics.cosine_threshold:.4f})")
        print(f"• MiniFASNet Real Score:  {live_res.get('minifas_score', 0.0): .4f}  (Threshold: 0.6000)")
        print(f"• Blink Detection:        0/2 blinks (Static image: FAIL ✖)")
        print(f"• 3D Parallax Shift:      0.0000 (No depth: FAIL ✖)")
        print(f"• VERDICT:                {verdict}")
        print(f"• REASON:                 {reason}")
        print("=" * 60)
        return False

    cap_source = str(source_file) if source_file else camera_idx
    cap = cv2.VideoCapture(cap_source)
    if not cap.isOpened():
        print(f"\n[ERROR] Unable to open video source: {cap_source}.")
        return False

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

    window_name = "OmniHermes - Face Verification"
    cv2.namedWindow(window_name, cv2.WINDOW_AUTOSIZE)

    start_time = time.time()
    best_similarity = 0.0
    face_seen = False
    decision = "PENDING"
    reason = "Verification in progress"

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                reason = "Verification timed out"
                decision = "REJECTED_TIMEOUT"
                break

            ret, frame = cap.read()
            if not ret or frame is None:
                if source_file:
                    break
                continue

            if not source_file:
                frame = cv2.flip(frame, 1)
            h, w = frame.shape[:2]

            faces = biometrics.detect_faces(frame)
            live_res = liveness.process_frame(frame)

            current_sim = 0.0
            face_matched = False

            if len(faces) > 0:
                face_seen = True
                primary_face = faces[0]
                fw, fh = int(primary_face[2]), int(primary_face[3])
                fx, fy = int(primary_face[0]), int(primary_face[1])

                emb = biometrics.extract_embedding(frame, primary_face)
                face_matched, current_sim = biometrics.match_against_owner(emb)
                best_similarity = max(best_similarity, current_sim)

                box_color = (0, 255, 128) if face_matched else (0, 0, 255)
                cv2.rectangle(frame, (fx, fy), (fx + fw, fy + fh), box_color, 2)

            # Top HUD: Owner & Similarity
            cv2.rectangle(frame, (0, 0), (w, 75), (20, 20, 20), -1)
            cv2.putText(
                frame, f"Verifying: {owner_name}", (20, 26), cv2.FONT_HERSHEY_DUPLEX, 0.65, (255, 255, 255), 1, cv2.LINE_AA
            )
            sim_col = (0, 255, 128) if current_sim >= biometrics.cosine_threshold else (0, 100, 255)
            cv2.putText(
                frame,
                f"Similarity: {current_sim:.3f} (Req: {biometrics.cosine_threshold:.3f})",
                (20, 48),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                sim_col,
                1,
                cv2.LINE_AA,
            )

            # MiniFASNet Score
            mf_score = live_res.get("minifas_score", 0.0)
            mf_col = (0, 255, 128) if mf_score >= 0.60 else (0, 140, 255)
            cv2.putText(
                frame,
                f"Passive Liveness: {mf_score:.2f}",
                (20, 68),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.45,
                mf_col,
                1,
                cv2.LINE_AA,
            )

            # Countdown Timer (5-minute visible countdown)
            rem_s = int(timeout - elapsed)
            mins, secs = rem_s // 60, rem_s % 60
            cv2.putText(
                frame,
                f"Time: {mins:02d}:{secs:02d}",
                (w - 140, 26),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6,
                (220, 220, 220),
                1,
                cv2.LINE_AA,
            )

            # Challenge Status
            cv2.putText(
                frame,
                f"Blinks: {live_res.get('blink_count', 0)}/2",
                (w - 140, 48),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                (0, 255, 128) if live_res.get("blink_count", 0) >= 2 else (0, 220, 255),
                1,
                cv2.LINE_AA,
            )
            cv2.putText(
                frame,
                f"Parallax: {live_res.get('max_parallax_shift', 0.0):.3f}",
                (w - 140, 68),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.45,
                (0, 255, 128) if live_res.get("parallax_passed") else (180, 180, 180),
                1,
                cv2.LINE_AA,
            )

            # Bottom guidance
            cv2.rectangle(frame, (0, h - 50), (w, h), (20, 20, 20), -1)
            prompt_color = (0, 255, 255) if not live_res["completed"] else (0, 255, 0)
            cv2.putText(
                frame,
                live_res.get("prompt", ""),
                (20, h - 18),
                cv2.FONT_HERSHEY_DUPLEX,
                0.6,
                prompt_color,
                1,
                cv2.LINE_AA,
            )

            cv2.imshow(window_name, frame)
            key = cv2.waitKey(1) & 0xFF
            if key == 27 or key == ord("q"):
                reason = "Cancelled by user"
                decision = "CANCELLED"
                break

            # Check if all conditions passed
            if face_matched and live_res["completed"]:
                cv2.waitKey(800)
                decision = "APPROVED"
                reason = "Face match, MiniFASNet anti-spoofing, and 3D parallax verified"
                break

    finally:
        cap.release()
        cv2.destroyAllWindows()

    # Detailed verdict determination
    as_summary = liveness.antispoof.get_summary()
    minifas_score = as_summary["avg_real_score"]
    spoofs_detected = as_summary["spoof_count"]
    total_eval_frames = as_summary["total_frames"]

    if not face_seen:
        decision = "REJECTED_NO_FACE"
        reason = "No face detected in camera view (camera covered or user absent)"
    elif decision == "PENDING" and best_similarity < biometrics.cosine_threshold:
        decision = "REJECTED_IMPOSTOR"
        reason = f"Face similarity {best_similarity:.4f} is below threshold {biometrics.cosine_threshold:.4f}"
    elif decision == "PENDING":
        liveness_ok, specific_reason, details = liveness.get_verdict_decision()
        if not liveness_ok:
            decision = specific_reason
            reason = details.get("reason", "Liveness check failed")
        elif best_similarity >= biometrics.cosine_threshold:
            decision = "APPROVED"
            reason = "All checks passed successfully"

    passed = decision == "APPROVED"
    evidence_liveness = live_res.get("liveness_score", 0.0)

    # Cryptographic Audit Log
    audit.log_event(
        event_type="VERIFY_RESULT",
        user_name=owner_name,
        action="Face & Multi-Challenge Liveness Verification",
        result=decision,
        similarity_score=best_similarity,
        liveness_score=evidence_liveness,
        details={
            "reason": reason,
            "threshold": biometrics.cosine_threshold,
            "minifas_score": minifas_score,
            "spoofs_detected": spoofs_detected,
            "blinks_detected": liveness.blink_count,
            "max_parallax_shift": liveness.max_parallax_shift,
        },
    )

    # Print comprehensive diagnostic output
    print("\n" + "=" * 60)
    print("OMNIHERMES — MULTI-FACTOR VERIFICATION REPORT")
    print("=" * 60)
    print(f"• Enrolled Owner:         {owner_name}")
    print(f"• Face Detected:          {face_seen}")
    print(f"• SFace Facial Similarity:{best_similarity: .4f}  (Threshold: {biometrics.cosine_threshold:.4f}) -> {'PASS ✔' if best_similarity >= biometrics.cosine_threshold else 'FAIL ✖'}")
    print(f"• MiniFASNet Real Score:  {minifas_score: .4f}  (Threshold: 0.6000, Spoofs: {spoofs_detected}/{total_eval_frames}) -> {'PASS ✔' if as_summary['passed'] else 'FAIL ✖'}")
    print(f"• Dynamic Blink Challenge:{liveness.blink_count}/2 blinks (Min EAR: {liveness.min_ear_observed:.4f}) -> {'PASS ✔' if liveness.blink_count >= 2 else 'FAIL ✖'}")
    print(f"• 3D Parallax Consistency:{liveness.max_parallax_shift: .4f} shift (Threshold: 0.0500) -> {'PASS ✔' if liveness.parallax_passed else 'FAIL ✖'}")
    print(f"• Overall Liveness Score: {evidence_liveness: .4f}  (Measured from real evidence)")
    print(f"• VERDICT:                {decision}")
    print(f"• REASON:                 {reason}")
    print("=" * 60)

    return passed


def main():
    parser = argparse.ArgumentParser(description="OmniHermes - Face Verification Diagnostic")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds (default: 300s / 5 mins)")
    parser.add_argument("--camera", type=int, default=0, help="Camera device index (default: 0)")
    parser.add_argument("--data-dir", type=str, default=None, help="Custom data directory")
    parser.add_argument("--list-cameras", action="store_true", help="List available camera devices and exit")
    parser.add_argument("--identity-only", action="store_true", help="Perform similarity match only (skips liveness)")
    parser.add_argument("--image", type=str, default=None, help="Path to static image for identity verification")
    parser.add_argument("--source", type=str, default=None, help="Path to static image or video file instead of webcam")
    parser.add_argument("--unlock", action="store_true", help="Grant a temporary execution unlock window on success")

    args = parser.parse_args()
    data_dir_path = Path(args.data_dir) if args.data_dir else None

    if args.list_cameras:
        cams = list_available_cameras()
        if cams:
            print(f"[OmniHermes] Detected active camera device indices: {cams}")
        else:
            print("[OmniHermes] No active camera devices detected.")
        sys.exit(0)

    if args.identity_only or args.image:
        if not args.image and not args.source:
            print("[ERROR] --identity-only requires --image <path_to_image>")
            sys.exit(1)
        target = Path(args.image or args.source)
        success = verify_image_identity_only(target, data_dir=data_dir_path)
        sys.exit(0 if success else 1)

    source_path = Path(args.source) if args.source else None
    success = run_verify(
        timeout=args.timeout,
        camera_idx=args.camera,
        source_file=source_path,
        data_dir=data_dir_path,
    )

    if success and args.unlock:
        from omnihermes.unlock import UnlockManager
        manager = UnlockManager(data_dir=data_dir_path)
        manager.grant_unlock("Elijah", duration_seconds=120)
        print("\n[OmniHermes] 2-minute execution unlock window granted.")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
