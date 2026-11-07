"""Standalone Face Verification and Liveness Diagnostic Tool for OmniHermes.

Usage:
    python -m omnihermes.verify
    python -m omnihermes.verify --timeout 45
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
from omnihermes.renderer import (
    COLOR_AMBER,
    COLOR_NAVY_BG,
    COLOR_PANEL_BG,
    COLOR_RED,
    COLOR_SLATE,
    COLOR_TEAL,
    COLOR_WHITE,
    draw_animated_arrow,
    draw_debug_overlay,
    draw_face_guide,
    draw_panel,
    draw_progress_bar,
    draw_shield_icon,
    render_closing_screen,
    render_text_pil,
)


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
        print("Run 'python -m omnihermes.enroll --name \"Elijah\" --primary --replace' to enroll first.")
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
        print("OMNIHERMES - IDENTITY CHECK (IMAGE)")
        print("=" * 60)
        print(f"- File:             {image_path.name}")
        print(f"- Enrolled Owner:   {owner_name}")
        print("- Face Detected:    False")
        print("- VERDICT:          REJECTED_NO_FACE")
        print("=" * 60)
        return False

    emb = biometrics.extract_embedding(img, faces[0])
    passed, similarity = biometrics.match_against_owner(emb)

    print("\n" + "=" * 60)
    print("OMNIHERMES - IDENTITY CHECK (IMAGE)")
    print("=" * 60)
    print(f"- File:                   {image_path.name}")
    print(f"- Enrolled Owner:         {owner_name}")
    print(f"- Face Detected:          True")
    print(f"- SFace Cosine Similarity:{similarity: .4f}  (Threshold: {biometrics.cosine_threshold:.4f})")
    print(f"- Match Result:           {'PASS' if passed else 'FAIL'}")
    print(f"- VERDICT:                {'APPROVED' if passed else 'REJECTED_IMPOSTOR'}")
    print("=" * 60)
    return passed


def run_verify(
    timeout: int = 300,
    camera_idx: int = 0,
    source_file: Optional[Path] = None,
    data_dir: Optional[Path] = None,
) -> bool:
    """Run real face verification with guaranteed clean exit and Windows event pumping."""
    data_dir = data_dir or get_default_data_dir()
    biometrics = BiometricEngine(data_dir=data_dir)
    audit = AuditLogger(data_dir=data_dir)

    if not biometrics.is_enrolled():
        print("\n" + "=" * 60)
        print("[ERROR] No enrolled biometric profile found!")
        print("Please enroll first using:")
        print("    python -m omnihermes.enroll --name \"Elijah\" --primary --replace")
        print("=" * 60)
        return False

    owner_info = biometrics.get_owner_info()
    owner_name = owner_info.get("owner_name", "Owner")
    liveness = LivenessSession(data_dir=data_dir)

    print("=" * 60)
    print("OMNIHERMES: LIVE VERIFICATION DIAGNOSTIC")
    print(f"- Enrolled Owner:               {owner_name} ({owner_info.get('role', 'PRIMARY_OWNER')})")
    print(f"- SFace Cosine Threshold:       {biometrics.cosine_threshold:.4f}")
    print(f"- Passive Anti-Spoofing:        MiniFASNetV2-SE (Threshold: 0.6000)")
    print(f"- Dynamic Active Challenge:     1. BLINK TWICE | 2. {liveness.challenge_2.upper()}")
    source_desc = f"File '{source_file}'" if source_file else f"Webcam Device {camera_idx}"
    print(f"- Input Source:                 {source_desc}")
    print(f"- Verification Timeout:         {timeout}s (Press 'q' or click [X] to cancel, 'd' for telemetry)")
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

        if not faces:
            verdict = "REJECTED_NO_FACE"
            reason = "No face detected in static image"
        elif not face_matched:
            verdict = "REJECTED_FACE_MISMATCH"
            reason = f"Face similarity {current_sim:.4f} below threshold {biometrics.cosine_threshold:.4f}"
        else:
            verdict = "REJECTED_NO_BLINK"
            reason = "Static image cannot complete dynamic eye blink challenge"

        print("\n" + "=" * 60)
        print("OMNIHERMES - STATIC SOURCE VERIFICATION")
        print("=" * 60)
        print(f"- Source File:            {source_file.name}")
        print(f"- Enrolled Owner:         {owner_name}")
        print(f"- Face Detected:          {len(faces) > 0}")
        print(f"- SFace Cosine Similarity:{current_sim: .4f}  (Threshold: {biometrics.cosine_threshold:.4f})")
        print(f"- MiniFASNet Real Score:  {live_res.get('minifas_score', 0.0): .4f}  (Threshold: 0.6000)")
        print("- Blink Detection:        0/2 blinks (Static image: FAIL)")
        print("- 3D Parallax Shift:      0.0000 (No depth: FAIL)")
        print(f"- VERDICT:                {verdict}")
        print(f"- REASON:                 {reason}")
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
    cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)
    try:
        cv2.setWindowProperty(window_name, cv2.WND_PROP_TOPMOST, 1)
    except Exception:
        pass
    try:
        import winsound
        winsound.MessageBeep()
    except Exception:
        pass

    start_time = time.time()
    best_similarity = 0.0
    face_seen = False
    face_seen_start: Optional[float] = None
    face_continuous_seconds = 0.0
    face_seen_frames = 0
    decision = "PENDING"
    reason = "Verification in progress"
    first_frame = True
    show_debug = False
    anim_tick = 0
    frame_for_closing = None

    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                reason = "Verification timed out"
                decision = "TIMEOUT_EXPIRED"
                break

            # Immediate detection of user clicking window's [X] close button
            if not first_frame and cv2.getWindowProperty(window_name, cv2.WND_PROP_VISIBLE) < 1:
                reason = "Window closed by user"
                decision = "CANCELLED"
                break

            ret, frame = cap.read()
            if not ret or frame is None:
                if source_file:
                    break
                continue

            if not source_file:
                frame = cv2.flip(frame, 1)
            h, w = frame.shape[:2]
            cx, cy = w // 2, h // 2
            anim_tick += 1
            frame_for_closing = frame.copy()

            faces = biometrics.detect_faces(frame)
            live_res = liveness.process_frame(frame)

            current_sim = 0.0
            face_matched = False
            primary_face = None

            if len(faces) > 0:
                face_seen = True
                face_seen_frames += 1
                if face_seen_start is None:
                    face_seen_start = time.time()
                face_continuous_seconds = time.time() - face_seen_start

                primary_face = faces[0]
                fw, fh = int(primary_face[2]), int(primary_face[3])
                fx, fy = max(0, int(primary_face[0])), max(0, int(primary_face[1]))

                emb = biometrics.extract_embedding(frame, primary_face)
                face_matched, current_sim = biometrics.match_against_owner(emb)
                best_similarity = max(best_similarity, current_sim)

                # Centred face guide follows face bounding box
                fcx, fcy = fx + fw // 2, fy + fh // 2
                guide_w, guide_h = max(180, int(fw * 1.35)), max(220, int(fh * 1.35))
                guide_col = COLOR_TEAL if face_matched else COLOR_RED
                draw_face_guide(frame, fcx, fcy, w=guide_w, h=guide_h, override_color=guide_col)
            else:
                face_seen_start = None
                face_continuous_seconds = 0.0
                # Default centered guide when looking for face (AMBER)
                draw_face_guide(frame, cx, cy, w=200, h=250, override_color=COLOR_AMBER)

            # Determine live status prompt & accent colors
            if len(faces) == 0:
                current_step_prompt = "Checking face match..."
                prompt_color = COLOR_AMBER
                header_border = COLOR_AMBER
                header_state = "checking"
            elif not face_matched:
                current_step_prompt = f"Face not recognised ({current_sim:.2f} / {biometrics.cosine_threshold:.2f} needed)"
                prompt_color = COLOR_RED
                header_border = COLOR_RED
                header_state = "denied"
            elif live_res.get("current_phase") == 1:
                current_step_prompt = "Step 1 of 2: Blink twice"
                prompt_color = COLOR_AMBER
                header_border = COLOR_AMBER
                header_state = "checking"
            elif live_res.get("current_phase") == 2:
                ch = live_res.get("challenge_2", "turn_left")
                from omnihermes.liveness import CHALLENGE_PROMPTS
                current_step_prompt = CHALLENGE_PROMPTS.get(ch, "Step 2 of 2: Follow prompt")
                prompt_color = COLOR_AMBER
                header_border = COLOR_AMBER
                header_state = "checking"
            else:
                current_step_prompt = "Checking face match..."
                prompt_color = COLOR_AMBER
                header_border = COLOR_AMBER
                header_state = "checking"

            # Top Semi-Transparent Modern Panel
            draw_panel(frame, (16, 12), (w - 16, 72), bg_color=COLOR_PANEL_BG, alpha=0.88, radius=12, border_color=header_border)
            draw_shield_icon(frame, (40, 42), size=14, color=header_border, state=header_state)
            render_text_pil(frame, "OmniHermes", (64, 22), font_size=16, color=COLOR_WHITE, bold=True)
            render_text_pil(
                frame,
                current_step_prompt,
                (64, 46),
                font_size=12,
                color=prompt_color if not face_matched and len(faces) > 0 else COLOR_SLATE,
                bold=(not face_matched and len(faces) > 0),
            )

            # Status on top right
            render_text_pil(frame, f"Owner: {owner_name}", (w - 200, 24), font_size=12, color=COLOR_WHITE, bold=True)
            if len(faces) > 0:
                sim_col = COLOR_TEAL if face_matched else COLOR_RED
            else:
                sim_col = COLOR_SLATE
            render_text_pil(
                frame,
                f"Sim: {current_sim:.3f} (Req: {biometrics.cosine_threshold:.3f})",
                (w - 200, 44),
                font_size=11,
                color=sim_col,
                bold=(len(faces) > 0 and not face_matched),
            )

            # Animated Arrow for Challenge 2
            if live_res.get("current_phase") == 2 and not live_res.get("completed"):
                ch = live_res.get("challenge_2", "turn_left")
                arrow_col = COLOR_TEAL if live_res.get("turn_progress", 0.0) >= 1.0 else COLOR_AMBER
                draw_animated_arrow(frame, (cx, cy + 30), direction=ch, tick=anim_tick, color=arrow_col)

            # Bottom Semi-Transparent Guidance Panel
            draw_panel(frame, (16, h - 80), (w - 16, h - 14), bg_color=COLOR_PANEL_BG, alpha=0.88, radius=12, border_color=header_border)
            render_text_pil(frame, current_step_prompt, (32, h - 72), font_size=14, color=prompt_color, bold=True)

            if live_res.get("current_phase") == 1 and face_matched:
                b_cnt = live_res.get("blink_count", 0)
                b_pct = min(1.0, b_cnt / 2.0)
                draw_progress_bar(frame, (32, h - 38), width=180, height=12, progress=b_pct, bar_color=COLOR_TEAL)
                render_text_pil(frame, f"Blinks: {b_cnt}/2", (222, h - 41), font_size=11, color=COLOR_TEAL)
            elif live_res.get("current_phase") == 2 and face_matched:
                prog = live_res.get("turn_progress", 0.0)
                draw_progress_bar(frame, (32, h - 38), width=w - 190, height=12, progress=prog, bar_color=COLOR_TEAL)
                render_text_pil(
                    frame,
                    f"{int(prog * 100)}% ({live_res.get('challenge_time_remaining', 15)}s)",
                    (w - 150, h - 41),
                    font_size=11,
                    color=COLOR_TEAL if prog >= 1.0 else COLOR_AMBER,
                    bold=True,
                )

            # Debug Telemetry Overlay (Toggled with 'D' key)
            if show_debug:
                draw_debug_overlay(frame, live_res)

            # Bring window to front on first frame
            if first_frame:
                first_frame = False
                try:
                    cv2.setWindowProperty(window_name, cv2.WND_PROP_TOPMOST, 1)
                except Exception:
                    pass
                try:
                    import ctypes
                    user32 = ctypes.windll.user32
                    hwnd = user32.FindWindowW(None, window_name)
                    if hwnd:
                        user32.ShowWindow(hwnd, 9)
                        user32.SetForegroundWindow(hwnd)
                except Exception:
                    pass

            cv2.imshow(window_name, frame)
            key = cv2.waitKey(1) & 0xFF
            if key in (27, ord("q"), ord("Q")):
                reason = "Cancelled by user"
                decision = "CANCELLED"
                break
            elif key in (ord("d"), ord("D")):
                show_debug = not show_debug

            # Early Definite Rejections
            # 1. Definite Spoof Detection: MiniFASNet has >= 10 frames and excessive spoofs
            as_summary_now = liveness.antispoof.get_summary()
            if as_summary_now["total_frames"] >= 10 and as_summary_now["spoof_count"] > liveness.antispoof.max_allowed_spoofs:
                decision = "REJECTED_SPOOF_DETECTED"
                reason = f"MiniFASNet anti-spoofing triggered ({as_summary_now['spoof_count']}/{as_summary_now['total_frames']} spoofs detected)"
                break

            # 2. Definite Challenge Failure: challenge retries exhausted
            if live_res.get("challenge_failed", False):
                decision = "REJECTED_CHALLENGE_FAILED"
                reason = f"Active challenge '{liveness.challenge_2}' failed after {liveness.challenge_retries + 1} attempts"
                break

            # 3. Definite Face Mismatch: face seen continuously for >= 6.0s and >= 30 frames with similarity below threshold
            if face_continuous_seconds >= 6.0 and face_seen_frames >= 30 and best_similarity < biometrics.cosine_threshold:
                decision = "REJECTED_FACE_MISMATCH"
                reason = f"Face similarity {best_similarity:.4f} is below required threshold {biometrics.cosine_threshold:.4f}"
                break

            # Completion check: approval triggers when face matched and liveness completed (Phase 3)
            if (face_matched or best_similarity >= biometrics.cosine_threshold) and (
                live_res.get("completed") or live_res.get("current_phase") == 3
            ):
                decision = "APPROVED"
                reason = "Face match and dynamic liveness verified"
                break

        # Show closing screen for at most 1.5 seconds, closing automatically
        if frame_for_closing is not None:
            if decision == "APPROVED":
                closing_card = render_closing_screen(
                    frame_for_closing,
                    success=True,
                    title=f"Verified: {owner_name}",
                    subtitle="Unlocked for 2 minutes",
                )
            elif decision != "CANCELLED":
                short_title = f"Verification denied: {reason}" if len(reason) <= 28 else "Verification denied"
                closing_card = render_closing_screen(
                    frame_for_closing,
                    success=False,
                    title=short_title,
                    subtitle=reason[:60],
                )
            else:
                closing_card = None

            if closing_card is not None:
                t_end = time.time() + 1.5
                while time.time() < t_end:
                    cv2.imshow(window_name, closing_card)
                    k = cv2.waitKey(20) & 0xFF
                    if k in (27, ord("q"), ord("Q")):
                        break
                    if cv2.getWindowProperty(window_name, cv2.WND_PROP_VISIBLE) < 1:
                        break

    finally:
        # Guaranteed cleanup in all exit paths (success, cancel, timeout, exception)
        if "cap" in locals() and cap is not None:
            try:
                cap.release()
            except Exception:
                pass
        try:
            cv2.destroyWindow(window_name)
        except Exception:
            pass
        try:
            cv2.destroyAllWindows()
        except Exception:
            pass
        # Pump event loop so Windows removes the window handle immediately
        for _ in range(10):
            cv2.waitKey(1)

    # Detailed verdict determination
    as_summary = liveness.antispoof.get_summary()
    minifas_score = as_summary["avg_real_score"]
    spoofs_detected = as_summary["spoof_count"]
    total_eval_frames = as_summary["total_frames"]

    if decision in ("PENDING", "TIMEOUT_EXPIRED", "REJECTED_TIMEOUT"):
        if not face_seen:
            decision = "REJECTED_NO_FACE"
            reason = "No face detected in camera view (camera covered or user absent)"
        elif not as_summary["passed"] and total_eval_frames >= 5:
            decision = "REJECTED_SPOOF_DETECTED"
            reason = f"MiniFASNet anti-spoofing failed: {as_summary['reason']}"
        elif best_similarity < biometrics.cosine_threshold:
            decision = "REJECTED_FACE_MISMATCH"
            reason = f"Face similarity {best_similarity:.4f} is below threshold {biometrics.cosine_threshold:.4f}"
        elif liveness.blink_count < 2:
            decision = "REJECTED_NO_BLINK"
            reason = f"Required 2 deliberate eye blinks, detected {liveness.blink_count}"
        elif live_res.get("challenge_failed", False):
            decision = "REJECTED_CHALLENGE_FAILED"
            reason = f"Active challenge '{liveness.challenge_2}' failed after {liveness.challenge_retries + 1} attempts"
        elif not liveness.head_movement_reached:
            decision = "REJECTED_CHALLENGE_INCOMPLETE"
            reason = f"Active challenge '{liveness.challenge_2}' was not completed"
        elif not liveness.parallax_passed or liveness.max_parallax_shift < PARALLAX_MIN_THRESHOLD:
            decision = "REJECTED_NO_PARALLAX"
            reason = f"3D parallax consistency check failed (shift: {liveness.max_parallax_shift:.4f} < {PARALLAX_MIN_THRESHOLD:.4f})"
        else:
            decision = "REJECTED_TIMEOUT"
            reason = "Verification timed out before all checks completed"

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
    print("OMNIHERMES - MULTI-FACTOR VERIFICATION REPORT")
    print("=" * 60)
    print(f"- Enrolled Owner:         {owner_name}")
    print(f"- Face Detected:          {face_seen}")
    print(f"- SFace Facial Similarity:{best_similarity: .4f}  (Threshold: {biometrics.cosine_threshold:.4f}) -> {'PASS' if best_similarity >= biometrics.cosine_threshold else 'FAIL'}")
    print(f"- MiniFASNet Real Score:  {minifas_score: .4f}  (Threshold: 0.6000, Spoofs: {spoofs_detected}/{total_eval_frames}) -> {'PASS' if as_summary['passed'] else 'FAIL'}")
    print(f"- Dynamic Blink Challenge:{liveness.blink_count}/2 blinks (Min EAR: {liveness.min_ear_observed:.4f}) -> {'PASS' if liveness.blink_count >= 2 else 'FAIL'}")
    print(f"- 3D Parallax Consistency:{liveness.max_parallax_shift: .4f} shift (Threshold: 0.0250) -> {'PASS' if liveness.parallax_passed else 'FAIL'}")
    print(f"- Overall Liveness Score: {evidence_liveness: .4f}  (Measured from real evidence)")
    print(f"- VERDICT:                {decision}")
    print(f"- REASON:                 {reason}")
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
