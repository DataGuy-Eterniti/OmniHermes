"""Biometric Authorization Dialog for Presence Gate.

Displays a security modal with live webcam feedback, active liveness challenge,
and biometric authorization prompt when high-risk actions are intercepted.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

import cv2
import numpy as np
from PIL import Image, ImageTk

try:
    import tkinter as tk
except ImportError:
    tk = None

try:
    from ..presence.biometrics import BiometricEngine
    from ..presence.liveness import LivenessSession
except (ImportError, ValueError):
    from presence.biometrics import BiometricEngine
    from presence.liveness import LivenessSession


class BiometricAuthDialog:
    """Tkinter-based verification window with camera feed and active liveness challenge."""

    def __init__(
        self,
        tool_name: str,
        action_summary: str,
        risk_level: str,
        engine: BiometricEngine,
        timeout_seconds: int = 18,
        camera_index: int = 0,
    ):
        self.tool_name = tool_name
        self.action_summary = action_summary
        self.risk_level = risk_level
        self.engine = engine
        self.timeout_seconds = min(timeout_seconds, 24)  # Strictly under 25s for Hermes hook safety
        self.camera_index = camera_index

        self.result: Dict[str, Any] = {
            "approved": False,
            "reason": "TIMEOUT",
            "message": "Biometric authorization timed out.",
            "confidence": 0.0,
            "liveness_score": 0.0,
        }
        self._running = False
        self._start_time = 0.0

    def run_dialog(self) -> Dict[str, Any]:
        """Launch the authorization dialog. Blocks until approved, rejected, or timed out."""
        # Fail closed immediately if no display environment (e.g. gateway/headless/cron/SSH)
        if tk is None or not os.environ.get("DISPLAY", "") and os.name != "nt":
            return {
                "approved": False,
                "reason": "HEADLESS_OR_NO_DISPLAY",
                "message": "Presence: this action needs face verification at Elijah's computer.",
                "confidence": 0.0,
                "liveness_score": 0.0,
            }

        try:
            root = tk.Tk()
        except Exception:
            return {
                "approved": False,
                "reason": "NO_DISPLAY_FOUND",
                "message": "Presence: this action needs face verification at Elijah's computer.",
                "confidence": 0.0,
                "liveness_score": 0.0,
            }

        root.title("Presence Gate — Security Authorization")
        root.geometry("520x640")
        root.resizable(False, False)
        root.configure(bg="#0F172A")

        owner_info = self.engine.get_owner_info() or {}
        owner_name = owner_info.get("owner_name", "Elijah")

        header_frame = tk.Frame(root, bg="#1E293B", padx=16, pady=12)
        header_frame.pack(fill=tk.X)

        title_lbl = tk.Label(
            header_frame,
            text="🛡️ PRESENCE GATE: AUTHORIZATION REQUIRED",
            font=("Segoe UI", 11, "bold"),
            fg="#F43F5E" if self.risk_level == "CRITICAL" else "#F59E0B",
            bg="#1E293B",
        )
        title_lbl.pack(anchor="w")

        risk_lbl = tk.Label(
            header_frame,
            text=f"Target: {self.tool_name}  |  Owner: {owner_name} (Primary)",
            font=("Segoe UI", 9),
            fg="#94A3B8",
            bg="#1E293B",
        )
        risk_lbl.pack(anchor="w", pady=(2, 0))

        action_frame = tk.Frame(root, bg="#1E293B", padx=12, pady=10)
        action_frame.pack(fill=tk.X, padx=16, pady=10)

        action_lbl = tk.Label(
            action_frame,
            text=f"Action:\n{self.action_summary}",
            font=("Segoe UI", 9),
            fg="#E2E8F0",
            bg="#1E293B",
            justify=tk.LEFT,
            wraplength=460,
        )
        action_lbl.pack(anchor="w")

        video_canvas = tk.Label(root, bg="#000000", width=480, height=320)
        video_canvas.pack(padx=16, pady=4)

        status_var = tk.StringVar(value="Initializing camera and liveness engine...")
        status_lbl = tk.Label(
            root,
            textvariable=status_var,
            font=("Segoe UI", 10, "bold"),
            fg="#38BDF8",
            bg="#0F172A",
            wraplength=460,
        )
        status_lbl.pack(pady=8)

        countdown_var = tk.StringVar(value=f"Expires in {self.timeout_seconds}s")
        countdown_lbl = tk.Label(
            root,
            textvariable=countdown_var,
            font=("Segoe UI", 8),
            fg="#64748B",
            bg="#0F172A",
        )
        countdown_lbl.pack()

        def on_cancel():
            self.result = {
                "approved": False,
                "reason": "USER_REJECTED",
                "message": "Action was manually rejected by the workstation owner.",
                "confidence": 0.0,
                "liveness_score": 0.0,
            }
            root.destroy()

        btn_frame = tk.Frame(root, bg="#0F172A")
        btn_frame.pack(fill=tk.X, padx=16, pady=12)

        cancel_btn = tk.Button(
            btn_frame,
            text="Reject / Abort Action",
            command=on_cancel,
            bg="#334155",
            fg="#F8FAFC",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=16,
            pady=6,
            cursor="hand2",
        )
        cancel_btn.pack(side=tk.RIGHT)

        # Open Webcam
        cap = cv2.VideoCapture(self.camera_index)
        if not cap.isOpened():
            root.destroy()
            return {
                "approved": False,
                "reason": "CAMERA_UNAVAILABLE",
                "message": "Presence Gate: Could not open camera device. Action blocked.",
                "confidence": 0.0,
                "liveness_score": 0.0,
            }

        liveness_session = LivenessSession(data_dir=self.engine.data_dir)
        self._start_time = time.time()
        self._running = True

        def update_frame():
            if not self._running or not root.winfo_exists():
                if cap.isOpened():
                    cap.release()
                return

            remaining = self.timeout_seconds - int(time.time() - self._start_time)
            if remaining <= 0:
                self.result = {
                    "approved": False,
                    "reason": "TIMEOUT",
                    "message": f"Presence verification timed out ({self.timeout_seconds}s limit). Action blocked.",
                    "confidence": 0.0,
                    "liveness_score": 0.0,
                }
                cap.release()
                root.destroy()
                return

            countdown_var.set(f"Expires in {remaining}s")

            ret, frame = cap.read()
            if ret and frame is not None:
                frame = cv2.flip(frame, 1)
                faces = self.engine.detect_faces(frame)
                live_res = liveness_session.process_frame(frame)

                current_sim = 0.0
                face_matched = False

                if len(faces) == 0:
                    status_var.set("No face detected — center your face in view")
                elif len(faces) > 1:
                    status_var.set("Multiple faces detected — ensure only you are visible")
                else:
                    primary_face = faces[0]
                    fx, fy = int(primary_face[0]), int(primary_face[1])
                    fw, fh = int(primary_face[2]), int(primary_face[3])

                    emb = self.engine.extract_embedding(frame, primary_face)
                    face_matched, current_sim = self.engine.match_against_owner(emb)

                    box_color = (0, 255, 128) if face_matched else (0, 0, 255)
                    cv2.rectangle(frame, (fx, fy), (fx + fw, fy + fh), box_color, 2)

                    if not face_matched:
                        status_var.set(f"Face mismatch ({current_sim:.2f} < {self.engine.cosine_threshold:.2f}) — Impostor")
                    elif not live_res["completed"]:
                        status_var.set(f"Challenge: {live_res['prompt']}")
                    else:
                        status_var.set("✔ Face and Liveness Verified! Approving...")
                        self.result = {
                            "approved": True,
                            "owner_name": owner_name,
                            "reason": "APPROVED",
                            "message": f"Verified in-person presence for {owner_name}.",
                            "confidence": round(float(current_sim), 4),
                            "liveness_score": round(float(live_res.get("liveness_score", 0.95)), 4),
                        }
                        self._running = False
                        root.after(350, root.destroy)
                        return

                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                rgb_resized = cv2.resize(rgb, (480, 320))
                img = Image.fromarray(rgb_resized)
                imgtk = ImageTk.PhotoImage(image=img)
                video_canvas.imgtk = imgtk
                video_canvas.configure(image=imgtk)

            root.after(30, update_frame)

        root.update_idletasks()
        win_w, win_h = 540, 560
        scr_w = root.winfo_screenwidth()
        scr_h = root.winfo_screenheight()
        pos_x = max(0, (scr_w - win_w) // 2)
        pos_y = max(0, (scr_h - win_h) // 2)
        root.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")
        root.after(50, update_frame)

        try:
            root.mainloop()
        finally:
            self._running = False
            if cap.isOpened():
                cap.release()

        return self.result
