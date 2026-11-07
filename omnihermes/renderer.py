"""Modern visual HUD rendering engine for OmniHermes.

Provides professional visual components:
- Semi-transparent rounded navy panels
- Vector shield and challenge icons
- Anti-aliased Segoe UI font rendering via PIL
- Adaptive face positioning guide (turns Teal when aligned)
- Animated challenge arrows and progress bars
- Success and failure closing screens (2s display)
- Live debug overlay (toggled with 'D' key)
"""

from __future__ import annotations

import math
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

# Brand Color Palette (OpenCV BGR Format)
COLOR_NAVY_BG = (26, 18, 12)       # #0C121A
COLOR_PANEL_BG = (43, 30, 20)      # #141E2B
COLOR_PANEL_BORDER = (75, 55, 38)  # #26374B
COLOR_WHITE = (255, 255, 255)
COLOR_SLATE = (180, 160, 140)
COLOR_MUTED = (120, 105, 90)

COLOR_TEAL = (166, 184, 20)        # #14B8A6 (Progress, Verified, Pass)
COLOR_AMBER = (11, 158, 245)       # #F59E0B (Instructions, Active Guidance)
COLOR_RED = (68, 68, 239)          # #EF4444 (Failure, Alert, Warnings)

# Font loading with fallback
FONT_REGULAR_PATH = Path("C:/Windows/Fonts/segoeui.ttf")
FONT_BOLD_PATH = Path("C:/Windows/Fonts/segoeuib.ttf")

_fonts_cache: Dict[Tuple[str, int], ImageFont.FreeTypeFont] = {}


def get_font(size: int = 14, bold: bool = False) -> Optional[ImageFont.FreeTypeFont]:
    """Load cached FreeType font from Windows system fonts."""
    key = ("bold" if bold else "regular", size)
    if key in _fonts_cache:
        return _fonts_cache[key]

    target_path = FONT_BOLD_PATH if bold else FONT_REGULAR_PATH
    if not target_path.exists():
        target_path = FONT_REGULAR_PATH
    if not target_path.exists():
        target_path = Path("C:/Windows/Fonts/arial.ttf")

    if target_path.exists():
        try:
            f = ImageFont.truetype(str(target_path), size)
            _fonts_cache[key] = f
            return f
        except Exception:
            pass
    return None


def draw_rounded_rect(
    img: np.ndarray,
    pt1: Tuple[int, int],
    pt2: Tuple[int, int],
    color: Tuple[int, int, int],
    radius: int = 12,
    thickness: int = -1,
) -> None:
    """Draw a rectangle with rounded corners."""
    x1, y1 = pt1
    x2, y2 = pt2
    w = x2 - x1
    h = y2 - y1
    r = min(radius, w // 2, h // 2)

    if thickness == -1:
        # Fill center body and edge blocks
        cv2.rectangle(img, (x1 + r, y1), (x2 - r, y2), color, -1)
        cv2.rectangle(img, (x1, y1 + r), (x2, y2 - r), color, -1)
        # Fill four corner circles
        cv2.circle(img, (x1 + r, y1 + r), r, color, -1)
        cv2.circle(img, (x2 - r, y1 + r), r, color, -1)
        cv2.circle(img, (x1 + r, y2 - r), r, color, -1)
        cv2.circle(img, (x2 - r, y2 - r), r, color, -1)
    else:
        # Draw outlines
        cv2.line(img, (x1 + r, y1), (x2 - r, y1), color, thickness)
        cv2.line(img, (x1 + r, y2), (x2 - r, y2), color, thickness)
        cv2.line(img, (x1, y1 + r), (x1, y2 - r), color, thickness)
        cv2.line(img, (x2, y1 + r), (x2, y2 - r), color, thickness)
        cv2.ellipse(img, (x1 + r, y1 + r), (r, r), 180, 0, 90, color, thickness)
        cv2.ellipse(img, (x2 - r, y1 + r), (r, r), 270, 0, 90, color, thickness)
        cv2.ellipse(img, (x2 - r, y2 - r), (r, r), 0, 0, 90, color, thickness)
        cv2.ellipse(img, (x1 + r, y2 - r), (r, r), 90, 0, 90, color, thickness)


def draw_panel(
    frame: np.ndarray,
    pt1: Tuple[int, int],
    pt2: Tuple[int, int],
    bg_color: Tuple[int, int, int] = COLOR_PANEL_BG,
    alpha: float = 0.85,
    radius: int = 12,
    border_color: Tuple[int, int, int] = COLOR_PANEL_BORDER,
) -> None:
    """Render a semi-transparent panel with rounded corners and border."""
    overlay = frame.copy()
    draw_rounded_rect(overlay, pt1, pt2, bg_color, radius=radius, thickness=-1)
    cv2.addWeighted(overlay, alpha, frame, 1.0 - alpha, 0, frame)
    draw_rounded_rect(frame, pt1, pt2, border_color, radius=radius, thickness=1)


def draw_shield_icon(
    frame: np.ndarray,
    center: Tuple[int, int],
    size: int = 16,
    color: Tuple[int, int, int] = COLOR_AMBER,
    state: str = "checking",
) -> None:
    """Draw a vector security shield with symbol strictly matching the verification state:
    - "checking": Amber shield with padlock (NEVER a checkmark!)
    - "verified": Teal shield with crisp checkmark (only on APPROVED)
    - "denied": Red shield with crisp 'X' cross
    """
    cx, cy = center
    s = size
    pts = np.array([
        [cx - s, cy - s],
        [cx + s, cy - s],
        [cx + s, cy],
        [cx, cy + s + s // 3],
        [cx - s, cy],
    ], dtype=np.int32)
    cv2.fillPoly(frame, [pts], color)
    cv2.polylines(frame, [pts], True, (255, 255, 255), 1, cv2.LINE_AA)

    if state in ("verified", "success") or (state == "auto" and color == COLOR_TEAL):
        # Crisp vector checkmark ONLY on verified/success
        check_pts = np.array([
            [cx - s // 2, cy],
            [cx - s // 6, cy + s // 3],
            [cx + s // 2, cy - s // 3],
        ], dtype=np.int32)
        cv2.polylines(frame, [check_pts], False, (255, 255, 255), 2, cv2.LINE_AA)
    elif state in ("denied", "failure", "error", "mismatch") or (state == "auto" and color == COLOR_RED):
        # Crisp vector cross
        cv2.line(frame, (cx - s // 2 + 1, cy - s // 2 + 1), (cx + s // 2 - 1, cy + s // 2 - 1), (255, 255, 255), 2, cv2.LINE_AA)
        cv2.line(frame, (cx + s // 2 - 1, cy - s // 2 + 1), (cx - s // 2 + 1, cy + s // 2 - 1), (255, 255, 255), 2, cv2.LINE_AA)
    else:
        # Checking / Active Guidance (AMBER): Clean padlock
        bw, bh = max(3, s // 2), max(3, s // 3 + 1)
        # Padlock body
        cv2.rectangle(frame, (cx - bw, cy), (cx + bw, cy + bh + 1), (255, 255, 255), -1)
        # Padlock shackle
        cv2.ellipse(frame, (cx, cy), (bw - 2, max(2, bh - 1)), 180, 0, 180, (255, 255, 255), 2, cv2.LINE_AA)
        # Keyhole dot
        cv2.circle(frame, (cx, cy + bh // 2), 1, color, -1)


def render_text_pil(
    frame: np.ndarray,
    text: str,
    pos: Tuple[int, int],
    font_size: int = 14,
    color: Tuple[int, int, int] = COLOR_WHITE,
    bold: bool = False,
) -> None:
    """Render anti-aliased text using Windows Segoe UI font."""
    font = get_font(size=font_size, bold=bold)
    if font is None:
        cv_scale = font_size / 28.0
        cv2.putText(
            frame,
            text,
            (pos[0], pos[1] + font_size),
            cv2.FONT_HERSHEY_DUPLEX,
            cv_scale,
            color,
            1,
            cv2.LINE_AA,
        )
        return

    # Convert BGR to RGB for PIL
    rgb_color = (color[2], color[1], color[0])
    pil_img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
    draw = ImageDraw.Draw(pil_img)
    draw.text(pos, text, font=font, fill=rgb_color)
    res_bgr = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)
    np.copyto(frame, res_bgr)


def draw_face_guide(
    frame: np.ndarray,
    cx: int,
    cy: int,
    w: int = 180,
    h: int = 230,
    is_aligned: bool = False,
    override_color: Optional[Tuple[int, int, int]] = None,
) -> None:
    """Centred face guide brackets. Turns Teal when face matches, Red on mismatch, Amber while checking."""
    if override_color is not None:
        color = override_color
    else:
        color = COLOR_TEAL if is_aligned else COLOR_AMBER
    x1, y1 = cx - w // 2, cy - h // 2
    x2, y2 = cx + w // 2, cy + h // 2
    arm_len = 30
    thick = 3

    # Draw rounded corner brackets
    # Top-left
    cv2.line(frame, (x1, y1), (x1 + arm_len, y1), color, thick, cv2.LINE_AA)
    cv2.line(frame, (x1, y1), (x1, y1 + arm_len), color, thick, cv2.LINE_AA)
    # Top-right
    cv2.line(frame, (x2, y1), (x2 - arm_len, y1), color, thick, cv2.LINE_AA)
    cv2.line(frame, (x2, y1), (x2, y1 + arm_len), color, thick, cv2.LINE_AA)
    # Bottom-left
    cv2.line(frame, (x1, y2), (x1 + arm_len, y2), color, thick, cv2.LINE_AA)
    cv2.line(frame, (x1, y2), (x1, y2 - arm_len), color, thick, cv2.LINE_AA)
    # Bottom-right
    cv2.line(frame, (x2, y2), (x2 - arm_len, y2), color, thick, cv2.LINE_AA)
    cv2.line(frame, (x2, y2), (x2, y2 - arm_len), color, thick, cv2.LINE_AA)


def draw_animated_arrow(
    frame: np.ndarray,
    center: Tuple[int, int],
    direction: str,
    tick: int = 0,
    color: Tuple[int, int, int] = COLOR_TEAL,
) -> None:
    """Draw a bold animated directional chevron / arrow."""
    cx, cy = center
    pulse = int(math.sin(tick * 0.18) * 8)
    arrow_size = 22

    if direction == "turn_left":
        px = cx + pulse
        pts = np.array([
            [px + arrow_size, cy - arrow_size],
            [px, cy],
            [px + arrow_size, cy + arrow_size],
        ], dtype=np.int32)
        cv2.polylines(frame, [pts], False, color, 4, cv2.LINE_AA)
        cv2.line(frame, (px + arrow_size * 2, cy), (px, cy), color, 4, cv2.LINE_AA)
    elif direction == "turn_right":
        px = cx - pulse
        pts = np.array([
            [px - arrow_size, cy - arrow_size],
            [px, cy],
            [px - arrow_size, cy + arrow_size],
        ], dtype=np.int32)
        cv2.polylines(frame, [pts], False, color, 4, cv2.LINE_AA)
        cv2.line(frame, (px - arrow_size * 2, cy), (px, cy), color, 4, cv2.LINE_AA)
    elif direction == "nod_down":
        py = cy - pulse
        pts = np.array([
            [cx - arrow_size, py - arrow_size],
            [cx, py],
            [cx + arrow_size, py - arrow_size],
        ], dtype=np.int32)
        cv2.polylines(frame, [pts], False, color, 4, cv2.LINE_AA)
        cv2.line(frame, (cx, py - arrow_size * 2), (cx, py), color, 4, cv2.LINE_AA)


def draw_progress_bar(
    frame: np.ndarray,
    pt: Tuple[int, int],
    width: int,
    height: int,
    progress: float,
    bar_color: Tuple[int, int, int] = COLOR_TEAL,
    label: str = "",
) -> None:
    """Render a modern progress bar with rounded edges and label."""
    x, y = pt
    progress_clamped = max(0.0, min(1.0, progress))
    fill_w = int(width * progress_clamped)

    # Background
    draw_rounded_rect(frame, (x, y), (x + width, y + height), (40, 30, 22), radius=height // 2, thickness=-1)
    if fill_w > 4:
        draw_rounded_rect(frame, (x, y), (x + fill_w, y + height), bar_color, radius=height // 2, thickness=-1)
    draw_rounded_rect(frame, (x, y), (x + width, y + height), COLOR_PANEL_BORDER, radius=height // 2, thickness=1)

    if label:
        render_text_pil(frame, label, (x + width + 10, y - 2), font_size=13, color=COLOR_WHITE, bold=True)


def draw_debug_overlay(frame: np.ndarray, debug: Dict[str, Any]) -> None:
    """Live telemetry overlay showing real-time numbers, toggled with 'D'."""
    h, w = frame.shape[:2]
    dw = 320
    dh = 265
    dx = w - dw - 15
    dy = 75

    draw_panel(frame, (dx, dy), (dx + dw, dy + dh), bg_color=(20, 14, 10), alpha=0.92, radius=8)
    render_text_pil(frame, "TELEMETRY [D: Hide]", (dx + 12, dy + 8), font_size=12, color=COLOR_TEAL, bold=True)

    lines = [
        f"Yaw:   {debug.get('yaw', 0.0):+.1f} deg | Base: {debug.get('baseline_yaw', 0.0):+.1f} | Δ: {debug.get('delta_yaw', 0.0):+.1f}",
        f"Pitch: {debug.get('pitch', 0.0):+.1f} deg | Base: {debug.get('baseline_pitch', 0.0):+.1f} | Δ: {debug.get('delta_pitch', 0.0):+.1f}",
        f"Turn Ratio: {debug.get('turn_ratio', 0.0):.3f} | Base: {debug.get('baseline_turn_ratio', 0.0):.3f} | Δ: {debug.get('delta_turn_ratio', 0.0):+.3f}",
        f"Nod Ratio:  {debug.get('nod_ratio', 0.0):.3f} | Base: {debug.get('baseline_nod_ratio', 0.0):.3f} | Δ: {debug.get('delta_nod_ratio', 0.0):+.3f}",
        f"Angle Met:  {'YES' if debug.get('angle_threshold_met') else 'no'} | Ratio Met: {'YES' if debug.get('ratio_threshold_met') else 'no'}",
        f"Hold Frames: {debug.get('hold_frames', 0)}/2 (Req: >= 2)",
        f"Blinks:      {debug.get('blink_count', 0)}/2 (EAR: {debug.get('current_ear', 0.0):.3f})",
        f"MiniFASNet:  {debug.get('minifas_score', 0.0):.3f} (Req >= 0.60)",
        f"3D Parallax: {debug.get('max_parallax_shift', 0.0):.4f} (Req >= 0.025)",
        f"Challenge Left: {debug.get('challenge_time_remaining', 15)}s (Retries: {debug.get('challenge_retries', 0)})",
    ]

    cur_y = dy + 32
    for line in lines:
        render_text_pil(frame, line, (dx + 12, cur_y), font_size=11, color=COLOR_SLATE)
        cur_y += 22


def render_closing_screen(
    frame: np.ndarray,
    success: bool,
    title: str,
    subtitle: str,
) -> np.ndarray:
    """Render final success or failure card over the frame with vector shapes (no unicode box bugs)."""
    h, w = frame.shape[:2]
    out = frame.copy()

    # Darken background
    darken = np.zeros_like(out)
    cv2.addWeighted(out, 0.30, darken, 0.70, 0, out)

    card_w = min(480, w - 30)
    card_h = 150
    cx, cy = w // 2, h // 2
    x1, y1 = cx - card_w // 2, cy - card_h // 2
    x2, y2 = cx + card_w // 2, cy + card_h // 2

    accent_color = COLOR_TEAL if success else COLOR_RED
    draw_panel(out, (x1, y1), (x2, y2), bg_color=(24, 17, 12), alpha=0.96, radius=16, border_color=accent_color)

    # Vector Icon Badge
    badge_cx = x1 + 52
    badge_cy = cy
    draw_rounded_rect(out, (badge_cx - 26, badge_cy - 26), (badge_cx + 26, badge_cy + 26), accent_color, radius=12, thickness=-1)

    if success:
        # Crisp vector checkmark
        pts = np.array([
            [badge_cx - 12, badge_cy],
            [badge_cx - 3, badge_cy + 9],
            [badge_cx + 13, badge_cy - 8],
        ], dtype=np.int32)
        cv2.polylines(out, [pts], False, (255, 255, 255), 3, cv2.LINE_AA)
    else:
        # Crisp vector cross
        cv2.line(out, (badge_cx - 10, badge_cy - 10), (badge_cx + 10, badge_cy + 10), (255, 255, 255), 3, cv2.LINE_AA)
        cv2.line(out, (badge_cx + 10, badge_cy - 10), (badge_cx - 10, badge_cy + 10), (255, 255, 255), 3, cv2.LINE_AA)

    # Clean text without symbol glyphs
    render_text_pil(out, title, (x1 + 96, cy - 24), font_size=20, color=COLOR_WHITE, bold=True)
    render_text_pil(out, subtitle, (x1 + 96, cy + 8), font_size=13, color=COLOR_SLATE)

    return out

