# OmniHermes — Verification Test Guide 🛡️👁️

This guide outlines how to execute the core verification tests for **OmniHermes**, either live using your webcam or offline using image/video sources.

---

## Prerequisites

1. Ensure all model weights are downloaded and verified:
   ```bash
   python -c "from omnihermes.models import ensure_models; print(ensure_models())"
   ```
2. Ensure your primary profile is enrolled:
   ```bash
   python -m omnihermes.enroll --name "Your Name" --primary
   ```
   *(Note: Enrollment allows up to 5 minutes [300s] with a live HUD countdown timer. You must perform two sequential challenges: first blinking twice, then a randomized head motion).*

3. You can list connected camera devices at any time:
   ```bash
   python -m omnihermes.verify --list-cameras
   ```

---

## Architecture: Multi-Layer Biometric Verification

OmniHermes evaluates four independent criteria before approving any high-risk tool execution:
1. **Face Detection & Alignment:** YuNet identifies the face bbox and 5-point facial landmarks.
2. **Passive Anti-Spoofing (MiniFASNetV2-SE):** Evaluates texture, screen moiré, and color distributions over $\ge 10$ frames via OpenCV DNN. Requires average real confidence $\ge 0.60$ and $\le 2$ spoof-classified frames.
3. **Active Multi-Challenge Liveness:**
   - **Challenge 1 (Mandatory):** `blink_twice` — verifies dynamic Eye Aspect Ratio (EAR) dip ($< 0.21$) and full recovery ($> 0.26$).
   - **Challenge 2 (Randomized Pose + Parallax):** Randomly requests `turn_left`, `turn_right`, `nod_down`, or `nod_up`. A **3D parallax geometric consistency check** measures the nose displacement ratio $R(t) = \frac{x_{\text{nose}} - x_{\text{right}}}{x_{\text{left}} - x_{\text{right}}}$. Real heads exhibit parallax shift $\Delta R \ge 0.05$. A rotated flat photo preserves planar symmetry ($\Delta R < 0.01$) and is rejected.
4. **SFace 128-d Identity Match:** Measures cosine similarity against the encrypted profile. Must meet or exceed the OpenCV recommended threshold ($0.3630$).

The composite liveness score is calculated entirely from measured evidence:
$$\text{Liveness} = 0.50 \times \text{MiniFASNet} + 0.30 \times \text{Blink} + 0.20 \times \text{Parallax}$$

---

## The 4 Verification Tests

### Test 1: Genuine Owner
- **Goal:** Verify that the registered owner passes both the SFace facial similarity match, MiniFASNet anti-spoofing, and both active liveness challenges.
- **Webcam Command:**
   ```bash
   python -m omnihermes.verify
   ```
   *(Or with custom camera index: `python -m omnihermes.verify --camera 0`)*
- **Action:** Sit in front of the camera. The on-screen HUD will instruct you to:
  1. *Blink twice* (EAR dip and recovery).
  2. *Perform randomized movement* (e.g., *Turn head to the LEFT*).
- **Expected Result:**
  - `Face Detected: True`
  - `MiniFASNet Real Conf: > 0.60` (spoof frames $\le 2$)
  - `Challenge 1 (blink_twice): PASSED ✔`
  - `Challenge 2 (pose + parallax): PASSED ✔` (parallax shift $\ge 0.05$)
  - `SFace Cosine Similarity: >= 0.3630` (typically 0.70 – 0.85)
  - `Liveness Score: > 0.8000`
  - `VERDICT: APPROVED ✔`

---

### Test 2: Different Person (Impostor)
- **Goal:** Verify that an impostor is rejected based on SFace embedding mismatch, even if they complete the liveness challenges.
- **Webcam Command:**
   ```bash
   python -m omnihermes.verify
   ```
- **Action:** Have another person sit in front of the camera and complete the liveness challenges.
- **Offline / Image Check (Similarity Only):**
   ```bash
   python -m omnihermes.verify --identity-only --image path/to/other_person.jpg
   ```
- **Expected Result:**
  - `Face Detected: True`
  - `SFace Cosine Similarity: < 0.3630` (typically -0.10 to 0.25)
  - `VERDICT: REJECTED_IMPOSTOR ✖`
  - `REASON: Face similarity below threshold (0.3630)`

---

### Test 3: Photo Spoof / Screen Replay Attack (CRITICAL SECURITY TEST)
- **Goal:** Verify that holding up a printed photograph or smartphone screen displaying the owner's photo is **REJECTED**, defeating presentation and flat rotation attacks.
- **Webcam Command:**
   ```bash
   python -m omnihermes.verify
   ```
- **Test Scenarios & Expected Verdicts:**
  1. **Static Photo or Phone Screen Held Still:**
     - A flat photo cannot blink. The first challenge (`blink_twice`) fails.
     - MiniFASNet detects display moiré / paper texture and flags spoof frames.
     - `VERDICT: REJECTED_NO_BLINK ✖` or `REJECTED_SPOOF_DETECTED ✖`
  2. **Tilting / Rotating a Flat Photo:**
     - Rotating a flat picture fools naive 2D pose estimators, but the planar parallax ratio remains flat ($\Delta R < 0.01$).
     - The 3D parallax check fails the threshold ($\ge 0.05$).
     - `VERDICT: REJECTED_NO_PARALLAX ✖` or `REJECTED_NO_BLINK ✖`
- **Expected Terminal Output:**
   ```text
   • Face Detected:          True
   • SFace Cosine Similarity: 0.4152  (Threshold: 0.3630) [Identity matches owner]
   • MiniFASNet Score:        0.1840  (Threshold: 0.6000, Spoof Frames: 8/10)
   • Challenge 1 (Blink):     FAILED ✖
   • Challenge 2 (Parallax):  FAILED ✖ (Shift: 0.0041 < 0.0500)
   • VERDICT:                 REJECTED_NO_BLINK ✖ (or REJECTED_SPOOF_DETECTED ✖)
   ```

---

### Test 4: Camera Covered / Obstructed
- **Goal:** Verify that an obstructed, dark, or disconnected camera is safely blocked (fail-closed).
- **Webcam Command:**
   ```bash
   python -m omnihermes.verify
   ```
- **Action:** Cover your webcam lens with tape, a finger, or a physical shutter.
- **Expected Result:**
  - `Face Detected: False`
  - `SFace Cosine Similarity: 0.0000`
  - `VERDICT: REJECTED_NO_FACE ✖`
  - `REASON: No face detected in camera view (camera covered or user absent)`

---

## Hermes Unlock Window (`/omnihermes unlock`)

When executing multi-step agent tasks in Hermes, repeatedly triggering the 22-second in-hook dialog can interrupt agent autonomy.

To solve this securely:
1. Run the unlock command:
   ```bash
   python -m omnihermes.unlock
   ```
   *(Or within Hermes chat: `/omnihermes unlock`)*
2. Complete the 5-minute interactive biometric check.
3. On success, an **Unlock Window** is granted for **120 seconds** (configurable):
   - High-risk operations matching policy pass during this window without opening the camera dialog.
   - **Stepping Away Revocation:** If the background desk presence monitor detects that you stepped away (`STATUS: AWAY`), the unlock window is **instantly revoked**, failing closed.

---

## Diagnostics & Troubleshooting Options

- **Custom Timeout:**  
  Adjust verification timeout (default 300 seconds / 5 minutes):
  ```bash
  python -m omnihermes.verify --timeout 60
  ```
- **Custom Data Directory:**  
  ```bash
  python -m omnihermes.verify --data-dir path/to/dir
  ```
- **Cryptographic Audit Integrity:**  
  Verify the tamper-evident SHA-256 hash chain of all audit entries:
  ```bash
  python -c "from omnihermes.audit import AuditLogger; print(AuditLogger().verify_integrity())"
  ```
- **Unit and Regression Test Suite:**  
  Run all automated unit and fixture tests:
  ```bash
  python -m unittest discover tests -v
  ```
