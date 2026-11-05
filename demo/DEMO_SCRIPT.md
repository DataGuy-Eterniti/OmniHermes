# Presence Gate — 90-Second Demo Video Script 🎬

> **Hackathon Submission Video Guide**  
> *Target Duration: < 90 seconds*  
> *Format: Screen capture with webcam picture-in-picture (or split screen)*

---

## Pre-Recording Checklist

1. **Enrolled Owner:** Ensure Elijah is enrolled:
   ```bash
   python -m presence.enroll --name "Elijah" --primary
   ```
2. **Test Folder:** Create a harmless dummy folder for the deletion demo:
   ```bash
   mkdir test_dir
   ```
3. **Props Ready:**
   - A printed photograph of Elijah or a smartphone displaying Elijah's photo.
   - A friend/colleague ready for the impostor attempt (or an alternate face photo).

---

## 90-Second Scene-by-Scene Timeline

### 0:00 – 0:12 | Scene 1: Introduction & Security Posture
- **Visual:** Terminal showing Hermes Agent running with Presence Gate active. Hermes Desktop status bar displays `🛡️ Presence: Protected`.
- **Narration:**  
  *"Autonomous agents have real shell access, financial authority, and API keys, but approvals are just text prompts anyone can click. Presence Gate gives Hermes hardware-verified physical identity."*

---

### 0:12 – 0:25 | Scene 2: Benign Action Passes Instantly
- **Action:** Ask Hermes to inspect a safe local file:
  ```text
  "Hermes, read the project README.md"
  ```
- **Visual:** Hermes calls `read_file`. Presence Gate's `pre_tool_call` hook checks the policy, classifies it as `LOW` risk, and lets it execute immediately without prompting.
- **Narration:**  
  *"Benign workspace operations execute with zero friction."*

---

### 0:25 – 0:45 | Scene 3: High-Risk Shell Command & Live Face Authorization
- **Action:** Ask Hermes to execute a dangerous command:
  ```text
  "Hermes, delete the test_dir folder using rm -rf"
  ```
- **Visual:**
  - Presence Gate intercepts `terminal` matching `rm -rf`.
  - The camera modal opens with the active challenge: *"Turn your head to the LEFT"* (or *"Blink twice"*).
  - Elijah looks at the camera, completes the challenge.
  - SFace cosine similarity matches (> 0.3630). Bounding box flashes green `✔ APPROVED`.
  - Hermes executes the command and reports success.
- **Narration:**  
  *"When a destructive terminal command is issued, Presence Gate pauses execution. It requires real face recognition and an unpredictable live challenge. I verify, and the action proceeds."*

---

### 0:45 – 0:60 | Scene 4: Impostor & Photo Spoof Rejection
- **Action:**
  1. Have a second person attempt an action $\rightarrow$ rejected (`REJECTED_IMPOSTOR`, similarity < 0.3630).
  2. Hold up Elijah's photo on a phone screen $\rightarrow$ rejected (`REJECTED_LIVENESS_FAILED`, zero dynamic Eye Aspect Ratio movement, challenge fails).
- **Narration:**  
  *"An impostor sitting at the computer is blocked by identity mismatch. Holding up a static photo of me fails the randomized eye-blink and head pose challenge."*

---

### 0:60 – 0:75 | Scene 5: Desk Absence Tracking
- **Action:** Elijah steps away from the chair. The status indicator switches to `🔒 Presence: Away (Locked)`.
- **Action:** Issue another sensitive command (e.g. `npm publish`).
- **Visual:** Action is quarantined instantly:  
  `"Presence: action 'terminal' paused: workstation owner is away."`
- **Narration:**  
  *"If I step away from my desk, Presence Gate automatically quarantines dangerous operations until I return."*

---

### 0:75 – 0:90 | Scene 6: Cryptographic Audit Ledger & Conclusion
- **Action:** View the audit log:
  ```bash
  python -c "from presence.audit import AuditLogger; print(AuditLogger().verify_integrity())"
  ```
- **Visual:** Shows SHA-256 hash-chained entries verifying 100% tamper-evident integrity.
- **Narration:**  
  *"Every decision is logged to an immutable SHA-256 hash chain with zero raw face photos stored. Presence Gate makes Hermes safe for production."*

---

## Recording Tips
- Keep camera lighting clear and even.
- Make sure terminal font size is set to at least 16pt for readability on mobile/X video feeds.
- End the video on the verified audit output and the Nous Research hackathon tag!

