"""Presence Gate — Simulated Walkthrough Runner.

[SIMULATED] This is a mock simulation demonstrating plugin logic flow.
It does NOT use a live webcam or real Hermes execution.
For live hardware testing, use:
    python -m presence.enroll --name "Elijah" --primary
    python -m presence.verify
"""

import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.biometrics import BiometricEngine
from core.policy import PolicyEngine
from core.audit import AuditLogger
from core.away import PresenceMonitor
import __init__ as presence_gate


def print_banner():
    banner = r"""
============================================================
[SIMULATED] PRESENCE GATE — AUTOMATED FLOW SIMULATION
============================================================
NOTE: This walkthrough simulates agent interception, biometric
thresholding, and away-detection logic without touching hardware.
============================================================
    """
    print("\033[93m" + banner + "\033[0m")


def run_simulation():
    print_banner()

    policy = presence_gate.get_policy()
    audit = presence_gate.get_audit()
    presence = presence_gate.get_presence()

    # Step 1: Simulated enrollment
    print("\033[1;33m[STEP 1/5] [SIMULATED] Enrolling Mock Profile ('Elijah')...\033[0m")
    time.sleep(1)
    dummy_vec = [0.1] * 128
    presence_gate.handle_presence_enroll({"owner_name": "Elijah", "test_embedding": dummy_vec})
    print("  \033[32m✔ Simulated profile created: 128-d vector encrypted with AES-256-GCM.\033[0m\n")
    time.sleep(1)

    # Step 2: Benign action allowed
    print("\033[1;33m[STEP 2/5] [SIMULATED] Agent executes benign tool: 'read_file'\033[0m")
    res1 = presence_gate.on_pre_tool_call(tool_name="read_file", arguments={"path": "README.md"})
    print(f"  \033[32m✔ Policy Assessment: Low Risk -> Action Allowed: {res1}\033[0m\n")
    time.sleep(1)

    # Step 3: High-risk action intercepted
    print("\033[1;33m[STEP 3/5] [SIMULATED] Intercepting High-Risk Tool: terminal ('rm -rf /test')\033[0m")
    print("  \033[36m⚡ Guard Triggered: 'terminal' command matches destructive pattern 'rm -rf'.\033[0m")
    time.sleep(1)

    presence.mark_seen("Elijah")
    audit.log_event(
        event_type="INTERCEPT_APPROVED",
        user_name="Elijah",
        tool_name="terminal",
        action="rm -rf /test",
        result="APPROVED",
        similarity_score=0.82,
        liveness_score=0.95,
        details={"risk_level": "HIGH", "simulated": True},
    )
    print("  \033[32m✔ Biometric Verification: Owner Confirmed (Similarity: 0.8200 >= 0.3630, Liveness: 0.9500)\033[0m")
    print("  \033[32m✔ Execution authorized!\033[0m\n")
    time.sleep(1.5)

    # Step 4: Impostor and photo attack simulation
    print("\033[1;33m[STEP 4/5] [SIMULATED] Impostor & Photo Spoof Defense\033[0m")
    audit.log_event(
        event_type="INTERCEPT_REJECTED",
        user_name="Candidate",
        tool_name="terminal",
        action="git push --force",
        result="REJECTED_IMPOSTOR",
        similarity_score=0.18,
        liveness_score=0.90,
        details={"simulated": True},
    )
    print("  \033[31m✖ Attack 1: Impostor mismatch (Similarity: 0.1800 < 0.3630) -> BLOCKED\033[0m")
    time.sleep(1)

    audit.log_event(
        event_type="INTERCEPT_REJECTED",
        user_name="Candidate",
        tool_name="terminal",
        action="sudo reboot",
        result="REJECTED_LIVENESS_FAILED",
        similarity_score=0.85,
        liveness_score=0.12,
        details={"simulated": True},
    )
    print("  \033[31m✖ Attack 2: Printed photo spoof (Liveness: 0.1200 < 0.8000) -> BLOCKED\033[0m\n")
    time.sleep(1.5)

    # Step 5: Away detection
    print("\033[1;33m[STEP 5/5] [SIMULATED] Desk Absence Tracking\033[0m")
    presence.mark_away()
    print("  \033[33m⚡ Presence status: [AWAY] (Workstation unattended)\033[0m")
    away_check = presence_gate.on_pre_tool_call(tool_name="terminal", arguments={"command": "npm publish"})
    print(f"  \033[31m✖ Intercepted & Paused: {away_check['message']}\033[0m\n")
    time.sleep(1)

    # Cryptographic Audit Verification
    print("\033[1;36m[AUDIT VERIFICATION] Checking SHA-256 Tamper-Evident Chain...\033[0m")
    audit_report = audit.verify_integrity()
    print(f"  \033[32m✔ Audit Status: {audit_report['message']}\033[0m\n")

    print("\033[92m============================================================\033[0m")
    print("\033[92m✔ Simulated Walkthrough Completed.\033[0m")
    print("\033[92m============================================================\033[0m")


if __name__ == "__main__":
    run_simulation()

