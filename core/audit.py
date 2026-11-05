"""Tamper-evident cryptographic audit logger for Omnihermes.

Maintains an immutable SHA-256 hash-chained log of every authorization
request, liveness score, biometric verification outcome, and away-pause.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditLogger:
    """Manages an append-only, SHA-256 hash-chained audit log."""

    def __init__(self, log_path: Optional[Path] = None):
        if log_path is None:
            base_dir = Path.home() / ".hermes" / "omnihermes"
            base_dir.mkdir(parents=True, exist_ok=True)
            log_path = base_dir / "audit.jsonl"
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._compute_tip_hash()

    def _compute_tip_hash(self) -> str:
        """Find the last entry's hash in the log file, or return genesis hash."""
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return "0" * 64

        last_line = ""
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line

        if not last_line:
            return "0" * 64

        try:
            record = json.loads(last_line)
            return record.get("current_hash", "0" * 64)
        except Exception:
            return "0" * 64

    def log_event(
        self,
        event_type: str,
        tool_name: str,
        action_summary: str,
        result: str,
        confidence: float,
        liveness_score: float,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append a new audited event to the hash chain."""
        timestamp = time.time()
        iso_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))

        payload = {
            "timestamp": timestamp,
            "iso_time": iso_time,
            "event_type": event_type,
            "tool_name": tool_name,
            "action_summary": action_summary,
            "result": result,  # APPROVED, REJECTED_FACE, REJECTED_SPOOF, REJECTED_AWAY, TIMEOUT
            "confidence": round(confidence, 4),
            "liveness_score": round(liveness_score, 4),
            "details": details or {},
            "prev_hash": self._last_hash,
        }

        # Calculate current SHA-256 block hash
        serialized = json.dumps(payload, sort_keys=True)
        current_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        payload["current_hash"] = current_hash

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")

        self._last_hash = current_hash
        return payload

    def read_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Read the most recent N audit records."""
        if not self.log_path.exists():
            return []

        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        continue
        return entries[-limit:]

    def verify_integrity(self) -> Dict[str, Any]:
        """Verify the cryptographic integrity of the entire audit chain."""
        if not self.log_path.exists():
            return {"valid": True, "entries_checked": 0, "message": "Audit log is empty."}

        expected_prev = "0" * 64
        count = 0

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except Exception as e:
                    return {
                        "valid": False,
                        "broken_at_line": line_no,
                        "error": f"JSON parse error: {e}",
                    }

                current_hash = record.get("current_hash")
                prev_hash = record.get("prev_hash")

                if prev_hash != expected_prev:
                    return {
                        "valid": False,
                        "broken_at_line": line_no,
                        "error": f"Chain link broken: expected prev_hash {expected_prev}, got {prev_hash}",
                    }

                # Recompute hash
                payload_copy = dict(record)
                payload_copy.pop("current_hash", None)
                computed = hashlib.sha256(json.dumps(payload_copy, sort_keys=True).encode("utf-8")).hexdigest()

                if computed != current_hash:
                    return {
                        "valid": False,
                        "broken_at_line": line_no,
                        "error": f"Tampered record detected at line {line_no}",
                    }

                expected_prev = current_hash
                count += 1

        return {
            "valid": True,
            "entries_checked": count,
            "tip_hash": expected_prev,
            "message": f"Successfully verified {count} chained records. No tampering detected.",
        }
