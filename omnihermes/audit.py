"""Tamper-evident cryptographic audit logger for OmniHermes.

Maintains an append-only, SHA-256 hash-chained log of every enrollment,
authorization, rejection, and presence event.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from omnihermes.models import get_default_data_dir, assert_not_real_data_dir


class AuditLogger:
    """Cryptographic SHA-256 hash-chained audit logger."""

    def __init__(self, data_dir: Optional[Path] = None, log_path: Optional[Path] = None):
        if log_path:
            self.log_path = Path(log_path)
        else:
            base_dir = data_dir or get_default_data_dir()
            self.log_path = base_dir / "audit.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._get_tip_hash()

    def _get_tip_hash(self) -> str:
        """Find the last entry's hash or return genesis hash."""
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
        user_name: str = "Unknown",
        action: str = "",
        result: str = "",
        similarity_score: float = 0.0,
        liveness_score: float = 0.0,
        details: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Record an event into the cryptographic hash chain."""
        tool_name = kwargs.get("tool_name", "")
        action_summary = kwargs.get("action_summary", action)
        confidence = kwargs.get("confidence", similarity_score)

        entry_body = {
            "timestamp": time.time(),
            "event_type": event_type,
            "user_name": user_name,
            "tool_name": tool_name,
            "action": action_summary or action,
            "result": result,
            "similarity_score": round(confidence, 4),
            "liveness_score": round(liveness_score, 4),
            "details": details or {},
            "prev_hash": self._last_hash,
        }

        canonical_bytes = json.dumps(entry_body, sort_keys=True).encode("utf-8")
        current_hash = hashlib.sha256(canonical_bytes).hexdigest()
        entry_body["current_hash"] = current_hash

        assert_not_real_data_dir(self.log_path, operation="append_audit_log")
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry_body) + "\n")

        self._last_hash = current_hash
        return entry_body

    def verify_integrity(self) -> Dict[str, Any]:
        """Verify the cryptographic hash chain of the audit log."""
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return {"valid": True, "count": 0, "message": "Audit chain empty."}

        expected_prev = "0" * 64
        count = 0

        with open(self.log_path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                recorded_hash = record.get("current_hash")
                recorded_prev = record.get("prev_hash")

                if recorded_prev != expected_prev:
                    msg = f"Hash chain broken at index {idx}: expected prev {expected_prev}, got {recorded_prev}"
                    return {
                        "valid": False,
                        "broken_at_index": idx,
                        "message": msg,
                        "error": f"Tampered record detected at line {idx}: {msg}",
                    }

                body_copy = dict(record)
                del body_copy["current_hash"]
                computed_hash = hashlib.sha256(json.dumps(body_copy, sort_keys=True).encode("utf-8")).hexdigest()

                if computed_hash != recorded_hash:
                    msg = f"Record tampered at index {idx}: hash mismatch"
                    return {
                        "valid": False,
                        "broken_at_index": idx,
                        "message": msg,
                        "error": f"Tampered record detected at line {idx}: {msg}",
                    }

                expected_prev = recorded_hash
                count += 1

        return {
            "valid": True,
            "count": count,
            "entries_checked": count,
            "tip_hash": expected_prev,
            "message": f"Cryptographic integrity verified across {count} records.",
        }

