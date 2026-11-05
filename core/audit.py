"""Audit logger bridge to presence package."""

try:
    from ..presence.audit import AuditLogger
except (ImportError, ValueError):
    from presence.audit import AuditLogger

__all__ = ["AuditLogger"]
