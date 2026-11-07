"""Audit logger bridge to omnihermes package."""

try:
    from ..omnihermes.audit import AuditLogger
except (ImportError, ValueError):
    from omnihermes.audit import AuditLogger

__all__ = ["AuditLogger"]
