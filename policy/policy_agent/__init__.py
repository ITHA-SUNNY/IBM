"""Threshold policy agent: deterministic, auditable response decisions.

Standard library only. Contains no machine learning.
"""
from .audit import AuditLog, VerifyResult
from .engine import Decision, Policy
from .errors import AuditError, EvidenceError, PolicyConfigError
from .evidence import EvidenceObject
from .pipeline import PolicyAgent

__version__ = "1.0.0"

__all__ = [
    "AuditLog",
    "AuditError",
    "Decision",
    "EvidenceError",
    "EvidenceObject",
    "Policy",
    "PolicyAgent",
    "PolicyConfigError",
    "VerifyResult",
]
