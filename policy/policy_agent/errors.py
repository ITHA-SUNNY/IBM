"""Exception types shared across the policy agent."""
from __future__ import annotations


class EvidenceError(ValueError):
    """The evidence object is malformed or uses vocabulary the policy does not know.

    The policy agent never acts on evidence that raises this; it falls back to
    the fail-safe decision (alert a human, no automated action).
    """

    def __init__(self, problems):
        if isinstance(problems, str):
            problems = [problems]
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


class PolicyConfigError(ValueError):
    """rules.json is invalid or breaks one of the built-in safety guardrails."""

    def __init__(self, problems):
        if isinstance(problems, str):
            problems = [problems]
        self.problems = list(problems)
        super().__init__("invalid policy config: " + "; ".join(self.problems))


class AuditError(RuntimeError):
    """The audit log cannot be appended to safely (for example, a corrupt tail)."""
