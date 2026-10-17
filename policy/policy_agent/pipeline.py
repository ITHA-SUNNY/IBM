"""PolicyAgent: the one object other agents call.

    agent = PolicyAgent(audit_path="audit_log.jsonl")
    decision = agent.process(evidence_dict)   # validate -> severity -> rules -> audit log

`process` never raises on bad input. Evidence that fails validation produces the
FAILSAFE decision (alert a human, no automated action) and is still logged.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Union

from .audit import AuditLog
from .engine import Decision, Policy
from .errors import EvidenceError
from .evidence import EvidenceObject, canonical_json


def _json_safe(raw: Any) -> Any:
    try:
        return json.loads(canonical_json(raw))
    except (TypeError, ValueError):
        return repr(raw)


class PolicyAgent:
    def __init__(self, config_path: Optional[str] = None, audit_path: str = "audit_log.jsonl") -> None:
        self.policy = Policy.load(config_path)
        self.audit = AuditLog(audit_path)

    def _failsafe(self, raw: Any, problems: List[str]) -> Decision:
        actor = session = None
        if isinstance(raw, dict):
            actor = raw["actor_id"] if isinstance(raw.get("actor_id"), str) else None
            session = raw["session_id"] if isinstance(raw.get("session_id"), str) else None
        return Decision(
            action="ALERT_ANALYST",
            rule_id="FAILSAFE",
            rule_name="Evidence rejected",
            reason="Evidence failed validation, so no automated action was taken and a human is alerted. "
                   "Problems: " + "; ".join(problems),
            severity="UNKNOWN",
            severity_score=None,
            confidence=None,
            indicator_count=None,
            predicted_next_stage=None,
            target={"actor_id": actor, "session_id": session},
            automated=False,
            policy_version=self.policy.version,
            trace=[],
            notes=[],
        )

    def process(self, evidence: Union[Dict[str, Any], EvidenceObject]) -> Decision:
        raw = evidence.to_dict() if isinstance(evidence, EvidenceObject) else evidence
        try:
            ev = evidence if isinstance(evidence, EvidenceObject) else EvidenceObject.from_dict(evidence)
            decision = self.policy.evaluate(ev)
        except EvidenceError as exc:
            decision = self._failsafe(raw, exc.problems)
            self.audit.append(
                {
                    "event": "decision",
                    "status": "failsafe",
                    "policy_version": self.policy.version,
                    "config_hash": self.policy.config_hash,
                    "evidence": None,
                    "evidence_raw": _json_safe(raw),
                    "evidence_hash": None,
                    "validation_errors": exc.problems,
                    "decision": decision.to_dict(),
                }
            )
            return decision

        self.audit.append(
            {
                "event": "decision",
                "status": "ok",
                "policy_version": self.policy.version,
                "config_hash": self.policy.config_hash,
                "evidence": ev.to_dict(),
                "evidence_raw": None,
                "evidence_hash": ev.digest(),
                "validation_errors": [],
                "decision": decision.to_dict(),
            }
        )
        return decision

    def process_many(self, items: Iterable[Any]) -> List[Decision]:
        return [self.process(item) for item in items]
