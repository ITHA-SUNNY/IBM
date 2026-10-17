"""PolicyAgent: the one object other agents call.

    agent = PolicyAgent(audit_path="audit_log.jsonl")
    decision = agent.process(evidence_dict)   # validate -> severity -> rules -> audit log

    # M3's evidence.json shape plus the events it covers (one call per event):
    decision = agent.process_model_evidence(m3_evidence, session_events_so_far)

Neither call raises on bad input. Evidence that fails validation produces the
FAILSAFE decision (alert a human, no automated action) and is still logged.
"""
from __future__ import annotations

import dataclasses
import json
from typing import Any, Dict, Iterable, List, Optional, Union

from .audit import AuditLog
from .contract import from_model_evidence
from .engine import Decision, Policy
from .errors import EvidenceError
from .evidence import EvidenceObject, canonical_json


def _json_safe(raw: Any) -> Any:
    try:
        return json.loads(canonical_json(raw))
    except (TypeError, ValueError):
        return repr(raw)


def _evidence_id(raw: Any) -> Optional[str]:
    if isinstance(raw, dict) and isinstance(raw.get("evidence_id"), str):
        return raw["evidence_id"]
    return None


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
            threat_type=None,
            next_confidence=None,
            target={"actor_id": actor, "session_id": session},
            automated=False,
            policy_version=self.policy.version,
            trace=[],
            notes=[],
        )

    def _log(self, decision: Decision, raw: Any, ev: Optional[EvidenceObject], errors: List[str]) -> None:
        self.audit.append(
            {
                # shared audit.jsonl contract fields (seq, ts, prev_hash, entry_hash added by AuditLog)
                "evidence_id": _evidence_id(raw),
                "rule_fired": decision.rule_id,
                "action": decision.action,
                "policy_version": self.policy.version,
                # policy detail
                "event": "decision",
                "status": "failsafe" if errors else "ok",
                "config_hash": self.policy.config_hash,
                "evidence": ev.to_dict() if ev else None,
                "evidence_raw": None if ev else _json_safe(raw),
                "evidence_hash": ev.digest() if ev else None,
                "validation_errors": errors,
                "decision": decision.to_dict(),
            }
        )

    def _decide(self, evidence: Union[Dict[str, Any], EvidenceObject], notes: List[str]) -> Decision:
        raw = evidence.to_dict() if isinstance(evidence, EvidenceObject) else evidence
        try:
            ev = evidence if isinstance(evidence, EvidenceObject) else EvidenceObject.from_dict(evidence)
            decision = self.policy.evaluate(ev)
        except EvidenceError as exc:
            decision = self._failsafe(raw, exc.problems)
            if notes:
                decision = dataclasses.replace(decision, notes=notes)
            self._log(decision, raw, None, exc.problems)
            return decision
        if notes:
            decision = dataclasses.replace(decision, notes=notes + decision.notes)
        self._log(decision, raw, ev, [])
        return decision

    def process(self, evidence: Union[Dict[str, Any], EvidenceObject]) -> Decision:
        return self._decide(evidence, [])

    def process_model_evidence(self, evidence: Any, events: List[Dict[str, Any]]) -> Decision:
        """Decide on M3's evidence.json object, using the observed events it covers.

        `events` are the events.csv rows of that session up to and including
        the event this evidence was produced after.
        """
        try:
            mapped, notes = from_model_evidence(evidence, events, self.policy.severity_model)
        except EvidenceError as exc:
            raw = evidence if isinstance(evidence, dict) else {"evidence": _json_safe(evidence)}
            if isinstance(raw, dict) and "actor" in raw and "actor_id" not in raw:
                raw = {**raw, "actor_id": raw["actor"]}
            decision = self._failsafe(raw, exc.problems)
            self._log(decision, raw, None, exc.problems)
            return decision
        return self._decide(mapped, notes)

    def process_many(self, items: Iterable[Any]) -> List[Decision]:
        return [self.process(item) for item in items]
