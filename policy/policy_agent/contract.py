"""Model-side evidence (M3's evidence.json) -> the policy's evidence object.

M3 sends one evidence object per event, in the shared evidence.json shape:

    evidence_id, actor, session_id, current_stage, stage_confidence,
    next_stage, next_confidence, severity, indicators[], top_events[],
    model_version

It says what the model believes. It does not say what was touched, so the
severity context (resource_tier, action) comes from the observed events the
evidence covers (events.csv rows for that session, up to and including the
latest one). That keeps severity on the policy side and based on real
observations, never on model output.

Mapping:
    actor_id              <- actor (or actor_id)
    timestamp             <- timestamp, else the last observed event's timestamp
    threat_type           <- current_stage
    confidence            <- stage_confidence (or confidence)
    next_confidence       <- next_confidence
    predicted_next_stage  <- next_stage (or predicted_next_stage)
    indicators            <- indicators (strings; {"id": ...} objects accepted)
    resource_tier, action <- highest-risk observed event (sensitivity, event_type)
    is_privileged_actor   <- is_privileged_actor if supplied as true/false, else false

Everything else (evidence_id, top_events, severity, model_version, ...) is kept
for the audit trail and ignored by the decision. Nothing here is guessed: a
missing field stays missing and the evidence fails safe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .severity import SeverityModel

PASS_THROUGH = ("evidence_id", "top_events", "severity", "model_version", "stage_confidence", "conformal_set", "ood_flag")


def _first(evidence: Dict[str, Any], *names: str) -> Any:
    for name in names:
        if evidence.get(name) is not None:
            return evidence[name]
    return None


def _indicator_ids(raw: Any) -> Any:
    if not isinstance(raw, list):
        return raw  # left as-is so validation reports it
    out = []
    for item in raw:
        if isinstance(item, dict):
            item = item.get("id") or item.get("name")
        out.append(item)
    return out


def from_model_evidence(evidence: Any, events: List[Dict[str, Any]],
                        severity: SeverityModel) -> Tuple[Any, List[str]]:
    """Return (policy evidence dict, notes). Raises EvidenceError for unusable events."""
    if not isinstance(evidence, dict):
        return evidence, []
    notes: List[str] = []
    out: Dict[str, Any] = {}

    for target, names in (
        ("actor_id", ("actor_id", "actor")),
        ("session_id", ("session_id",)),
        ("threat_type", ("threat_type", "current_stage")),
        ("confidence", ("confidence", "stage_confidence")),
        ("next_confidence", ("next_confidence",)),
        ("predicted_next_stage", ("predicted_next_stage", "next_stage")),
    ):
        value = _first(evidence, *names)
        if value is not None:
            out[target] = value

    timestamp = _first(evidence, "timestamp")
    if timestamp is None and events and isinstance(events[-1], dict):
        timestamp = events[-1].get("timestamp")
    if timestamp is not None:
        out["timestamp"] = timestamp

    if "indicators" in evidence:
        out["indicators"] = _indicator_ids(evidence["indicators"])

    privileged = evidence.get("is_privileged_actor")
    if isinstance(privileged, bool):
        out["is_privileged_actor"] = privileged
    else:
        out["is_privileged_actor"] = False
        notes.append("is_privileged_actor not supplied; treated as false (no privilege bonus)")

    if evidence.get("resource_tier") and evidence.get("action"):
        out["resource_tier"], out["action"] = evidence["resource_tier"], evidence["action"]
    else:
        tier, action, event_id = severity.highest_risk_event(events)
        out["resource_tier"], out["action"] = tier, action
        out["severity_context_event"] = event_id
        notes.append(f"severity context from observed event {event_id} ({action} on {tier} resource)")

    for key in PASS_THROUGH:
        if key in evidence:
            out[key] = evidence[key]
    return out, notes
