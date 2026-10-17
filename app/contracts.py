"""Threshold — shared contracts for the M5 console (app/).

Owned by M5 only in the narrow sense that M5 must speak the *agreed* formats.
The authoritative producers are:

    events.csv   -> M2 (Data)      read by M3, M5, M6
    evidence.json-> M3 (Model)     read by M4, M5, M6
    audit.jsonl  -> M4 (Policy)    read by M5, M6

Nothing here overrides those owners. It only pins the field names, the eight
fixed stage names, the display colours, and the audit hash rule so the console
and its stub fixtures cannot drift from the shared contracts.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

# --- The eight fixed stage names (contract) ---------------------------------

STAGES = [
    "BENIGN",
    "INITIAL_ACCESS",
    "CREDENTIAL_ACCESS",
    "DISCOVERY",
    "PRIVILEGE_ESCALATION",
    "LATERAL_MOVEMENT",
    "COLLECTION_EXFIL",
    "IMPACT",
]

# --- Contract field names ----------------------------------------------------

EVENTS_COLUMNS = [
    "event_id",
    "timestamp",
    "system_id",
    "actor_id",
    "session_id",
    "event_type",
    "outcome",
    "resource",
    "sensitivity",
    "origin",
    "off_hours",
    "stage_label",
    "scenario_id",
]

EVIDENCE_FIELDS = [
    "evidence_id",
    "actor",
    "session_id",
    "current_stage",
    "stage_confidence",
    "next_stage",
    "next_confidence",
    "severity",
    "indicators",
    "top_events",
    "model_version",
]

AUDIT_FIELDS = [
    "seq",
    "ts",
    "evidence_id",
    "rule_fired",
    "action",
    "policy_version",
    "prev_hash",
    "entry_hash",
]

POLICY_VERSION_FALLBACK = "policy-v0.1.0"

POLICY_ACTIONS = [
    "LOG_ONLY",
    "EARLY_WARNING",
    "ALERT_ANALYST",
    "REVOKE_SESSION",
    "STAGE_CREDENTIAL_LOCK",
]

# --- Display tokens (Streamlit badge colours) --------------------------------
# st.badge supports: red, orange, yellow, blue, green, violet, gray/grey,
# primary. Six stages map 1:1 to distinct colours; the two most severe share
# red but IMPACT is drawn as a filled block so they stay distinguishable.

STAGE_COLOR = {
    "BENIGN": "gray",
    "INITIAL_ACCESS": "green",
    "CREDENTIAL_ACCESS": "blue",
    "DISCOVERY": "yellow",
    "PRIVILEGE_ESCALATION": "orange",
    "LATERAL_MOVEMENT": "violet",
    "COLLECTION_EXFIL": "red",
    "IMPACT": "red",
}

STAGE_FILLED = {"IMPACT"}  # rendered as a filled colour block, not an outline

ACTION_COLOR = {
    "LOG_ONLY": "gray",
    "EARLY_WARNING": "blue",
    "ALERT_ANALYST": "orange",
    "REVOKE_SESSION": "red",
    "STAGE_CREDENTIAL_LOCK": "violet",
    "OVERRIDE_CONFIRM": "green",
    "OVERRIDE_REVERSE": "orange",
    "OVERRIDE_ANNOTATE": "blue",
}

SEVERITY_COLOR = {
    "LOW": "gray",
    "MEDIUM": "blue",
    "HIGH": "orange",
    "CRITICAL": "red",
}

# --- Audit hash chain (contract: entry_hash = SHA256(prev + canonical entry)) -

ZERO_HASH = "0" * 64


def canonical_json(obj: dict[str, Any]) -> str:
    """The canonical form hashed into the chain (must match M4's audit.py)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_json_spaced(obj: dict[str, Any]) -> str:
    """Variant using json.dumps' default separators (', ', ': ').

    Some early stubs (run_demo.py) hashed this form. Verification accepts it too
    so an M5-only console never reports a false 'broken' on a valid log.
    """
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def entry_hash_candidates(prev_hash: str, entry: dict[str, Any]) -> list[str]:
    """All accepted entry_hash values for an entry (compact + spaced forms)."""
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    forms = (canonical_json(body), canonical_json_spaced(body))
    return [
        hashlib.sha256((prev_hash + form).encode("utf-8")).hexdigest()
        for form in forms
    ]


def compute_entry_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    """entry_hash = SHA-256(prev_hash + canonical_json(entry without hash))."""
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256((prev_hash + canonical_json(body)).encode("utf-8")).hexdigest()


# --- Indicator helpers -------------------------------------------------------


def normalize_indicators(indicators: Iterable[Any] | None) -> list[dict[str, Any]]:
    """Accept indicators as strings or {id}/{source}/{event_ids} objects."""
    out: list[dict[str, Any]] = []
    for ind in indicators or []:
        if isinstance(ind, str):
            out.append({"id": ind, "source": None, "event_ids": []})
        elif isinstance(ind, dict):
            out.append(
                {
                    "id": ind.get("id") or ind.get("name") or str(ind),
                    "source": ind.get("source"),
                    "event_ids": ind.get("event_ids", []),
                }
            )
    return out


def indicator_source_count(indicators: Iterable[Any] | None) -> int:
    return len({i["source"] for i in normalize_indicators(indicators) if i["source"]})


# --- Stub policy preview -----------------------------------------------------
# This is NOT the policy engine. The engine is policy/engine.py (M4) and is the
# only component allowed to act. This mirror of the agreed rules table exists so
# the console shows a decision before M4 lands, and is bypassed in Live mode.


def preview_decision(evidence: dict[str, Any]) -> dict[str, str]:
    severity = (evidence.get("severity") or "").upper()
    stage_conf = float(evidence.get("stage_confidence") or 0.0)
    next_stage = evidence.get("next_stage")
    next_conf = float(evidence.get("next_confidence") or 0.0)
    indicators = normalize_indicators(evidence.get("indicators"))
    n_ind = len(indicators)
    n_src = indicator_source_count(indicators)
    conformal = evidence.get("conformal_set")
    ood = bool(evidence.get("ood_flag", False))

    # Corroboration: require >=2 distinct sources only when sources are given.
    # Repo stub evidence carries plain-string indicators (no source), so treat
    # "no sources provided" as satisfied rather than blocking a real containment.
    corroborated = n_src >= 2 or n_src == 0

    if evidence.get("protected_identity"):
        return {"action": "ALERT_ANALYST", "rule_fired": "P2",
                "reason": "Protected identity — never auto-contain."}

    if ood or (isinstance(conformal, (list, tuple)) and len(conformal) >= 3):
        size = len(conformal) if isinstance(conformal, (list, tuple)) else "-"
        return {"action": "ALERT_ANALYST", "rule_fired": "P3",
                "reason": f"Model uncertainty — abstain (conformal set = {size})."}

    if severity == "CRITICAL" and stage_conf >= 0.90 and n_ind >= 3 and corroborated:
        src_note = f" from {n_src} sources" if n_src else ""
        return {"action": "REVOKE_SESSION", "rule_fired": "P4",
                "reason": f"CRITICAL, confidence {stage_conf:.2f} >= 0.90, "
                          f"{n_ind} indicators{src_note}."}

    if severity == "CRITICAL" and stage_conf < 0.90:
        return {"action": "ALERT_ANALYST", "rule_fired": "P6",
                "reason": f"CRITICAL but confidence {stage_conf:.2f} < 0.90 — "
                          "escalate, do not act."}

    if next_stage in ("PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT") and next_conf >= 0.75:
        return {"action": "EARLY_WARNING", "rule_fired": "P7",
                "reason": f"Predicted {next_stage} at {next_conf:.2f} >= 0.75."}

    if severity == "HIGH" and stage_conf >= 0.75:
        return {"action": "ALERT_ANALYST", "rule_fired": "P8",
                "reason": f"HIGH severity, confidence {stage_conf:.2f} >= 0.75."}

    return {"action": "LOG_ONLY", "rule_fired": "P9",
            "reason": "No policy threshold met."}
