"""Generate the M5 stub fixtures used before M2/M3/M4 land.

    python app/stubs/build_stubs.py

Writes, into this directory (deterministic, no randomness):

    demo_stream.csv   events.csv-shaped stream: one attack (S1) + one look-alike
    evidence.json     one evidence object per keyframe, keyed to an event
    audit.jsonl       hash-chained audit log built with the shared rule

These are *fixtures*, not the real pipeline. In Live mode the console prefers
data/demo_stream.csv, model/predict.py, policy/engine.py and the real audit log.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

STUB_DIR = Path(__file__).resolve().parent
APP_DIR = STUB_DIR.parent
REPO_ROOT = APP_DIR.parent
for p in (str(REPO_ROOT),):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.contracts import (  # noqa: E402
    EVENTS_COLUMNS,
    ZERO_HASH,
    compute_entry_hash,
    normalize_indicators,
    preview_decision,
)

POLICY_VERSION = "policy-v0.1.0-3f9c"
MODEL_VERSION = "threshold-hmm-gru v0.1.0-stub"

# ---------------------------------------------------------------------------
# Event stream. Ground-truth stage labels; the attack actor and the look-alike
# actor are HMAC pseudonyms (the privacy gate is M2's; these are already
# pseudonymized).
# ---------------------------------------------------------------------------

ATTACK = dict(
    system_id="zos1",
    actor_id="u-8a3f21",
    session_id="s1",
    scenario_id="S1",
)
LOOKALIKE = dict(
    system_id="zos2",
    actor_id="u-1d7b90",
    session_id="s2",
    scenario_id="S1-LOOKALIKE",
)

# (event_id, ts, event_type, outcome, resource, sensitivity, origin, off_hours, stage)
EVENTS: list[dict] = [
    # --- Attack: stolen credential -> privilege escalation -> crown-jewel read
    dict(**ATTACK, event_id="e0001", timestamp="2026-10-17T09:14:02Z",
         event_type="LOGON", outcome="SUCCESS", resource="", sensitivity="",
         origin="net-10.44.0", off_hours=True, stage_label="INITIAL_ACCESS"),
    dict(**ATTACK, event_id="e0002", timestamp="2026-10-17T09:15:31Z",
         event_type="MFA_CHALLENGE", outcome="FAILURE", resource="", sensitivity="",
         origin="net-10.44.0", off_hours=True, stage_label="CREDENTIAL_ACCESS"),
    dict(**ATTACK, event_id="e0003", timestamp="2026-10-17T09:16:04Z",
         event_type="LOGON", outcome="SUCCESS", resource="", sensitivity="",
         origin="net-10.44.0", off_hours=True, stage_label="CREDENTIAL_ACCESS"),
    dict(**ATTACK, event_id="e0004", timestamp="2026-10-17T09:18:20Z",
         event_type="COMMAND", outcome="SUCCESS", resource="LISTCAT CATALOG",
         sensitivity="internal", origin="net-10.44.0", off_hours=True,
         stage_label="DISCOVERY"),
    dict(**ATTACK, event_id="e0005", timestamp="2026-10-17T09:19:05Z",
         event_type="DATASET_ACCESS", outcome="SUCCESS", resource="CATALOG.DATASETS.*",
         sensitivity="internal", origin="net-10.44.0", off_hours=True,
         stage_label="DISCOVERY"),
    dict(**ATTACK, event_id="e0006", timestamp="2026-10-17T09:21:40Z",
         event_type="PRIVILEGE_CHANGE", outcome="SUCCESS",
         resource="ALTUSER u-8a3f21 SPECIAL", sensitivity="critical",
         origin="net-10.44.0", off_hours=True, stage_label="PRIVILEGE_ESCALATION"),
    dict(**ATTACK, event_id="e0007", timestamp="2026-10-17T09:24:10Z",
         event_type="DATASET_READ", outcome="SUCCESS", resource="PROD.PAYROLL.MASTER",
         sensitivity="critical", origin="net-10.44.0", off_hours=True,
         stage_label="COLLECTION_EXFIL"),
    dict(**ATTACK, event_id="e0008", timestamp="2026-10-17T09:26:55Z",
         event_type="DATASET_READ", outcome="SUCCESS", resource="PROD.CUSTOMER.PII",
         sensitivity="critical", origin="net-10.44.0", off_hours=True,
         stage_label="COLLECTION_EXFIL"),
    # --- Look-alike: on-call admin, known network, emergency change
    dict(**LOOKALIKE, event_id="e0009", timestamp="2026-10-17T02:03:11Z",
         event_type="LOGON", outcome="SUCCESS", resource="", sensitivity="",
         origin="net-10.10.0", off_hours=True, stage_label="BENIGN"),
    dict(**LOOKALIKE, event_id="e0010", timestamp="2026-10-17T02:04:02Z",
         event_type="DATASET_READ", outcome="SUCCESS", resource="OPS.RUNBOOK.LIVE",
         sensitivity="internal", origin="net-10.10.0", off_hours=True,
         stage_label="BENIGN"),
    dict(**LOOKALIKE, event_id="e0011", timestamp="2026-10-17T02:06:30Z",
         event_type="PRIVILEGE_CHANGE", outcome="SUCCESS",
         resource="PERMIT OPS.TEAM ID(u-1d7b90) ACCESS(READ)",
         sensitivity="internal", origin="net-10.10.0", off_hours=True,
         stage_label="BENIGN"),
    dict(**LOOKALIKE, event_id="e0012", timestamp="2026-10-17T02:09:48Z",
         event_type="DATASET_ACCESS", outcome="SUCCESS", resource="OPS.INCIDENT.LOG",
         sensitivity="internal", origin="net-10.10.0", off_hours=True,
         stage_label="BENIGN"),
]


def _ind(iid: str, source: str, *event_ids: str) -> dict:
    return {"id": iid, "source": source, "event_ids": list(event_ids)}


def _ev(evidence_id, actor, session_id, cur, conf, nxt, nconf, sev, indicators,
        top_events, conformal, ood=False) -> dict:
    return {
        "evidence_id": evidence_id,
        "actor": actor,
        "session_id": session_id,
        "current_stage": cur,
        "stage_confidence": conf,
        "next_stage": nxt,
        "next_confidence": nconf,
        "severity": sev,
        "indicators": indicators,
        "top_events": top_events,
        "model_version": MODEL_VERSION,
        # staging / extended fields (tolerated extras):
        "conformal_set": conformal,
        "ood_flag": ood,
        "after_event_id": None,
    }


def build_evidence() -> list[dict]:
    """One evidence object per keyframe, each tagged with after_event_id."""
    a = ATTACK["actor_id"]
    l = LOOKALIKE["actor_id"]
    ev: list[dict] = []

    kf = [
        (_ev("ev-0001", a, "s1", "INITIAL_ACCESS", 0.62, "CREDENTIAL_ACCESS", 0.70,
             "MEDIUM",
             [_ind("NEW_ORIGIN", "SMF80", "e0001"),
              _ind("OFF_HOURS", "SMF80", "e0001")],
             [{"event_id": "e0001", "contribution": 0.41,
               "reason": "First logon from previously unseen origin network."}],
             ["INITIAL_ACCESS"], False), "e0001"),
        (_ev("ev-0002", a, "s1", "CREDENTIAL_ACCESS", 0.71, "PRIVILEGE_ESCALATION", 0.70,
             "HIGH",
             [_ind("NEW_ORIGIN", "SMF80", "e0001"),
              _ind("MFA_FAILURE", "SMF80", "e0002"),
              _ind("OFF_HOURS", "SMF80", "e0001")],
             [{"event_id": "e0002", "contribution": 0.38,
               "reason": "MFA challenge failed before any success."}],
             ["CREDENTIAL_ACCESS"], False), "e0002"),
        (_ev("ev-0003", a, "s1", "CREDENTIAL_ACCESS", 0.80, "PRIVILEGE_ESCALATION", 0.74,
             "HIGH",
             [_ind("AUTH_FAILURE_BURST", "SMF80", "e0002"),
              _ind("NEW_ORIGIN", "SMF80", "e0001"),
              _ind("OFF_HOURS", "SMF80", "e0001")],
             [{"event_id": "e0003", "contribution": 0.35,
               "reason": "Success immediately after a failure (fail-then-success)."}],
             ["CREDENTIAL_ACCESS"], False), "e0003"),
        (_ev("ev-0004", a, "s1", "DISCOVERY", 0.85, "PRIVILEGE_ESCALATION", 0.81,
             "HIGH",
             [_ind("AUTH_FAILURE_BURST", "SMF80", "e0002"),
              _ind("NEW_ORIGIN", "SMF80", "e0001"),
              _ind("OFF_HOURS", "SMF80", "e0001")],
             [{"event_id": "e0004", "contribution": 0.52,
               "reason": "Catalogue enumeration shortly after login."}],
             ["DISCOVERY"], False), "e0004"),
        (_ev("ev-0005", a, "s1", "DISCOVERY", 0.87, "PRIVILEGE_ESCALATION", 0.82,
             "HIGH",
             [_ind("AUTH_FAILURE_BURST", "SMF80", "e0002"),
              _ind("NEW_ORIGIN", "SMF80", "e0001"),
              _ind("OFF_HOURS", "SMF80", "e0001")],
             [{"event_id": "e0005", "contribution": 0.55,
               "reason": "Discovery sweep widens to many datasets."}],
             ["DISCOVERY", "PRIVILEGE_ESCALATION"], False), "e0005"),
        (_ev("ev-0006", a, "s1", "PRIVILEGE_ESCALATION", 0.93, "COLLECTION_EXFIL", 0.88,
             "CRITICAL",
             [_ind("NEW_ORIGIN", "SMF80", "e0001"),
              _ind("AUTH_FAILURE_BURST", "SMF80", "e0002"),
              _ind("PRIV_ATTR_GRANTED", "SMF80", "e0006"),
              _ind("TDZ_ANOMALY", "SMF83", "e0006")],
             [{"event_id": "e0006", "contribution": 0.71,
               "reason": "Self-granted SPECIAL attribute — classic escalation."}],
             ["PRIVILEGE_ESCALATION"], False), "e0006"),
        (_ev("ev-0007", a, "s1", "COLLECTION_EXFIL", 0.96, "IMPACT", 0.90,
             "CRITICAL",
             [_ind("NEW_ORIGIN", "SMF80", "e0001"),
              _ind("AUTH_FAILURE_BURST", "SMF80", "e0002"),
              _ind("PRIV_ATTR_GRANTED", "SMF80", "e0006"),
              _ind("CROWN_JEWEL_ACCESS", "SMF98", "e0007"),
              _ind("TDZ_ANOMALY", "SMF83", "e0006")],
             [{"event_id": "e0007", "contribution": 0.66,
               "reason": "Read of a critical dataset never touched by this actor."}],
             ["COLLECTION_EXFIL"], False), "e0007"),
        (_ev("ev-0008", a, "s1", "COLLECTION_EXFIL", 0.97, "IMPACT", 0.91,
             "CRITICAL",
             [_ind("CROWN_JEWEL_ACCESS", "SMF98", "e0007"),
              _ind("CROWN_JEWEL_ACCESS", "SMF98", "e0008"),
              _ind("PRIV_ATTR_GRANTED", "SMF80", "e0006"),
              _ind("TDZ_ANOMALY", "SMF83", "e0006")],
             [{"event_id": "e0008", "contribution": 0.69,
               "reason": "Volume of critical reads exceeds this actor's baseline."}],
             ["COLLECTION_EXFIL", "IMPACT"], False), "e0008"),
        (_ev("ev-0009", l, "s2", "BENIGN", 0.55, "INITIAL_ACCESS", 0.40,
             "LOW",
             [_ind("OFF_HOURS", "SMF80", "e0009")],
             [{"event_id": "e0009", "contribution": 0.30,
               "reason": "Off-hours logon, but from a known on-call network."}],
             ["BENIGN", "INITIAL_ACCESS"], False), "e0009"),
        (_ev("ev-0010", l, "s2", "BENIGN", 0.58, "PRIVILEGE_ESCALATION", 0.45,
             "MEDIUM",
             [_ind("OFF_HOURS", "SMF80", "e0009")],
             [{"event_id": "e0010", "contribution": 0.22,
               "reason": "Reads an operational runbook — consistent with on-call."}],
             ["BENIGN", "CREDENTIAL_ACCESS"], False), "e0010"),
        (_ev("ev-0011", l, "s2", "CREDENTIAL_ACCESS", 0.62, "PRIVILEGE_ESCALATION", 0.58,
             "HIGH",
             [_ind("OFF_HOURS", "SMF80", "e0009"),
              _ind("PRIV_ATTR_GRANTED", "SMF80", "e0011")],
             [{"event_id": "e0011", "contribution": 0.44,
               "reason": "Permission change during a change-management window."}],
             ["BENIGN", "CREDENTIAL_ACCESS", "PRIVILEGE_ESCALATION"], False), "e0011"),
        (_ev("ev-0012", l, "s2", "DISCOVERY", 0.60, "PRIVILEGE_ESCALATION", 0.55,
             "HIGH",
             [_ind("OFF_HOURS", "SMF80", "e0009"),
              _ind("PRIV_ATTR_GRANTED", "SMF80", "e0011")],
             [{"event_id": "e0012", "contribution": 0.31,
               "reason": "Access to incident log — plausible for on-call work."}],
             ["BENIGN", "CREDENTIAL_ACCESS", "DISCOVERY"], False), "e0012"),
    ]
    for obj, after in kf:
        obj["after_event_id"] = after
        ev.append(obj)
    return ev


def build_audit(evidence: list[dict]) -> list[dict]:
    """One audit entry per evidence object, hash-chained per the contract."""
    entries: list[dict] = []
    prev = ZERO_HASH
    for i, e in enumerate(evidence, start=1):
        decision = preview_decision(e)
        entry = {
            "seq": i,
            "ts": _ts_for(e["after_event_id"]),
            "evidence_id": e["evidence_id"],
            "rule_fired": decision["rule_fired"],
            "action": decision["action"],
            "policy_version": POLICY_VERSION,
            "prev_hash": prev,
        }
        entry["entry_hash"] = compute_entry_hash(prev, entry)
        entries.append(entry)
        prev = entry["entry_hash"]
    return entries


_TS = {e["event_id"]: e["timestamp"] for e in EVENTS}


def _ts_for(event_id: str) -> str:
    return _TS.get(event_id, "2026-10-17T00:00:00Z")


def write_fixtures() -> None:
    # demo_stream.csv
    with (STUB_DIR / "demo_stream.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=EVENTS_COLUMNS)
        writer.writeheader()
        for e in EVENTS:
            writer.writerow({k: e.get(k, "") for k in EVENTS_COLUMNS})

    evidence = build_evidence()
    with (STUB_DIR / "evidence.json").open("w", encoding="utf-8") as fh:
        json.dump(evidence, fh, indent=2)
        fh.write("\n")

    audit = build_audit(evidence)
    with (STUB_DIR / "audit.jsonl").open("w", encoding="utf-8") as fh:
        for entry in audit:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")

    print(f"events   : {len(EVENTS):>3} -> demo_stream.csv")
    print(f"evidence : {len(evidence):>3} -> evidence.json")
    print(f"audit    : {len(audit):>3} -> audit.jsonl")


if __name__ == "__main__":
    write_fixtures()
