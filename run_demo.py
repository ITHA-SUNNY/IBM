import csv
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# File paths following the Shared Contracts
DATA_FILE = Path("data/demo_stream.csv")
EVIDENCE_FILE = Path("data/evidence.json")
AUDIT_FILE = Path("audit/audit.jsonl")

# 1. GENERATOR STUB (Until M2 finishes data/generate.py)
def step1_generate_stub_data():
    DATA_FILE.parent.mkdir(exist_ok=True)
    if DATA_FILE.exists():
        print("[1. Generator] Found existing data/demo_stream.csv")
        return

    print("[1. Generator] Creating stub data/demo_stream.csv...")
    headers = [
        "event_id", "timestamp", "system_id", "actor_id", "session_id",
        "event_type", "outcome", "resource", "sensitivity", "origin",
        "off_hours", "stage_label", "scenario_id"
    ]
    rows = [
        # Attack scenario (ends in REVOKE_SESSION)
        ["evt_1", "2026-10-17T02:01:00Z", "SYS1", "hmac_attacker", "sess_01", "LOGON", "FAIL", "RACF", "INTERNAL", "NEW_NET", "True", "INITIAL_ACCESS", "attack"],
        ["evt_2", "2026-10-17T02:02:00Z", "SYS1", "hmac_attacker", "sess_01", "ALTUSER_SPECIAL", "SUCCESS", "RACF_DB", "CRITICAL", "NEW_NET", "True", "PRIVILEGE_ESCALATION", "attack"],
        # Admin look-alike scenario (ends in ALERT_ANALYST, no lockout)
        ["evt_3", "2026-10-17T02:10:00Z", "SYS1", "hmac_admin", "sess_02", "ALTUSER_SPECIAL", "SUCCESS", "PROD_FIX", "CRITICAL", "KNOWN_NET", "True", "BENIGN", "lookalike"]
    ]
    with open(DATA_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

# 2. MODEL STUB (Until M3 finishes model/predict.py)
def step2_model_stub():
    print("[2. Model] Generating stub evidence.json...")
    evidence_list = [
        {
            "evidence_id": "ev_01",
            "actor": "hmac_attacker",
            "session_id": "sess_01",
            "current_stage": "PRIVILEGE_ESCALATION",
            "stage_confidence": 0.94,
            "next_stage": "COLLECTION_EXFIL",
            "next_confidence": 0.85,
            "severity": "CRITICAL",
            "indicators": ["new_origin", "off_hours", "mfa_fail", "priv_change"],
            "top_events": ["evt_1", "evt_2"],
            "model_version": "stub_v1"
        },
        {
            "evidence_id": "ev_02",
            "actor": "hmac_admin",
            "session_id": "sess_02",
            "current_stage": "BENIGN",
            "stage_confidence": 0.45,
            "next_stage": "BENIGN",
            "next_confidence": 0.30,
            "severity": "CRITICAL",
            "indicators": ["off_hours"],
            "top_events": ["evt_3"],
            "model_version": "stub_v1"
        }
    ]
    with open(EVIDENCE_FILE, "w", encoding="utf-8") as f:
        json.dump(evidence_list, f, indent=2)
    return evidence_list

# 3. POLICY STUB (Until M4 finishes policy/engine.py)
def step3_policy_stub(ev: dict):
    if ev["severity"] == "CRITICAL" and ev["stage_confidence"] >= 0.90 and len(ev["indicators"]) >= 3:
        return "R4_CRITICAL_REVOKE", "REVOKE_SESSION"
    elif ev["stage_confidence"] < 0.65:
        return "R3_LOW_CONF_ANALYST", "ALERT_ANALYST"
    return "R6_DEFAULT", "LOG_ONLY"

# 4. AUDIT STUB (Until M4 finishes audit/audit.py)
def step4_write_audit(evidence_list: list):
    print("[3 & 4. Policy + Audit] Evaluating rules and writing audit/audit.jsonl...")
    AUDIT_FILE.parent.mkdir(exist_ok=True)
    prev_hash = "0" * 64

    with open(AUDIT_FILE, "w", encoding="utf-8") as f:
        for seq, ev in enumerate(evidence_list, start=1):
            rule_fired, action = step3_policy_stub(ev)
            entry = {
                "seq": seq,
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "evidence_id": ev["evidence_id"],
                "rule_fired": rule_fired,
                "action": action,
                "policy_version": "v1.0",
                "prev_hash": prev_hash
            }
            raw = json.dumps(entry, sort_keys=True).encode("utf-8")
            entry_hash = hashlib.sha256(prev_hash.encode("utf-8") + raw).hexdigest()
            entry["entry_hash"] = entry_hash
            prev_hash = entry_hash

            f.write(json.dumps(entry) + "\n")
            print(f"  -> Session {ev['session_id']}: Severity={ev['severity']}, Conf={ev['stage_confidence']} => Action: {action}")

if __name__ == "__main__":
    print("=== Running Threshold Pipeline (Stub Mode) ===")
    step1_generate_stub_data()
    ev_list = step2_model_stub()
    step4_write_audit(ev_list)
    print("=== Done! All contract files generated. ===")
