# Threshold: Predictive, Policy-Gated Threat Intelligence
IBM Z Datathon 2026 · Track: AI Secured: Innovation Without Exposure

## Folder Structure
- `data/` — Event stream generator (M2)
- `model/` — ML model & temperature scaling calibration (M3)
- `policy/` — Deterministic policy engine & rules (M4)
- `audit/` — SHA-256 hash-chained audit log & verifier (M4)
- `app/` — Streamlit timeline & evidence UI (M5)
- `docs/` — Slides & LinuxONE evaluation results (M1 & M6)

## Shared Contracts (Everyone codes against these 3 formats)

**Fixed Stage Names:**
`BENIGN`, `INITIAL_ACCESS`, `CREDENTIAL_ACCESS`, `DISCOVERY`, `PRIVILEGE_ESCALATION`, `LATERAL_MOVEMENT`, `COLLECTION_EXFIL`, `IMPACT`

1. **events.csv** (M2 produces it; M3, M5 and M6 read it):
   `event_id, timestamp, system_id, actor_id, session_id, event_type, outcome, resource, sensitivity, origin, off_hours, stage_label, scenario_id`

2. **evidence.json** (M3 produces it; M4, M5 and M6 read it):
   `evidence_id, actor, session_id, current_stage, stage_confidence, next_stage, next_confidence, severity, indicators[], top_events[], model_version`

3. **audit.jsonl** (M4 produces it; M5 and M6 read it):
   `seq, ts, evidence_id, rule_fired, action, policy_version, prev_hash, entry_hash`
