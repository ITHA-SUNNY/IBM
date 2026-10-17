# Threshold: Policy Agent

The deterministic half of Threshold. It takes the **evidence object** the model side produces and decides what response is *permitted*: log, early warning, alert an analyst, revoke a session, or lock credentials. Every decision is written to a tamper-evident audit log.

Standard library only. No ML, no network, no clock in the decision path. The same evidence and the same `rules.json` always give the same decision.

```
model side ──evidence object──▶  policy_agent  ──decision──▶  dashboard / executor
(Agents 2-3)                     (this package)               (Agents 5-6)
                                      │
                                      └──▶ audit_log.jsonl (hash-chained)
```

## Quick start

```bash
python3 -m unittest -v          # 52 tests, under a second
python3 demo.py                 # full walkthrough on examples/evidence_feed.jsonl
```

```python
from policy_agent import PolicyAgent

agent = PolicyAgent(audit_path="audit_log.jsonl")
decision = agent.process(evidence_dict)      # never raises on bad input
print(decision.action, decision.rule_id, decision.reason)
```

CLI, for anyone not writing Python:

```bash
python3 -m policy_agent decide evidence.jsonl --audit audit_log.jsonl   # decisions as JSONL
python3 -m policy_agent verify audit_log.jsonl                          # exit code 1 if tampered
python3 -m policy_agent replay audit_log.jsonl --actor jmartinez
```

## The contract

### Input: what the model side sends (one JSON object per actor window)

| Field | Type | Notes |
|---|---|---|
| `actor_id` | string | required |
| `session_id` | string | optional, but needed if you want a real session revoked |
| `timestamp` | ISO-8601 string | required. Naive times are treated as UTC |
| `threat_type` | string | e.g. `credential_compromise` |
| `confidence` | number 0 to 1 | required. Model confidence only; never blended with severity |
| `predicted_next_stage` | string | e.g. `privilege_escalation`, `lateral_movement`, `exfiltration`, `impact`, `none`, `unknown` |
| `indicators` | list of strings | required. Distinct signals only; duplicates count once |
| `resource_tier` | string | `public`, `internal`, `restricted`, `critical` |
| `action` | string | `login`, `read`, `write`, `command_exec`, `crypto_op`, `delete`, `export`, `privilege_change`, `credential_change` |
| `is_privileged_actor` | true/false | required |

Any other keys (model name, window bounds, a display label) are kept in the audit log and ignored by the decision.

**Severity is not an input.** The model side sends the context (`resource_tier`, `action`, `is_privileged_actor`) and this package computes severity. If a `severity` key arrives it is ignored and noted in the decision.

**For whoever builds the sequence features (Agent 2):** `resource_tier` and `action` should describe the *highest-risk event in the window*. That is the event severity is judged on.

Vocabulary lives in `policy_agent/rules.json`. Tell me if your event types need other names and they are a one-line change.

### Output: the decision

```json
{
  "action": "REVOKE_SESSION",
  "rule_id": "P-02",
  "rule_name": "Session revoke",
  "reason": "Critical severity with high confidence and at least three independent indicators: revoke the session.",
  "severity": "CRITICAL",
  "severity_score": 8,
  "confidence": 0.93,
  "indicator_count": 4,
  "predicted_next_stage": "exfiltration",
  "target": {"actor_id": "jmartinez", "session_id": "S-7731"},
  "automated": true,
  "policy_version": "1.0.0",
  "trace": [ {"rule_id": "P-01", "matched": false, "failed_conditions": ["confidence 0.93 < 0.95 required"], "...": "..."} ],
  "notes": []
}
```

`action` is one of `LOG_ONLY`, `EARLY_WARNING`, `ALERT_ANALYST`, `REVOKE_SESSION`, `LOCK_CREDENTIALS`. `automated` is true only for the last two. `trace` lists every rule that was checked and why it did or did not match, which is the data for a "why" drill-down. `python3 demo.py` also writes `demo_output/demo_decisions.jsonl`; a copy is in `examples/` for dashboard work.

Evidence that fails validation (confidence 1.7, missing field, unknown tier) produces rule `FAILSAFE`: alert a human, `automated: false`, and the rejection is logged.

## Default rules (first match wins)

| Rule | Action | Needs |
|---|---|---|
| P-01 | `LOCK_CREDENTIALS` | CRITICAL, confidence >= 0.95, >= 4 indicators, predicted stage `exfiltration` or `impact` |
| P-02 | `REVOKE_SESSION` | CRITICAL, confidence >= 0.90, >= 3 indicators |
| P-03 | `ALERT_ANALYST` | CRITICAL but not enough evidence to act |
| P-04 | `ALERT_ANALYST` | HIGH, confidence >= 0.90, >= 3 indicators (HIGH never auto-acts) |
| P-05 | `EARLY_WARNING` | predicted stage `lateral_movement`, `exfiltration` or `impact`, confidence >= 0.75 |
| default | `LOG_ONLY` | nothing matched |

Severity score = resource tier + action weight + 1 if the actor is privileged. 6 or more is CRITICAL, 4 to 5 HIGH, 3 MEDIUM, otherwise LOW. All weights and thresholds are in `rules.json`.

## What the tests prove (the pitch claims, enforced)

- **Severity and confidence are independent.** Severity never changes with confidence or indicator count (swept over every tier, action and privilege combination). Upstream-supplied severity is ignored.
- **No destructive action on thin evidence.** Across about 22,000 generated cases, revoke or lock only ever happens at CRITICAL severity, confidence >= 0.80 and >= 2 indicators.
- **The config can't weaken that.** `rules.json` is rejected at load if a revoke/lock rule omits severity, drops below those floors, or if the default action is destructive. Misspelled condition names and empty conditions are rejected rather than silently ignored.
- **Bad input fails safe.** Garbage, `None`, out-of-range confidence, unknown tiers all end in an alert, never an action.
- **The audit log is tamper-evident.** Editing, deleting, reordering or inserting entries is detected, with the line number.
- **The policy side contains no ML.** A test parses every file in `policy_agent/` and fails on any import outside a short standard-library list.

I also broke the code on purpose three ways (off-by-one on the confidence bound, confidence leaking into severity, a `numpy` import in the engine) and the suite failed each time.

## Running it on the LinuxONE instance (judges look for this evidence)

```bash
uname -m                        # prints s390x on LinuxONE: screenshot it
python3 --version
python3 -m unittest -v          # screenshot the passing run
python3 demo.py                 # screenshot the walkthrough
```

Third-party libraries used: **none** (nothing to list for this module). Tested on Python 3.13 and written without newer syntax, so older 3.x should work; the test run on the LinuxONE box confirms it.

## Limits worth knowing

- **It decides; it does not execute.** Nothing here touches RACF or kills a session. Whoever owns integration reads `decision.action` and `decision.target` and either performs the action or, for the demo, prints what it would do.
- **Truncation needs an outside anchor.** The hash chain catches edits, deletions and reordering. Cutting entries off the *end* is only visible if you kept the latest `head hash` elsewhere (`python3 -m policy_agent verify` prints it; a screenshot is enough for a demo).
- **One writer per log file.** Run one `PolicyAgent` per audit path.
- **Thresholds are starting points.** 0.90 and 3 indicators are sensible defaults, not tuned values. Once the model's confidence is calibrated, revisit them against its real score distribution.

## Layout

```
policy_agent/
  evidence.py   evidence contract, validation, normalisation
  severity.py   rule-based severity (never sees confidence)
  engine.py     rules, guardrails, Decision
  audit.py      hash-chained log, verify, replay
  pipeline.py   PolicyAgent: validate -> decide -> log
  rules.json    all thresholds and vocabulary
tests/test_policy.py
examples/       evidence_feed.jsonl (input), demo_decisions.jsonl (output)
demo.py
```
