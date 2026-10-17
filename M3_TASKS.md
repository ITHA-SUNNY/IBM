# M3: ML Model — Task File for Antigravity

Project: **Threshold** (IBM Z Datathon 2026, Track: AI Secured)
Owner: Vinayak (M3). Build window: Oct 17–18. Folder: `model/`

Give this whole file to Antigravity as context first, then feed it the prompts in Section 6 **one at a time**, checking each result before moving on.

---

## 1. Your job in one paragraph

Read session events (`events.csv`, produced by M2). For each session, predict the **current attack stage** and the **next attack stage**, with **calibrated confidence** (temperature scaling). Output an explainable `evidence.json` object. The model never takes action; M4's policy engine decides. Done when `predict.py` returns valid `evidence.json` for every event in `demo_stream.csv`.

## 2. Contracts (do not change names without telling the team)

**Input: `events.csv`** columns:
`event_id, timestamp, system_id, actor_id, session_id, event_type, outcome, resource, sensitivity, origin, off_hours, stage_label, scenario_id`

**Output: `evidence.json`** fields:
`evidence_id, actor, session_id, current_stage, stage_confidence, next_stage, next_confidence, severity, indicators[], top_events[], model_version`

**Stage labels (fixed, exactly these 8):**
`BENIGN, INITIAL_ACCESS, CREDENTIAL_ACCESS, DISCOVERY, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, COLLECTION_EXFIL, IMPACT`

**Open questions to confirm with the team (assumed defaults below):**
| Question | Ask | Default I will code |
|---|---|---|
| `indicators[]` format | M4 | list of short strings, e.g. `"new_origin"`, `"mfa_failure_then_success"` |
| `top_events[]` format | M4 / M5 | list of `event_id` strings (most contributing first, max 5) |
| `severity` values | M4 | one of `LOW, MEDIUM, HIGH, CRITICAL` (M4's rule uses CRITICAL) |
| Model save format | M6 | `joblib` + a small `calibration.json` (temperatures) |
| `actor` | M2 | the pseudonymized `actor_id` (HMAC) as-is |

## 3. Files to create (in this order)

```
model/
  sample_events.csv      # hand-made data, ~40-60 rows, exact events.csv format
  features.py            # events -> feature vector (sliding window)
  train.py               # trains current-stage + next-stage models
  calibrate.py           # temperature scaling + ECE before/after
  predict.py             # session events -> evidence.json
  test_predict.py        # validity tests
  stub_evidence.json     # hard-coded valid example for M4/M5/M6 (create FIRST)
  model_artifacts/       # saved models + calibration.json
  requirements.txt
```

## 4. Timeline (hours from Oct 17 build start)

| Hours | Task | Output |
|---|---|---|
| 0 | Stub first: `stub_evidence.json` + stub `predict.py` | unblocks M4/M5/M6 |
| 0–4 | `sample_events.csv`, `features.py`, `train.py` on sample | pipeline runs |
| 4–10 | Retrain on M2's real splits (LightGBM or logistic regression) | `model_artifacts/` |
| 10–13 | `calibrate.py`: fit temperature on validation, record ECE before and after | **ECE numbers for the slide** |
| 13–15 | Real `predict.py` | valid evidence for all demo events |
| 15–18 | Hand model + `predict.py` to M6, fix LinuxONE issues | runs on LinuxONE |
| Stretch | GRU, ONNX export, zDLC on Telum | only if all above works |

Checkpoints: Hour 6 stubs connected, Hour 12 real model output reaches M4, Hour 16 full pipeline on LinuxONE, Hour 20 feature freeze.

## 5. Technical spec

### Features (per sliding window of the last N=10 events in a session, N is a parameter)
- count of failed outcomes, count of MFA failures
- count of privilege-change events (e.g. ALTUSER SPECIAL)
- count of sensitive-resource accesses (`sensitivity` high)
- count of discovery-type events
- `new_origin` flag (origin not previously seen for this actor), `off_hours` flag (any/last)
- event_type counts (one count per type) and the last event type
- number of events so far, seconds since session start, mean gap between events
- **Never use `stage_label` or `scenario_id` as a feature (label leakage).**

### Targets
- **current_stage** = `stage_label` of the last event in the window
- **next_stage** = `stage_label` of the next event in the same session; for the last event in a session use BENIGN (or drop it, but document the choice)

### Splits
- Use M2's train/validation/test files. If splitting yourself, **split by `session_id`, never by row**, so windows from one session do not leak across splits.

### Model
- Start with logistic regression (fast, reliable), then try LightGBM. Pick by validation macro-F1. Two classifiers: one for current, one for next.
- Set `random_state=42` everywhere. Class imbalance: use `class_weight="balanced"`.

### Calibration
- Temperature scaling (Guo et al. 2017): take logits (for LightGBM use log of predicted probabilities), find scalar T > 0 minimizing NLL on the validation set (`scipy.optimize.minimize_scalar`), divide logits by T, softmax.
- Fit **separate T for current and next**. Save to `model_artifacts/calibration.json`.
- ECE: 10 equal-width confidence bins, `ECE = sum(|acc_bin - conf_bin| * n_bin / n)`. Report before and after, for both heads, on validation and test. Also save a reliability diagram PNG.

### Evidence rules
- `stage_confidence` / `next_confidence` = calibrated max probability of each head.
- `severity` is **separate from confidence**: derive from current stage and indicators (e.g. BENIGN/INITIAL_ACCESS → LOW, DISCOVERY → MEDIUM, PRIVILEGE_ESCALATION/LATERAL_MOVEMENT → HIGH, COLLECTION_EXFIL/IMPACT or priv-esc plus sensitive access → CRITICAL). Keep this mapping in one dict at the top of `predict.py`.
- `indicators[]`: rule-based strings from the window (e.g. `new_origin`, `off_hours_activity`, `mfa_failure_then_success`, `privilege_change`, `sensitive_access`, `discovery_sweep`). M4 needs ≥3 for revoke, so be accurate, not generous.
- `top_events[]`: up to 5 `event_id`s that contributed most (use feature-contribution proxy such as the privilege/sensitive/failed events in the window, ranked by recency and risk).
- `evidence_id` = unique per call (e.g. `ev-<session_id>-<event_index>`), `model_version` = e.g. `m3-<short hash of model files>`.
- Evidence must be produced **after each event** in a session (prefix of the session), because the demo replays `demo_stream.csv` event by event.

### Reliability
- Deterministic output for same input. No network calls. Must run on LinuxONE (s390x): avoid exotic dependencies, pin versions, test `pip install` of LightGBM early (fallback to sklearn).
- Handle empty/odd input gracefully: return a valid BENIGN evidence with low confidence, never crash.

## 6. Prompts to give Antigravity (one at a time)

**Prompt 0: context**
> I am building the ML model module (M3) of a project called Threshold. I'm attaching M3_TASKS.md. Read it fully. Work only inside the `model/` folder. Do not rename any contract fields. Confirm you understand by listing the files you will create and the order, then wait.

**Prompt 1: stubs (do first)**
> Create `model/stub_evidence.json` with one valid example evidence object (all 11 fields, realistic values for a PRIVILEGE_ESCALATION session). Create a stub `model/predict.py` exposing `predict_session(events_df) -> dict` and `predict_stream(events_df) -> list[dict]` (one evidence per event, prefix-based) that return hard-coded valid evidence. Add a CLI: `python model/predict.py --events path.csv --out evidence_out.json`.

**Prompt 2: sample data**
> Create `model/sample_events.csv` (about 50 rows) in the exact events.csv schema from M3_TASKS.md. Include: one attack session (new-network logon → failed MFA → success → discovery sweep → ALTUSER SPECIAL → sensitive dataset read), one look-alike (on-call admin at 02:00 from a known origin, no failures, one privilege change), and 3 benign sessions (routine logons, a batch job, a password typo). Fill `stage_label` using the 8 fixed names, `scenario_id` for each session, pseudonymized-looking actor_ids (e.g. `U_9f3a...`). Timestamps ISO-8601.

**Prompt 3: features**
> Write `model/features.py` implementing the feature spec in Section 5: function `build_windows(df, window=10)` that returns X (DataFrame), y_current, y_next, and a metadata frame (session_id, event_id, index). No use of stage_label or scenario_id as features. Include a docstring listing every feature. Add a quick self-test under `if __name__ == "__main__"` using sample_events.csv.

**Prompt 4: training**
> Write `model/train.py`: loads events from a path argument (default sample_events.csv, or M2's train/validation CSVs when given), builds windows, trains logistic regression and LightGBM for both heads, picks the best by validation macro-F1, prints accuracy and macro-F1 per head and a confusion matrix, and saves models with joblib to `model/model_artifacts/`. Split by session_id if only one file is given. random_state=42, balanced class weights. If LightGBM is not installed, fall back to sklearn gracefully.

**Prompt 5: calibration**
> Write `model/calibrate.py`: load the saved models, compute logits on validation, fit one temperature per head by minimizing NLL, compute 10-bin ECE before and after for both heads on validation and test, save `calibration.json`, save reliability diagrams as PNG, and print a small table I can paste into a slide.

**Prompt 6: real predict**
> Replace the stub in `model/predict.py` with the real implementation per the "Evidence rules" section: load models and calibration, build the window for each prefix of a session, return valid evidence objects with calibrated confidences, rule-based indicators, top_events, severity mapping and model_version. Keep the same function names and CLI. Validate each output against a JSON schema (write `evidence.schema.json`) before returning.

**Prompt 7: tests**
> Write `model/test_predict.py` (pytest): (1) every evidence from sample_events.csv has all 11 fields with correct types; (2) confidences are in [0,1]; (3) stages are among the 8 allowed names; (4) the attack session ends with current_stage at or beyond PRIVILEGE_ESCALATION; (5) the look-alike session never reaches CRITICAL severity with confidence above 0.90; (6) output is identical across two runs; (7) empty input returns valid BENIGN evidence, no exception.

**Prompt 8: run on real data (after M2 delivers)**
> M2's files are in `data/` (train/val/test CSVs and demo_stream.csv). Retrain with them, recalibrate, and run `predict_stream` over demo_stream.csv. Report: accuracy and macro-F1 per head, ECE before/after, and how many events earlier than the first PRIVILEGE_ESCALATION event the model first predicts it as next_stage (the "early warning" lead). Fix any schema mismatch between my code and the real CSV.

**Prompt 9: LinuxONE readiness for M6**
> Write `model/requirements.txt` with pinned versions and `model/README_M3.md` with: install, train, calibrate, predict commands, artifact file list, and known s390x concerns. Confirm the code has no hard-coded absolute paths and no GPU dependency.

**Stretch prompts (only if everything above passes):** GRU sequence model with PyTorch; ONNX export; zDLC compile notes for Telum.

## 7. Acceptance checklist

- [ ] `stub_evidence.json` and stub `predict.py` shared with M4/M5/M6 in the first hour
- [ ] `sample_events.csv` loads and trains end to end
- [ ] Windows built per session, no stage_label leakage, split by session
- [ ] ECE before and after recorded (current and next heads) → goes on a slide
- [ ] `predict.py` returns schema-valid evidence for **every event** in `demo_stream.csv`
- [ ] Attack session: next_stage predicted as PRIVILEGE_ESCALATION or LATERAL_MOVEMENT with high calibrated confidence before it happens
- [ ] Look-alike session: not flagged CRITICAL at high confidence
- [ ] Tests pass; deterministic; no crash on bad input
- [ ] Model and `predict.py` handed to M6; verified on LinuxONE

## 8. Hand-offs

- **To M4:** evidence.json format, severity values, indicators/top_events format
- **To M5:** `predict_stream()` for event-by-event replay
- **To M6:** model_artifacts, requirements.txt, evaluation numbers (stage accuracy, early-warning lead, ECE)
- **To M1:** ECE before/after and accuracy numbers for the results slide
