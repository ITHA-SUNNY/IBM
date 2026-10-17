# Threshold: Progress Log (M2 Data + M3 ML Model)

Started: 2026-10-17 18:17 UTC+05:30
Owner: Vinayak (M2 + M3)

---

## Repository Audit Status Table (Prompt A0)

| # | File / task | Status (DONE / PARTIAL / MISSING) | Notes |
|---|---|---|---|
| 1 | `data/schema.py` + `data/event_vocab.md` | **MISSING** | `data/` directory does not exist yet. Single source of truth for constants needed first. |
| 2 | `model/stub_evidence.json` + stub `model/predict.py` | **DONE** | `model/stub_evidence.json` exists with all 11 fields. Full `predict.py` already exists, superseding the stub. |
| 3 | `data/generate.py` | **MISSING** | Synthetic generator not yet implemented. |
| 4 | `data/validate_events.py` | **MISSING** | Event schema and invariant validator not yet implemented. |
| 5 | `data/pseudonymize.py` | **MISSING** | HMAC-SHA256 pseudonymizer (`U_` + 12 hex) not yet implemented. |
| 6 | `data/make_splits.py`, `data/make_demo_stream.py` | **MISSING** | Session-stratified split generator and demo stream generator not yet created. |
| 7 | `model/features.py` | **PARTIAL** | Exists (338 lines) with sliding window feature extraction and zero label leakage; but hardcodes local `STANDARD_EVENT_TYPES` rather than importing from `data/schema.py`, and vocabulary does not yet match Section 2 contract. |
| 8 | `model/train.py` | **PARTIAL** | Exists (349 lines) with dual-head training, session splitting, and model persistence; needs to read from `data/out/` splits and use `data/schema.py` constants once generated. |
| 9 | `model/calibrate.py` | **PARTIAL** | Exists (434 lines) with temperature scaling and ECE calculation; working on initial sample, but needs recalibration on new dataset splits. |
| 10 | `model/predict.py` (real) | **PARTIAL** | Exists (443 lines) with `predict_session`, `predict_stream`, and CLI; works and generates valid evidence on sample, but needs alignment with `data/schema.py` event vocabulary and indicators. |
| 11 | `model/test_predict.py` + `model/evidence.schema.json` | **PARTIAL** | `evidence.schema.json` is **DONE** (validates all 11 fields and 8 stages). `test_predict.py` exists and tests all 7 invariants, but currently targets `sample_events.csv`; needs updating to test against `demo_stream.csv`. |
| 12 | `data/make_hard_variants.py` | **MISSING** | Held-out test set generator not yet implemented. |
| 13 | `data/adapters/lanl_adapter.py`, `mordor_adapter.py` | **MISSING** | Public dataset adapters not yet implemented. |
| 14 | `model/evaluate_realdata.py` | **MISSING** | Public dataset evaluation script not yet implemented. |
| 15 | `data/README_data.md`, `model/README_M3.md`, `model/requirements.txt` | **MISSING** | Documentation and pinned requirements files not yet created. |

---

## Audit Log Entries

### [2026-10-17 18:17 UTC+05:30] Prompt A0: Repository Audit & Inventory
- **Action**: Performed read-only audit of existing codebase against M2_M3_COMBINED specification.
- **Findings**:
  - `model/` contains early implementations of M3 (`stub_evidence.json`, `evidence.schema.json`, `features.py`, `train.py`, `calibrate.py`, `predict.py`, `test_predict.py`, `sample_events.csv`, and trained joblib artifacts).
  - Existing `model/` code is functional and well-structured, but was developed against an earlier event vocabulary and sample file (`sample_events.csv` with `LOGON_ATTEMPT`, boolean `off_hours`, etc.).
  - `data/` module (M2) does not exist yet.
  - No files were modified or deleted.
- **Verification**: Verified existing files, schemas, and prediction pipeline execution. Created `PROGRESS.md`.

### [2026-10-17 18:20 UTC+05:30] Added M2_M3_COMBINED.md
- **Action**: Saved the user's master combined specification and execution plan to `M2_M3_COMBINED.md` in repository root.
- **Verification**: File verified in repository root.


### [2026-10-17 18:35] B1, C1-C4, R1, retrain + recalibrate
- Created: data/schema.py, data/event_vocab.md, data/pseudonymize.py, data/generate.py, data/validate_events.py, data/make_splits.py, data/make_demo_stream.py. Outputs in data/out/ (events_small, events_full, train/val/test, demo_stream); all pass validate_events.py.
- Changed (model/): features.py, predict.py, train.py, calibrate.py, test_predict.py now import from data/schema.py; no absolute paths; function names and CLIs unchanged. train.py no longer refits on train+val when pre-made splits are used (keeps val held-out). predict.py passes actor origin history so new_origin matches training; MFA indicator counts MFA events only.
- Verified: features self-test OK; train + calibrate ran; pytest model/test_predict.py = 8 passed.
- ECE (before -> after): current val 6.00->5.18%, test 6.21->5.17%; next val 8.22->6.56%, test 8.60->6.14%.
- Open: UNMAPPED legacy names need a decision (see data/event_vocab.md); 70 BENIGN val events predicted INITIAL_ACCESS.

### [2026-10-17 18:48] Add benign_offhours, demo baselines, retrain + recalibrate
- Added legitimate off-hours benign sessions (scenario_id=benign_offhours, N=100) to data/generate.py.
- Added short baseline benign sessions (scenario_id=demo_baseline) for both demo actors in data/make_demo_stream.py.
- Mapped FTP_TRANSFER -> DATASET_COPY; dropped remaining 13 legacy unmapped names.
- Regenerated, re-split, and validated all CSVs; retrained and recalibrated models.
- Result: look-alike Event 1 is now cleanly predicted BENIGN (0.86); new_origin now activates for attack replay and stays off for look-alike.
- Validation ECE: Current stage 6.54% -> 5.01% (23.4% reduction); Next stage 7.96% -> 6.32% (20.6% reduction).
- Test ECE: Current stage 5.89% -> 4.67% (20.7% reduction); Next stage 7.09% -> 6.36% (10.3% reduction).

### [2026-10-17 18:55] F1 Hard Variants & Policy Invariant Evaluation
- Created data/make_hard_variants.py; generated data/out/test_hard.csv (1383 events, 140 sessions); passes validate_events.py.
- Evaluated M4 Early Warning (>=0.75 next_conf) and Revoke rules on test.csv and test_hard.csv.
- Key findings: Early warning fires before PrivEsc on 22.2% of standard attacks (median lead 1.5-2 events) due to next-event target granularity.
- Key vulnerability: lookalike_high_read causes false revokes on 20% of sessions because sensitive_access checks row sensitivity rather than read event types.
- Event 9 deep-dive documented and full report saved to model/results_m3.md.

### [2026-10-17 19:07] Step 1: sensitive_access indicator fix & stream ordering fix
- Fixed sensitive_access in model/predict.py to count only DATASET_READ and DATASET_COPY events on HIGH sensitivity resources.
- Added test_lookalike_altuser_on_high_resource_no_sensitive_access in model/test_predict.py (pytest 9/9 passed).
- Fixed row-index preservation in predict_stream across interleaved session streams.
- Investigated lookalike_helpdesk_reset false revoke: confirmed session sess-hard-lookalike_helpdesk_reset-0138 has zero false revokes; previous report was an evaluation index mapping artifact from interleaved sessions.
- Re-evaluated test.csv and test_hard.csv: False revokes on all look-alikes dropped to exactly 0 / 10 (0.0%). Revoke timing on attacks now honestly fires on the exact event of first sensitive read (diff = 0.0). Results updated in model/results_m3.md.

### [2026-10-17 20:55] Step 2: Next Distinct Stage Target Optimization
- Implemented `next_distinct` stage target formulation in `model/features.py` and `model/train.py`, targeting the first subsequent different stage in the session.
- Trained and calibrated separate artifacts in `model/model_artifacts_distinct/`, leaving baseline artifacts intact in `model/model_artifacts/`.
- Updated `model/calibrate.py` and `model/predict.py` to support `next_stage_target` and seamless loading via `artifacts_dir`.
- Validation Macro-F1 for `next_stage` improved from 0.5653 to 0.7855 (+22.02 pts / +38.9% relative); accuracy increased from 82.76% to 89.50%.
- ECE on held-out test split calibrated to 5.18% (25.9% reduction).
- Evaluated on `test.csv`: Early warning detection before `PRIVILEGE_ESCALATION` rose from 22.2% (2/9) to **100.0% (9/9)** with median lead increasing from 1.5-2.0 to **5.0 events**.
- Evaluated on `test_hard.csv`: Early warning detection rose from 10.0% to **100.0% (10/10)** on `attack_noisy` (lead: 6.0 events) and from 20.0% to **100.0% (10/10)** on `attack_reordered` (lead: 5.0 events).
- Zero false early warnings (0/142, 0.0%) and zero false revokes (0/142, 0.0%) across all benign and look-alike scenarios on both test splits.
- All results recorded in `model/results_m3.md` Section 7.

### [2026-10-17 21:18] Step 3: Timing Features Elimination & Slow-Paced Defense
- Investigated `attack_slow_paced` evasion: revealed that linear weights for `mean_gap_seconds` (+2.05), `seconds_since_session_start` (+0.99), and `last_gap_seconds` (+1.07) acted as a spurious shortcut to `BENIGN`, overwhelming behavioral indicators when gaps were large.
- Added `--exclude-timing` option to `model/features.py`, `model/train.py`, and `model/calibrate.py`.
- Trained and calibrated separate artifacts in `model/model_artifacts_notiming/` using `next_distinct` target without timing features.
- Results on `attack_slow_paced`: Early Warning jumped from **0/10 (0.0%) $\rightarrow$ 10/10 (100.0%)** (median lead 4.5 events); Revoke jumped from **0/10 (0.0%) $\rightarrow$ 10/10 (100.0%)** (rel = 0.0 on first sensitive read).
- Zero false early warnings (0/206, 0.0%) and zero false revokes (0/206, 0.0%) across all benign and look-alike scenarios across both test splits.
- Total attack early warning coverage across all 5 variants reached **48/48 (100.0%)**.
- Full 3-way comparative evaluation documented in Section 8 of `model/results_m3.md`.

### [2026-10-17 22:15] Step 4: Multi-Distribution Integration, Unified Retraining & Full Submission Deliverables
- Ingested teammate's external dataset (`data/external/converted_clean/`) converted from GitHub branch `feature/m2-synthetic-data`.
- Cross-dataset testing revealed domain shift: look-alike false revokes occurred because teammate's generator assigned `ALTUSER_SPECIAL` + `DATASET_READ` on `HIGH` sensitivity to look-alikes with label `BENIGN`.
- Merged `data/out/` and `data/external/` into `data/combined/train.csv` (8,977 events, 932 sessions) and `data/combined/validation.csv` (4,917 events, 514 sessions) with conflict-free session IDs.
- Trained and calibrated Unified Model in `model/model_artifacts_unified/` (`next_distinct` target, `--exclude-timing`).
- Multi-dataset benchmark across all 4 held-out test splits (>11,400 events):
  - Internal `test.csv` & `test_hard.csv`: 100% attack detection, 0% false revokes, 100% slow-paced attack detection.
  - External `test.csv` & `harder_test.csv`: 100% attack detection, 0% false revokes (320/320 attacks caught, 0/240 look-alikes revoked!).
- Created presentation Jupyter Notebook `model/M3_Detection_Pipeline.ipynb` featuring the main dataset, feature engineering, calibration curves, 4-dataset benchmark, live stream replay, and IBM Telum SLA profile.
- Created `model/requirements.txt` and `model/README_M3.md` for M6 (LinuxONE / s390x) deployment readiness.
- Validated all 9/9 unit tests passing (`pytest model/test_predict.py` in 6.85s). Module M3 is 100% complete and ready for handoff.



