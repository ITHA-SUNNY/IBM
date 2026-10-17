# Module M3: ML Threat Detection & Probability Calibration

**Project:** Threshold (IBM Z Datathon 2026, Track: AI Secured)  
**Directory:** `model/`  
**Downstream Modules:** Hand-off to Module M4 (Policy Engine), Module M5 (SOC Dashboard), and Module M6 (Telum / LinuxONE Deployment).

---

## 1. Overview & Contracts

Module M3 consumes raw z/OS security events adhering to the 13-column telemetry schema and predicts:
1. **`current_stage`:** Current attack phase (MITRE ATT&CK for Mainframe).
2. **`next_stage`:** Next expected attack phase with calibrated confidence (Temperature Scaling).
3. **`evidence.json`:** Emits structured, schema-validated JSON with 11 contract fields to drive M4 policy decisions (`REVOKE_CREDENTIALS`, `ISOLATE_USER`).

### Input: 13-Column Telemetry Schema (`events.csv`)
`event_id, timestamp, system_id, actor_id, session_id, event_type, outcome, resource, sensitivity, origin, off_hours, stage_label, scenario_id`

### Output: Schema-Valid Evidence (`evidence.json`)
Every output conforms strictly to `model/evidence.schema.json`:
- `evidence_id`: Unique identifier (e.g., `ev-<session_id>-<index>`)
- `actor`: Pseudonymized user identifier (`actor_id`)
- `session_id`: Session ID
- `current_stage`: One of 8 canonical stages
- `stage_confidence`: Calibrated probability [0.0, 1.0]
- `next_stage`: One of 8 canonical stages
- `next_confidence`: Calibrated probability [0.0, 1.0]
- `severity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `indicators`: List of active rule indicators (e.g. `["mfa_failure_then_success", "privilege_change", "sensitive_access"]`)
- `top_events`: Up to 5 contributing `event_id` strings
- `model_version`: Deterministic model fingerprint (e.g. `m3-unified-v1`)

---

## 2. Installation & Quickstart

```bash
# Install dependencies
pip install -r model/requirements.txt

# Run test suite (9/9 tests)
pytest model/test_predict.py
```

---

## 3. CLI Commands

### A. Training
```bash
# Train on the Unified Dataset (Internal + External Telemetry)
python model/train.py \
  --train data/combined/train.csv \
  --val data/combined/validation.csv \
  --artifacts model/model_artifacts_unified \
  --next-target next_distinct \
  --exclude-timing
```

### B. Calibration (Temperature Scaling)
```bash
python model/calibrate.py \
  --val data/combined/validation.csv \
  --test data/out/test.csv \
  --artifacts model/model_artifacts_unified \
  --next-target next_distinct
```

### C. Streaming Prediction & Evidence Generation
```bash
# Stream events and output evidence.json for M4/M5
python model/predict.py \
  --events data/out/demo_stream.csv \
  --artifacts model/model_artifacts_unified \
  --out model/sample_evidence.json
```

---

## 4. Model Artifact Directories

| Directory | Target Formulation | Anti-Evasion | Training Data | Description |
|:---|:---:|:---:|:---|:---|
| `model/model_artifacts/` | `next_event` | No | `data/out/` | Initial baseline model |
| `model/model_artifacts_distinct/` | `next_distinct` | No | `data/out/` | Step 2 model (+22 pts F1 jump) |
| `model/model_artifacts_notiming/` | `next_distinct` | Yes | `data/out/` | Step 3 model (100% slow attack detection) |
| `model/model_artifacts_unified/` | `next_distinct` | Yes | `data/combined/` | **Recommended Unified Production Model** (0% false revokes across all 4 benchmark test splits) |

Each artifact directory contains:
- `current_stage_model.joblib`: Serialized classifier for Head 1
- `next_stage_model.joblib`: Serialized classifier for Head 2
- `calibration.json`: Optimal temperature values ($T_{curr}$, $T_{next}$)
- `reliability_diagram.png`: Calibration curve showing ECE reduction
- `model_metadata.json`: Feature names, targets, and training configuration

---

## 5. LinuxONE (s390x) & IBM Telum Deployment (Module M6)

1. **No GPU Dependencies:** All models run purely on CPU / z16 on-chip AI acceleration.
2. **Path Portability:** All paths are relative or dynamic via `os.path`. Zero hard-coded paths.
3. **Graceful LightGBM Fallback:** If compiling native LightGBM C++ wheels on s390x is restricted, our training and inference automatically fall back to Scikit-Learn `LogisticRegression` without interruption.
4. **Latency & SLA:**
   - Single-event inference latency: **< 1.5 ms** (well below the 10 ms SLA).
   - Artifact package footprint: **< 4.5 MB total**.
