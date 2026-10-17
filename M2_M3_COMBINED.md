# Threshold: Combined M2 (Data) + M3 (ML Model) Plan for Antigravity

Project: **Threshold** (IBM Z Datathon 2026, Track: AI Secured)
Owner: Vinayak (M2 + M3). Folders: `data/` (M2) and `model/` (M3). Run everything from the repo root.

This file replaces `M2_TASKS.md` and `M3_TASKS.md` as the single thing to give Antigravity. Those two files remain the detailed references.

---

## 0. Rules so work never overlaps (read first, give these to Antigravity first)

1. **Audit before building.** Run Prompt A0 (Section 5). It inventories what already exists in the repo and marks every file below as `DONE`, `PARTIAL` or `MISSING`. Build only what is `MISSING` or finish what is `PARTIAL`.
2. **Never recreate or overwrite an existing file.** If a file exists: read it, extend it, keep what works, and say what you changed. Delete nothing without asking.
3. **One owner per file.** Each file in Section 3 is created by exactly one prompt. If another prompt needs it, it imports or reads it; it does not rewrite it.
4. **Single source of truth for constants.** Stage names, event types, outcomes, sensitivity levels and column names live in `data/schema.py` (mirrored in `data/event_vocab.md`). `data/generate.py`, `model/features.py` and all adapters import from it. Nobody redefines these lists.
5. **Keep a log.** Append to `PROGRESS.md` in the repo root after each prompt: date/time, files created or changed, what was verified. The Section 4 status table is copied into it by Prompt A0.
6. **Do not touch other roles' folders** (`policy/`, `audit/`, `app/`, `docs/`) or the three contracts.
7. **Synthetic data trains. Public data only tests.** Never train on LANL/Mordor/Splunk data.

## 1. What each role does (plain English)

- **M2 (data):** generates fake-but-realistic mainframe security events: normal activity, many copies of an attack, and a look-alike legitimate admin. Splits them, pseudonymizes user IDs, makes the demo file and harder test sets, and converts public datasets for testing.
- **M3 (model):** turns events into numbers, trains a model to predict the session's current attack stage and next stage, calibrates its confidence, and outputs an explainable `evidence.json`. The model never acts; M4's policy engine decides.

**Done when:** `demo_stream.csv` exists and loads cleanly (M2), and `predict.py` returns valid `evidence.json` for every event in `demo_stream.csv` (M3).

## 2. Contracts

**`events.csv`** (M2 produces, M3 reads), exact column names and order:
`event_id, timestamp, system_id, actor_id, session_id, event_type, outcome, resource, sensitivity, origin, off_hours, stage_label, scenario_id`

**`evidence.json`** (M3 produces; M4, M5, M6 read):
`evidence_id, actor, session_id, current_stage, stage_confidence, next_stage, next_confidence, severity, indicators[], top_events[], model_version`

**Stages (fixed 8):** `BENIGN, INITIAL_ACCESS, CREDENTIAL_ACCESS, DISCOVERY, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, COLLECTION_EXFIL, IMPACT`

**Allowed values (put in `data/schema.py` and `data/event_vocab.md`):**
| Column | Values |
|---|---|
| timestamp | ISO-8601 UTC |
| event_type | `LOGON, LOGOFF, MFA, JOB_SUBMIT, PASSWORD_CHANGE, DATASET_LIST, RACF_LISTUSER, ALTUSER_SPECIAL, PERMIT, DATASET_READ, DATASET_COPY` |
| outcome | `SUCCESS, FAILURE` |
| sensitivity | `LOW, MEDIUM, HIGH` |
| origin | e.g. `NET_KNOWN_03`, `NET_NEW_17` |
| off_hours | `0` or `1` |
| actor_id | `U_` + 12 hex chars (HMAC pseudonym), never a raw user ID |
| scenario_id | `benign, attack_v1, attack_v2, lookalike_v1, ...` (analysis only; the model must never use it as a feature) |

**Evidence format defaults (confirm with M4):** `indicators[]` = list of short strings from `new_origin, off_hours_activity, mfa_failure_then_success, privilege_change, sensitive_access, discovery_sweep`; `top_events[]` = list of up to 5 `event_id` strings; `severity` in `LOW, MEDIUM, HIGH, CRITICAL`; model saved with `joblib` plus `calibration.json`.

## 3. Files, owners and dependencies

| File | Owner | Needs first |
|---|---|---|
| `data/schema.py` + `data/event_vocab.md` | M2 | nothing |
| `model/stub_evidence.json` + stub `model/predict.py` | M3 | nothing |
| `data/generate.py` | M2 | schema |
| `data/validate_events.py` | M2 | schema |
| `data/pseudonymize.py` | M2 | nothing |
| `data/make_splits.py`, `data/make_demo_stream.py` | M2 | generate |
| `model/features.py` | M3 | schema |
| `model/train.py` | M3 | features, generator output |
| `model/calibrate.py` | M3 | trained models |
| `model/predict.py` (real) | M3 | train, calibrate |
| `model/test_predict.py`, `evidence.schema.json` | M3 | predict |
| `data/make_hard_variants.py` | M2 | generate |
| `model/evaluate_realdata.py` | M3 | adapters, predict |
| `data/adapters/lanl_adapter.py`, `mordor_adapter.py` | M2 | schema, validate |
| `data/README_data.md`, `model/README_M3.md`, `model/requirements.txt` | M2 / M3 | everything |

**Note on the old "hand-made sample":** M3's hand-made `sample_events.csv` is only needed if `generate.py` is not ready yet. Once the generator can output a small file, use that instead and do not maintain a second sample.

## 4. Status table (Prompt A0 fills this in; update it as you go)

| # | File / task | Status (DONE / PARTIAL / MISSING) | Notes |
|---|---|---|---|
| 1 | schema.py + event_vocab.md | | |
| 2 | stub_evidence.json + stub predict.py | | |
| 3 | generate.py | | |
| 4 | validate_events.py | | |
| 5 | pseudonymize.py | | |
| 6 | make_splits.py, make_demo_stream.py | | |
| 7 | features.py | | |
| 8 | train.py | | |
| 9 | calibrate.py | | |
| 10 | predict.py (real) | | |
| 11 | test_predict.py + evidence.schema.json | | |
| 12 | make_hard_variants.py | | |
| 13 | LANL / Mordor adapters | | |
| 14 | evaluate_realdata.py | | |
| 15 | READMEs + requirements.txt | | |

## 5. Prompts for Antigravity (in this order; one at a time; check each result)

### Phase A: setup and audit

**A0: context + audit (always first)**
> I'm building two modules of a project called Threshold: M2 (data, in `data/`) and M3 (ML model, in `model/`). I'm attaching M2_M3_COMBINED.md. Read it fully, especially Section 0 (rules). Then audit the repository: list every file from Section 3 that already exists, read each one, and mark each as DONE (works and matches the contracts), PARTIAL (exists but incomplete or off-contract; say what is missing) or MISSING. Copy the Section 4 table into `PROGRESS.md` with your findings. Do not create, change or delete anything yet. Then wait for me.

*(Paste Antigravity's audit result back to me and I'll tell you which prompts to skip.)*

### Phase B: shared foundations

**B1: schema + vocabulary (skip if DONE)**
> Create `data/schema.py` with constants STAGES, COLUMNS, EVENT_TYPES, OUTCOMES, SENSITIVITY, OFF_HOURS and the actor_id regex, exactly as in Section 2, and `data/event_vocab.md` mirroring them plus a table of the event sequence and stage_label per event for benign, attack_v1, attack_v2 and lookalike_v1 (see B2). Do not duplicate these lists anywhere else.

**B2: scenario definitions (put these in event_vocab.md, do not create a separate file)**
- *Attack v1:* LOGON new origin success → `INITIAL_ACCESS`; MFA failure(s) then success → `CREDENTIAL_ACCESS`; several `DATASET_LIST`/`RACF_LISTUSER` → `DISCOVERY`; `ALTUSER_SPECIAL` → `PRIVILEGE_ESCALATION`; `DATASET_READ` on HIGH sensitivity → `COLLECTION_EXFIL`.
- *Attack v2:* as v1, then after privilege escalation a LOGON on a **second `system_id`** → `LATERAL_MOVEMENT`, then sensitive read → `COLLECTION_EXFIL`; optional final `IMPACT` event. (Needed so M3 learns `LATERAL_MOVEMENT`/`IMPACT`, which M4's early-warning rule depends on.)
- *Look-alike:* 02:00, known origin, no failures, one `ALTUSER_SPECIAL`, a few routine reads, **all labeled `BENIGN`** (the same event must be BENIGN here and PRIVILEGE_ESCALATION in the attack, so the model must use context).
- *Benign background:* routine logons from known origins, batch jobs, occasional password typos.

**B3: stub for the team (skip if DONE)**
> Create `model/stub_evidence.json` (one valid evidence object with all 11 fields, realistic values) and a stub `model/predict.py` exposing `predict_session(events_df) -> dict` and `predict_stream(events_df) -> list[dict]` (one per event, prefix-based) returning hard-coded valid evidence, plus a CLI `python model/predict.py --events path.csv --out evidence_out.json`.

### Phase C: data (M2)

**C1: generator (skip if DONE; if PARTIAL, extend it)**
> Write or extend `data/generate.py`: seeded (`--seed`, default 42, reproducible), importing constants from `data/schema.py`. Produce benign background plus N randomized copies each of attack_v1, attack_v2 and lookalike_v1: different users and times, varied gaps, 0–5 extra noise events, 1–3 MFA failures, discovery sweep length 2–6, different resources. Look-alike labeled all BENIGN. Output one CSV with all 13 columns and `scenario_id` set; CLI args for counts. Also support `--small` to emit a tiny file (about 60 rows) for quick tests of M3 code.

**C2: validator**
> Write `data/validate_events.py`: checks exact columns/order, allowed values (from `data/schema.py`), ISO timestamps, stage labels, `off_hours` in {0,1}, events time-ordered within a session, one actor per session. Print counts per stage and scenario; exit non-zero on error. Run it on the generator output.

**C3: pseudonymization**
> Write `data/pseudonymize.py`: user ID → `U_` + first 12 hex of HMAC-SHA256(secret, user_id), secret from env var `THRESHOLD_HMAC_KEY` (clear error if missing, never hard-coded). Used by the generator at ingest. Add a test: same user always maps the same, different users differ.

**C4: splits + demo stream**
> Write `data/make_splits.py` (train/val/test by `session_id`, about 70/15/15, stratified by scenario_id) and `data/make_demo_stream.py` (`demo_stream.csv` with exactly one attack session and one look-alike session, interleaved in time, unseen users and parameters). Output to `data/out/`.

### Phase D: model training (M3)

**D1: features (skip if DONE)**
> Write or extend `model/features.py`: `build_windows(df, window=10)` returns X, y_current, y_next and a metadata frame (session_id, event_id, index). Import constants from `data/schema.py`. Features per sliding window: counts of failures, MFA failures, privilege changes (`ALTUSER_SPECIAL`, `PERMIT`), HIGH-sensitivity accesses, discovery events; new-origin flag (origin not seen before for this actor), off-hours flag; per-event_type counts and last event type; events so far, seconds since session start, mean gap. **Never use `stage_label` or `scenario_id` as features.** current_stage = stage_label of the last event in the window; next_stage = stage_label of the next event in the session (BENIGN for the last event; document the choice). Handle classes missing from a split without crashing. Self-test on a small generator file.

**D2: training**
> Write or extend `model/train.py`: load M2's train/validation CSVs from `data/out/`, build windows, train logistic regression and LightGBM (fallback to sklearn if LightGBM is missing) for both heads, pick the best by validation macro-F1, print accuracy, macro-F1 and confusion matrix per head, save models with joblib to `model/model_artifacts/`. `random_state=42`, `class_weight="balanced"`. If only one file is given, split by `session_id`.

### Phase E: calibration, prediction, tests (M3)

**E1: calibration**
> Write `model/calibrate.py`: load models, compute logits on validation (LightGBM: log of predicted probabilities), fit one temperature per head by minimizing NLL (`scipy.optimize.minimize_scalar`), compute 10-bin ECE before and after for both heads on validation and test, save `calibration.json` and reliability-diagram PNGs, and print a slide-ready table.

**E2: real predict**
> Replace the stub in `model/predict.py` (keep function names and CLI): load models + calibration, build the window for each prefix of a session, return schema-valid evidence with calibrated confidences. `severity` from a single mapping dict at the top of the file (BENIGN/INITIAL_ACCESS → LOW, DISCOVERY → MEDIUM, PRIVILEGE_ESCALATION/LATERAL_MOVEMENT → HIGH, COLLECTION_EXFIL/IMPACT or privilege change plus sensitive access → CRITICAL); `indicators[]` rule-based and accurate (M4 needs at least 3 for revoke, so do not inflate); `top_events[]` up to 5 `event_id`s; `evidence_id` unique per call; `model_version` from a hash of the model files. Validate against `evidence.schema.json` before returning. Deterministic, no network calls; bad or empty input returns valid BENIGN evidence with low confidence, never an exception.

**E3: tests**
> Write `model/test_predict.py` (pytest): all 11 fields present with right types; confidences in [0,1]; stages among the 8; attack session ends at or beyond PRIVILEGE_ESCALATION; look-alike never reaches CRITICAL with confidence above 0.90; identical output across two runs; empty input returns valid BENIGN evidence; predict runs on every event of `demo_stream.csv`.

### Phase F: harder tests and real-data checks

**F1: hard variants (M2)**
> Write `data/make_hard_variants.py`: held-out variants with reordered steps, extra noise, slower pacing, and more look-alike types (batch-job admin change, helpdesk password reset). Same schema and labels, variants marked in `scenario_id`. Output `data/out/test_hard.csv`; print counts per variant. These must not appear in training data.

**F2: LANL adapter (M2; after the model works; cap about 2–3 hours for F2–F4 together)**
> Write `data/adapters/lanl_adapter.py`: stream `auth.txt` and `redteam.txt` (gzip ok, never load all in memory), keep all sessions of red-team users plus a random sample of other users, sessions per user with a 30-minute inactivity gap, map to the events.csv columns (origin ← source computer, system_id/resource ← destination computer, outcome ← success/failure, event_type LOGON/LOGOFF, sensitivity MEDIUM, off_hours 0 because real times are undisclosed; document this), label red-team events `LATERAL_MOVEMENT` and the rest `BENIGN`, pseudonymize users. Output `data/out/lanl_test.csv`; `--max-rows` for quick tests; run the validator.

**F3: Mordor adapter (M2)**
> Write `data/adapters/mordor_adapter.py`: read a folder of OTRF Mordor JSON/zip recordings, derive the stage label from the tactic folder (`initial_access→INITIAL_ACCESS`, `credential_access→CREDENTIAL_ACCESS`, `discovery→DISCOVERY`, `privilege_escalation→PRIVILEGE_ESCALATION`, `lateral_movement→LATERAL_MOVEMENT`, `collection`/`exfiltration→COLLECTION_EXFIL`, `impact→IMPACT`), map Windows event IDs to our event_type/outcome (document the table in the file; skip unmapped events; verify event-ID meanings), one recording = one session, pseudonymize users. Output `data/out/mordor_test.csv`; run the validator.

**F4: real-data evaluation (M3)**
> Write `model/evaluate_realdata.py`: run `predict_stream` on `lanl_test.csv` and `mordor_test.csv` and report, per dataset: sessions, how many red-team/attack sessions reached a high stage or severity, how many benign sessions did (false alarms), and for Mordor whether predicted stages move up the same tactic order. Print a small table plus caveats (different platform, approximate mapping, coarse labels). Do not compare these numbers with the synthetic results.

### Phase G: evaluation numbers and hand-off

**G1: final evaluation**
> Run the model on `test_hard.csv` and the test split. Report: stage accuracy and macro-F1 per head, ECE before/after, how many events earlier than the first PRIVILEGE_ESCALATION event the model first predicts it as `next_stage` (early-warning lead), and results on the look-alike variants. Save as `model/results_m3.md` for M6 and M1's slides.

**G2: README + LinuxONE readiness**
> Write `model/requirements.txt` (pinned), `model/README_M3.md` and `data/README_data.md`: commands to regenerate everything from scratch (generator → splits → demo stream → hard variants → adapters → train → calibrate → predict), seed, required env vars (`THRESHOLD_HMAC_KEY`), artifact list, known limitations, and s390x concerns. Confirm there are no absolute paths and no GPU dependency.

**Stretch (only if all above passes):** GRU sequence model, ONNX export, zDLC compile for Telum.

## 6. Timeline (hours from build start, from the team plan)

| Hours | M2 (data) | M3 (model) |
|---|---|---|
| 0–1 | schema + vocab to M3 first | stub `predict.py` + `stub_evidence.json` to team |
| 1–4 | generator, validator | features on `--small` generator output |
| 4–6 | splits, demo stream | train on real splits |
| 6–8 | pseudonymization | iterate models |
| 8–14 | help M3 with features | training done (4–10), calibration (10–13) |
| 13–15 | | real `predict.py` |
| 14–20 | hard variants to M6 | hand model to M6, fix LinuxONE issues |
| after | LANL/Mordor adapters | real-data evaluation, final numbers |

Team checkpoints: Hour 6 stubs connected, Hour 12 real model output reaches M4, Hour 16 full pipeline on LinuxONE, Hour 20 feature freeze.

## 7. Messages to send (you send these; I cannot)

- **To M4:** confirm evidence formats (Section 2), say attack v2 adds a lateral-movement step, ask to keep thresholds 0.90 and 0.75 configurable in `rules.yaml`, and tell them evidence is emitted after every event.
- **To M1:** ask to link `data/event_vocab.md` next to the three contracts, say `predict_stream(events_df)` is the function for `run_demo.py`, and that real-data tests are a sanity check on Windows logs, not proof.

## 8. Acceptance checklist

- [ ] Audit done; `PROGRESS.md` exists; no file duplicated or overwritten
- [ ] `data/schema.py` is the only place constants are defined
- [ ] Stub shared with the team in the first hour
- [ ] Generator reproducible; look-alike labeled all BENIGN; attack v2 included
- [ ] Splits by session; demo stream has one attack + one look-alike with unseen users
- [ ] All CSVs pass `validate_events.py`; no raw user IDs anywhere
- [ ] No `stage_label` / `scenario_id` leakage in features
- [ ] ECE before and after recorded for both heads
- [ ] `predict.py` returns schema-valid evidence for every event in `demo_stream.csv`; tests pass; deterministic
- [ ] Hard variants delivered to M6; results file ready for M1
- [ ] Real-data checks run with caveats written down
- [ ] Model + `predict.py` verified on LinuxONE
