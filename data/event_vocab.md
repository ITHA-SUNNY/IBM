# M2 event vocabulary v3.0 ? Vinayak schema aligned

`data/schema.py` is the single source of truth supplied by Vinayak. Generator, strict validator and feature helper import it; model/adapters must import it too. Run `python data/generate.py`, `python data/verify_data.py`, and `python -m unittest discover -s data -p "test_*.py"`.

## Exact CSV contract

Exactly these 13 columns, in order:
`event_id,timestamp,system_id,actor_id,session_id,event_type,outcome,resource,sensitivity,origin,off_hours,stage_label,scenario_id`

No operation column. Listing/reading/copying are event_type values themselves.

- event_type: LOGON, LOGOFF, MFA, JOB_SUBMIT, PASSWORD_CHANGE, DATASET_LIST, RACF_LISTUSER, ALTUSER_SPECIAL, PERMIT, DATASET_READ, DATASET_COPY
- outcome: SUCCESS, FAILURE
- sensitivity: LOW, MEDIUM, HIGH
- off_hours: 0 or 1; UTC hour <6 or >=20, computed by schema.is_off_hours (not the former 22:00 cutoff).
- actor_id: U_ plus first 12 lowercase hex characters of HMAC-SHA256.
- timestamp: %Y-%m-%dT%H:%M:%SZ (UTC)
- origin: KNOWN_NET or NEW_NET in this generator; schema itself only requires non-empty text.
- standard scenario_id: benign, attack_v1, attack_v2, lookalike_v1. demo_baseline is the permitted non-empty custom history label.
- fixed stage vocabulary: BENIGN, INITIAL_ACCESS, CREDENTIAL_ACCESS, DISCOVERY, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, COLLECTION_EXFIL, IMPACT.

DATASET_LIST is catalog enumeration; RACF_LISTUSER enumerates user attributes; DATASET_READ reads content; DATASET_COPY represents a synthetic transfer/copy. JOB_SUBMIT represents a submitted batch job. PASSWORD_CHANGE is a password change. These are normalized synthetic observations, not verified binary SMF records.

## No guessed legacy mappings

Use schema.normalize_event_type for the explicitly supplied mappings. Unmapped names remain unchanged and strict validation rejects them. In particular the previous generic DATASET_ACCESS, COMMAND_EXEC and CRYPTO_OP are no longer emitted. No WRITE/crypto event exists in the accepted vocabulary, so impact simulation is removed rather than disguising it as a read/copy. IMPACT remains the fixed eighth output class but has zero training observations in these files; M3 must handle absent classes explicitly or request a reviewed schema extension. Do not claim all eight stages are learned.

UNMAPPED (from supplied legacy schema): REVOKE_SPECIAL, EDIT_DATASET, WRITE_DATASET, QUERY_JOB_STATUS, VIEW_SYSLOG, RESTART_SERVICE, READ_SPOOL_OUTPUT, ALLOC_TEMP_DATASET, SORT_EXEC, WRITE_LOG, BATCH_PURGE_TEMP, BATCH_TERMINATE, ACCESS_ISPF.

## Files and demo

Canonical M5 file: data/demo_stream.csv (24 events), two same-actor BENIGN baseline histories followed by one attack_v1 and one lookalike_v1; demo admin stays KNOWN_NET and has no authentication failures. Two actors, four sessions. M5 must classify demo_baseline as history instead of attack; its current generic selector still needs that fix.

train/validation/test have 400 sessions each, including 160 attacks (40%). harder_test has 400 sessions with 4x pacing, additional JOB_SUBMIT noise, failed privilege probes and discovery-observation ordering changes, preserving causal stage progression. rare_test has 1,000 sessions and 30 attacks (3%). Origin and off-hours vary in every class of every split. Expected legitimate NEW_NET behavior remains BENIGN; origin/time alone must not cause containment. Final model/policy behavior must be measured, not assumed.

Each dataset has an unlabeled _events.csv for inference and _labels.csv for training/evaluation joins. _core.csv is now a byte-equivalent 13-column compatibility alias. Exclude stage_label/scenario_id and identifiers from predictive features. The sidecar next_stage_label means next DIFFERENT stage, otherwise current stage. M3 still needs to confirm that target convention. Train on train, calibrate on validation, tune policy on a separate partition of train, and keep test/harder/rare untouched until evaluation. Report benign false-positive counts with their denominators and precision with stated prevalence.

## Causal feature helper

`python data/features.py --events data/train_events.csv --output data/generated/train_features.csv`

Computes rolling 32-event per-actor/session counts, distinct discovered resources, origin/hour flags, inter-event seconds and the six agreed indicators. Uses PRIVILEGE_CHANGE_TYPES/DISCOVERY_TYPES from schema. MFA recovery requires ordered failure then success in that session window. Reads DATASET_READ/DATASET_COPY directly; no operation column is needed. IDs in output are join metadata only. Does not train a model, produce confidence or decide policy.

## Privacy and reproducibility

Raw IDs are invented SYNTH_<split>_<5-digit index>; demo uses SYNTH_demo_attacker/admin. They are HMAC'd before export. Private key comes from THRESHOLD_HMAC_KEY or ignored random data/.hmac_key; no secret/raw-ID mapping is committed. Repeatable bytes require same seed AND key. A fresh clone can structurally verify CSVs without the private key; byte regeneration explicitly skips if key is unavailable. Teammates can generate their own consistent IDs using their own key, but should not mix new and old splits. All actors are disjoint across splits, with intentional same-actor history inside demo.

These files are synthetic; neither their labels nor measured calibration establish enterprise accuracy. All changes from v2 require model regeneration/retraining. Current total: 22,540 events. See docs/integration_audit.md for outstanding integration risks.
