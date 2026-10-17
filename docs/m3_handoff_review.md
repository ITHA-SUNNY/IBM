# M2 review of M3 handoff ? 18 October 2026

Reviewed M3 branch feature/m3-ml-model at 23aa10c and accessible main at db29f01. Do not confuse the trained implementation on M3's branch with the older stub on main. This review did not run the full notebook, unpickle the models or benchmark LinuxONE.

## Confirmed M2 compatibility

- COLUMNS, STAGES, EVENT_TYPES and both off-hours constants match M2's accepted schema.
- Artifact metadata uses next_distinct, which matches the M2 sidecar target: next different stage or current stage if no later different stage exists.
- Executed M3 build_windows against the canonical M2 demo: all current and next-stage labels matched the M2 sidecars; metadata feature_names matched the extracted feature set.
- Returned X has no event_id, actor_id, session_id, stage_label or scenario_id columns. IDs live in metadata. This check does not establish freedom from every statistical shortcut.
- Keep existing M2 train/validation/test files frozen; no dataset regeneration was needed for this review.

## Important feature handoff to M6

The optional data/features.py helper and its data/generated/train_features.csv output are NOT the feature contract of the saved M3 model. They use different column names and windows (32 versus M3's 10). Matching raw row counts is useful for data validation but insufficient for model input compatibility. Do not pass that CSV into the trained artifacts or reindex its missing columns to zero.

Use M3's model.features.build_windows on raw CSV with window=10, next_stage_target='next_distinct', exclude_timing=True, then align to model_metadata.json feature_names. Inference should use M3 predict_stream on raw events and an explicit artifacts_dir='model/model_artifacts_unified'. Default model_artifacts is absent from the uploaded tree; current code silently falls back to non-model behavior if weights are missing. Fail visibly rather than claiming a live trained model in that case.

## Reproducibility and integration blockers

1. Notebook cell 18 references data/external/converted_clean/test.csv and harder_test.csv. Neither was in the uploaded M3 tree. Vinayak should push these held-out files, a reproducible conversion script/source mapping, or update notebook paths to the approved M2 test files after confirming what the recorded results actually used.
2. Notebook evaluates early-warning/revoke with local DataFrame boolean expressions. It does NOT call M4 PolicyAgent. Treat those as policy-proxy/model-side results, not proof of real M3-M4-M5 execution or actual audit verification.
3. calibration.json next-stage TEST ECE worsens 0.0615 -> 0.0982 (6.15% -> 9.82%); current-stage TEST ECE also worsens slightly 0.0587 -> 0.0593. Report these honestly. Temperature is fit using validation NLL; validation NLL optimization need not improve test ECE. Do not choose a new temperature using the test set.
4. results_m3.md includes earlier next_event/calibration tables alongside later next_distinct/unified results. Final slides need the exact artifact/version/dataset and actual denominators, not a mixture of earlier experiments. Its standard-test header says 99 sessions but the supplied CSV has 114 sessions, with 1,058 events.
5. M3 branch includes its own data/generate.py, validate_events.py, schema and data/out/demo_stream.csv, while main has the approved M2 files under data/. M1 must resolve merge conflicts deliberately and choose one canonical UI demo. Do not silently replace the validated M2 generator/data while integrating model files.
6. The older M3/M4 evidence API, audit hashing and UI baseline issues documented in integration_audit.md still require an actual end-to-end check after merge; this review does not fix their owners' code.

## IMPACT claim needs dataset scope

M2 data/train.csv has no IMPACT observations, as documented. M3's data/combined/train.csv DOES have IMPACT observations from M3-generated data, e.g. JOB_SUBMIT on resource DELETE.PROD.ALL; current-stage artifact metadata contains all eight classes. Therefore 'the trained final model has no IMPACT examples' is no longer accurate for that combined artifact. Say which dataset/model the statement describes. JOB_SUBMIT on that resource is an authored simulation label, not an observed real-world impact outcome. The next-stage head has seven classes and lacks INITIAL_ACCESS, consistent with the next-distinct transitions in this training set; report head-specific coverage.

## Suggested owner actions

- M2: input/target compatibility checked; keep data frozen.
- M3: supply missing files/conversion provenance, artifact loading instructions and final consistent results.
- M6: use M3 feature extractor and explicit unified artifact directory; verify LightGBM runtime compatibility on LinuxONE. A training fallback does not make an existing LightGBM artifact load without LightGBM.
- M1/M4/M5: merge deliberately, align contracts and run real policy/audit/UI pipeline; record measured deployment evidence for the <=3 minute submission video.
