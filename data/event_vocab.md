# M2 event vocabulary and handoff

Generate: `python data/generate.py --seed 42 --sessions 400` (Python stdlib only).

Required CSV columns, in shared-contract order:
`event_id,timestamp,system_id,actor_id,session_id,event_type,outcome,resource,sensitivity,origin,off_hours,stage_label,scenario_id`

- event_type: LOGON, MFA, DATASET_ACCESS, ALTUSER_SPECIAL, COMMAND_EXEC, CRYPTO_OP, LOGOFF
- outcome: SUCCESS, FAIL
- sensitivity: INTERNAL, HIGH, CRITICAL (HIGH is reserved; current generator emits INTERNAL/CRITICAL)
- origin: NEW_NET, KNOWN_NET
- off_hours: True, False (CSV strings; parse explicitly, never bool("False"))
- stage_label: BENIGN, INITIAL_ACCESS, CREDENTIAL_ACCESS, DISCOVERY, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, COLLECTION_EXFIL, IMPACT
- scenario_id: background, lookalike, attack, attack_lateral, attack_impact
- timestamp: UTC ISO 8601 with Z; system_id: SYS1, SYS2.
- actor_id: keyed HMAC-SHA256 pseudonym, truncated to 24 hex digits; raw synthetic identities are never exported.

Files: train.csv, validation.csv, test.csv, harder_test.csv; demo_stream.csv contains exactly one basic attack and one legitimate look-alike. Training includes lateral and impact variants to represent all eight stages. These extra variants are synthetic extensions, not additional live demos.

Each file also has an `_events.csv` copy without stage_label/scenario_id for inference and a `_labels.csv` sidecar for evaluation. Labels must never enter model features. IDs also must not become predictive features. Use train for fitting and validation for calibration. Keep test and harder_test untouched until evaluation.

Sidecar next_stage_label means next DIFFERENT stage; if none exists it stays at the current stage, keeping the fixed eight-class vocabulary. Confirm this convention with M3 before training. It is not necessarily the next event's label.

Use validation for temperature scaling, with policy tuning on a separate partition of train. Splits have disjoint sessions and actors. Same seed and key reproduce identical bytes. Default key is PUBLIC and intended only for invented data. For actual identities set THRESHOLD_HMAC_KEY to a private secret without committing it; production key management is outside this prototype.

Known limitations: all data is synthetic normalized telemetry, not a verified SMF binary mapping. Class balance is artificial (60% attack), and easy scenario signals can inflate accuracy. Harder test adds benign noise, slow pacing and new-origin legitimate sessions; it does not demonstrate unseen attack-family generalization. Synthetic ECE does not establish calibration at enterprise prevalence. No fixed-confidence results or desired policy outcomes are manufactured.

Integration warnings observed on origin/main: predict.py is still a stub with fixed confidence. predict_stream currently treats all rows as one session; caller must group by actor/session before replay. M3 emits actor/current_stage/stage_confidence whereas policy_agent requires actor_id/timestamp/threat_type/confidence/predicted_next_stage/resource_tier/action/is_privileged_actor. M1/M3/M4 must agree an adapter before the live demo. Do not claim the real model-policy chain works from stub results.
