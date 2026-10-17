# M2 event vocabulary v2 and handoff

Run `python data/generate.py`; verify with `python data/verify_data.py`. Python standard library only.

## Schema status

The exact data/schema.py referenced in chat was not present on any accessible remote branch when checked. These values implement Vinayak's stated changes; full schema compatibility is pending his file/link. Do not claim it is already validated against that file.

CSV columns: event_id,timestamp,system_id,actor_id,session_id,event_type,outcome,resource,sensitivity,origin,off_hours,stage_label,scenario_id,operation.

The first 13 columns retain the shared contract; operation is an additive field required to distinguish listing, reading and copying. Strict 13-column `_core.csv` copies are provided for temporary compatibility, but they lose operation detail. Consumers should use column names and read the full files.

- event_type: LOGON, MFA, DATASET_ACCESS, ALTUSER_SPECIAL, COMMAND_EXEC, CRYPTO_OP, LOGOFF
- outcome: SUCCESS, FAILURE
- sensitivity: LOW, MEDIUM, HIGH (HIGH maps former CRITICAL; MEDIUM maps former INTERNAL dataset access)
- off_hours: integer 0 or 1; relative to UTC in this simulation, outside 06:00?21:59. This is a calendar flag, not deviation from a per-user schedule.
- origin: NEW_NET, KNOWN_NET, independent of ground-truth class; no literal IPs.
- actor_id: U_ plus 12 lowercase hexadecimal digits of HMAC-SHA256.
- stage_label: BENIGN, INITIAL_ACCESS, CREDENTIAL_ACCESS, DISCOVERY, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, COLLECTION_EXFIL, IMPACT
- scenario_id: background, lookalike, attack, attack_lateral, attack_impact, baseline (demo only)

## Event semantics

DATASET_ACCESS is a resource request. operation distinguishes LIST (directory/catalog enumeration), READ (content retrieval), COPY (synthetic bulk transfer), WRITE (content modification). Listing is NOT the same observation as reading/copying. Repeated listings across resources followed by a privileged change and repeated high-sensitivity copies define the authored attack chain; they are not proof of exfiltration in production.

COMMAND_EXEC means a synthetic command/program invocation. operation: BATCH_JOB, EMERGENCY_FIX, ROUTINE_STATUS. CRYPTO_OP means an abstract cryptographic operation, KEY_ROTATE or BULK_ENCRYPT, NOT an actual ICSF record parser. Legitimate crypto and copying are included. Other operations: AUTHENTICATE (LOGON), CHALLENGE (MFA), GRANT_SPECIAL (ALTUSER_SPECIAL), END_SESSION (LOGOFF). Resource names are shared across classes.

## Files and targets

`data/demo_stream.csv` on this branch is the canonical M2 demo for M5. It has four sessions: two short BENIGN baselines using the same two actors, followed by one attack and one legitimate look-alike. Baselines precede both main sessions; admin origin remains KNOWN_NET. M5 can label the first two sessions as history. Session-level model replay must not combine the two actors; retain actor history across sessions only for baseline features.

train.csv, validation.csv and test.csv have independent actors/sessions and 40% attack sessions to exercise all classes, not to estimate operational prevalence. harder_test.csv is also independent and adds 4x pacing, 2?4 neutral events, optional failed privilege probes and within-DISCOVERY listing-order shuffles. It does NOT reverse causal stages or establish unseen-family generalization. Benign new origins and off-hours exist in every split, not just harder_test.

rare_test.csv has 1,000 sessions with 30 attacks (3%). Report benign false-positive rate as false positives / benign sessions, and precision with the prevalence stated. Rare prevalence changes precision; it does not alone repair model validity. Do not tune on this split.

Each dataset has `_events.csv` without stage_label/scenario_id and `_labels.csv` for targets. Never train on labels, identifiers or scenario_id as features. Sidecar next_stage_label means next DIFFERENT stage; without a later change it remains the current stage. M3 must confirm this convention.

## Privacy and reproducibility

Raw IDs are invented: SYNTH_<split>_<index padded to 5 digits>; demo uses SYNTH_demo_attacker and SYNTH_demo_admin for both baseline and main session. They are HMAC'd before export. There are no real identities, no exported raw-ID mapping and no cross-split actor overlap. Demo intentionally repeats actors within its own split.

THRESHOLD_HMAC_KEY supplies a private secret, or the CLI creates a random 32-byte local data/.hmac_key, ignored by Git. Do not commit/share that key. The prior public demonstration key has been replaced; IDs changed. Reproducibility requires the same seed AND key. Teammates without the key can consume checked-in CSVs or regenerate their own consistent pseudonyms; they should not expect byte-identical IDs. The manifest exposes only a key fingerprint.

## Expected benign behavior and limits

A legitimate NEW_NET admin is still labeled BENIGN. New origin or off-hours alone must not cause containment; if model confidence is uncertain, policy should route to an analyst. These are acceptance goals, not guaranteed model outputs. Benign and attack sequences deliberately overlap. Synthetic stage labels are authored ground truth; accuracy does not establish real enterprise protection. Hold out test/harder/rare data from fitting, calibration and policy tuning.

## Integration warning

Current origin/main predict.py remains a fixed-confidence stub; it groups an entire stream as one prefix, so its caller must group by actor/session. It cannot establish calibrated performance. M3's evidence contract still differs from policy_agent's required fields; M1/M3/M4 must align an adapter. FAILURE/LOW-MEDIUM-HIGH/0-1 replace earlier vocabulary; old trained models need regeneration/retraining, not silent reuse. M3 should consume operation to distinguish discovery from content access.
