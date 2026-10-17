# Integration audit ? 17 October 2026

Scope: origin/main at 1c7ba31; M5 remote branch at 6675199; M2 branch; all nine tabs of the shared team Google Doc. PR #1 remains open/unmerged at audit time. New work outside these accessible branches may differ. data/schema.py was absent from all accessible heads; its full enum validation remains pending Vinayak's file/link.

## Fixed in M2 v2.1

- Verify checked-in CSVs on a fresh clone without creating a new key and falsely failing the fingerprint. Structural checks work without a key; byte comparison explicitly skips when private key is unavailable.
- Canonical demo no longer has timestamps in 2037. It runs on 17 October 2026 UTC with two benign baseline histories, an attack and a failure-free legitimate admin session, preserving two actors across baseline/main sessions.
- Add data/features.py: causal, actor/session-scoped rolling features, operation retained, ground truth ignored. Six tests cover causal isolation, failed privilege changes, MFA ordering, window expiry and 0/1 flags.
- Rechecked v2 feedback: class overlap in origin/hours in every split, U_ + 12-hex HMAC IDs, no cross-split actors, explicit operations, 3% rare-attack evaluation.
- Current total: 23,788 events. This is a data count, not a model accuracy result.

## Blocking integration issues ? owners must align before demo

### 1. M5 discards operation and selects a baseline instead of the attack

app/bridge.py on the M5 branch:
- load_events projects rows onto EVENTS_COLUMNS, dropping the added operation field. Add operation to the input/display contract and retain it when invoking M3.
- _scenario_kind labels every non-lookalike scenario as attack. Baseline histories therefore get kind=attack, and pick_sessions selects demo-00001/baseline as the attack. Introduce kind=baseline/background; exclude those from main scenario selection while retaining them for actor history.

Reproduced with the actual canonical CSV: operation preserved=False; attack selector=[('demo-00001','baseline')]. Retest after M5 merges M2 data. Do not change baseline labels to attack to mask this UI issue.

### 2. M3 currently exposes only a fixed-confidence stub on accessible main

predict.py advertises m3-stub-v1.0 and returns hardcoded probabilities. It cannot demonstrate trained accuracy, next-stage forecasting or calibration. It also processes all rows as one prefix unless its caller groups by actor/session. M3 must train/retrain on v2.1, consume operation, exclude target/ID columns, confirm next-stage label convention and provide actual calibration/model artifacts.

### 3. M3 evidence is rejected by M4; UI cannot discover M4

Actual M3 evidence fails EvidenceObject.from_dict with missing fields:
actor_id, timestamp, threat_type, confidence, predicted_next_stage, resource_tier, action, is_privileged_actor.

M3 uses actor/stage_confidence/next_stage/next_confidence while M4 uses the above fields and recomputes severity. An adapter must provide real observed event context and distinguish stage confidence from next-stage confidence. Do not fabricate privileged status from target labels. M4 rule early-warning uses confidence rather than the separate next_confidence promised in the shared contract; agree this explicitly.

M5 probes policy/engine.py and expects a module-level function returning a dict/string. Actual M4 API is policy.policy_agent.PolicyAgent(...).process(evidence), returning a Decision object with to_dict(). M1/M4/M5 must wire that API and map rule_id to rule_fired. The current runner still calls its own model/policy/audit stubs; a successful run_demo.py does not test real integration.

### 4. M4 and M5 audit contracts disagree

Actual M4 audit uses SHA256(canonical_json(entry_without_entry_hash)), with prev_hash inside the entry. M5 expects SHA256(prev_hash + canonical_json(entry_without_entry_hash)). Both are hash chains, but incompatible. A genuine M4 entry passes M4.verify and fails M5's hash candidates (reproduced).

M4 audit has logged_at, nested decision, and evidence; M5/shared schema expects ts, evidence_id, rule_fired and action at top level. Prefer calling M4's actual verifier and explicitly adapting display fields. Do not silently rehash or bypass verification.

### 5. Policy implementation differs from the agreed MVP safety/UX contract

M4's own 52 tests pass, but current package lacks protected-identity and circuit-breaker implementations. Its action set includes LOCK_CREDENTIALS instead of the UI's STAGE_CREDENTIAL_LOCK requiring approval. Its early-warning stage tokens use exfiltration rather than COLLECTION_EXFIL and do not include PRIVILEGE_ESCALATION. Stage tokens need explicit mapping; upper/lowercase conversion alone is insufficient. M4 owner must reconcile these with the shared rules and demonstrate intended behavior.

## Documentation/submission findings

- M2 handoff still contained PR placeholder, old count and public-key wording. Updated that tab to PR #1, current count, private-key behavior, rare split and integration pending status.
- Source research tabs still contain broader/older plans (five scenarios, HMM+GRU+conformal, four-minute script and six judging categories). Treat these as historical design references, not proof of delivered features. Current workshop screenshots say four criteria totaling 40 points and a mandatory video <=3 minutes. The active six-person plan is updated to that video/rubric wording.
- M3 Results tab reports calibration ECE worsening on TEST: current-stage 2.37% -> 3.01%; next-stage 9.48% -> 11.72%. Do not describe this as a test-set calibration improvement. Its 95%-certain/95%-correct and eliminates-false-alarms claims are unsupported by the shown sample results. It also quotes different next-stage validation numbers in table and caption. M3/M1 should replace with measured results from the final model and clearly state synthetic data.
- No LinuxONE run evidence or final M6 results artifacts were present in the accessible repo branches. This is not proof M6 has done no work; ask for deployment commit/screenshots, s390x environment evidence and results to include in the final submission.

## Checks actually run

- data/verify_data.py: all 23,788 events pass structural checks and local same-key byte regeneration.
- Fresh-copy CSV verification without private key: structure PASS, regeneration explicitly SKIPPED; no key created.
- Six causal feature unit tests: PASS.
- M4's 52 existing unit tests, from policy/ directory: PASS.
- M5 input loader/selector tested against canonical CSV: reproduced two compatibility failures.
- M3 evidence passed directly into M4 validator: rejected with required-field mismatch.
- Actual M4 audit entry checked by M5 hash candidates: rejected while M4's own verifier accepts it.

No claim of an end-to-end live model, calibrated operational accuracy or LinuxONE deployment follows from these local checks.
