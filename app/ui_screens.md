# Threshold console — screen sketches (M5)

Owner: **M5 (UI and demo)**. Status: pre-hackathon design, no code.
This document is the agreed layout for the three demo screens. The build in
`app/console.py` implements exactly these three screens.

Design rules that apply to every screen:

- **Severity and confidence are never merged.** Severity is shown as a labelled
  badge (what is at stake). Confidence is shown as a percentage plus bar (how
  sure the model is). They are visually and structurally distinct.
- The model is never shown taking an action. Every action comes from the policy
  panel and carries a rule id and a policy version.
- Actor ids are pseudonyms in the UI. No raw identity is displayed.
- Eight fixed stage names, colour-coded everywhere:
  BENIGN, INITIAL_ACCESS, CREDENTIAL_ACCESS, DISCOVERY, PRIVILEGE_ESCALATION,
  LATERAL_MOVEMENT, COLLECTION_EXFIL, IMPACT.

---

## Screen 1 — Event timeline (colour-coded by stage)

```
┌───────────────────────────────────────────────────────────────────────┐
│ Threshold        session s1 · pseudonym u-8a3f21 · z/OS zos1          │
│ Stage rail:  (BENIGN)(INITIAL_ACCESS)(CREDENTIAL_ACCESS)(DISCOVERY)   │
│              (PRIVILEGE_ESCALATION)(LATERAL_MOVEMENT)...  ◀ current   │
├───────────────────────────────────────────────────────────────────────┤
│  replay:  [⏵ Play] [‹ Step] [Step ›] [↺ Reset]        stepping 4/8    │
├───────────────────────────────────────────────────────────────────────┤
│  ▸ 09:14:02  [INITIAL_ACCESS]  LOGON      new origin, off-hours       │
│  ▸ 09:15:31  [CREDENTIAL_ACCESS] MFA      failure                     │
│  ▸ 09:16:04  [CREDENTIAL_ACCESS] LOGON    success after 1 failure     │
│  ● 09:18:20  [DISCOVERY]        COMMAND    LISTCAT / dataset sweep    │
│  ▸ 09:19:05  [DISCOVERY]        DATASET    catalogue enumeration      │
│  … future events shown greyed / hidden until stepped …                │
└───────────────────────────────────────────────────────────────────────┘
```

- Events arrive one at a time from `demo_stream.csv` (M2). Each event is a card
  with a stage badge (colour), event type, outcome, resource, timestamp.
- The **stage rail** at the top lists all eight fixed stages; the current stage
  is highlighted.
- Current event has a filled marker (`●`); past events are settled (`▸`).
- Clicking/selecting an event opens the **why** drill-down: which indicators it
  fired and its contribution to the current evidence object.

## Screen 2 — Evidence panel (stage, confidence, next stage)

```
┌───────────────────────────────────────────────────────────────────────┐
│ Evidence  ev-0004 · model threshold-hmm-gru v0.1.0                    │
├───────────────────────────────────────────────────────────────────────┤
│  current stage        DISCOVERY                                       │
│  confidence           0.85   ████████████████░░░░   (calibrated)      │
│                                                                       │
│  predicted next       PRIVILEGE_ESCALATION                            │
│  next confidence      0.81   ████████████████░░░░                     │
│                                                                       │
│  severity   [HIGH]      (rule-based: resource tier + privilege +      │
│                          blast radius if next stage is correct)       │
│  confidence 0.85        (model: indicators + pattern match +          │
│                          deviation from this actor's baseline)        │
│                                                                       │
│  indicators  (NEW_ORIGIN · SMF80) (MFA_FAILURE · SMF80)               │
│              (OFF_HOURS · SMF80)                                      │
│  conformal set  1  → confident      ood: no                          │
├───────────────────────────────────────────────────────────────────────┤
│  Why this read?  ▸ top contributing events + contributions            │
└───────────────────────────────────────────────────────────────────────┘
```

- `evidence.json` fields rendered exactly per the shared contract:
  `evidence_id, actor, session_id, current_stage, stage_confidence,
  next_stage, next_confidence, severity, indicators[], top_events[],
  model_version`.
- Severity badge and confidence bar sit in separate labelled rows.
- Conformal / abstention state shown so the look-alike demo can say
  "abstain, send to analyst".

## Screen 3 — Decision and audit panel (with override)

```
┌───────────────────────────────────────────────────────────────────────┐
│ Policy decision        policy v0.1.0 · hash 3f9c…                     │
├───────────────────────────────────────────────────────────────────────┤
│  action      [ EARLY_WARNING ]                                        │
│  rule fired  P7 — predictive warning                                  │
│  because     predicted PRIVILEGE_ESCALATION · next-conf 0.81 ≥ 0.75   │
│                                                                       │
│  analyst override:  [ Confirm ] [ Reverse ] [ Annotate ]              │
│  (writes an audited OVERRIDE entry — never hides the original)        │
├───────────────────────────────────────────────────────────────────────┤
│  Audit chain (append-only, hash-linked)               [Tamper test]   │
│  #004  EARLY_WARNING   prev 9ab1…  hash c40d…                         │
│  #005  REVOKE_SESSION  prev c40d…  hash 71fe…   (attack, locked)      │
│  #006  ALERT_ANALYST   prev 71fe…  hash e2a9…   (look-alike, no lock) │
│                                                                       │
│  verify result:  ✓ chain intact   |   ✗ broken at #005                │
│                  expected hash …  actual hash …                       │
└───────────────────────────────────────────────────────────────────────┘
```

- The decision card shows the action, rule id, reason, and policy version.
- Clicking a decision reveals the evidence that triggered it (the **why**
  drill-down, screen 2 data).
- Override buttons (Confirm / Reverse / Annotate) let the analyst amend a
  decision; the amendment is appended to the audit chain and the original stays.
- **Tamper test**: edits one audit line in a copy of the log and runs the
  verifier live, printing the exact broken line with expected vs actual hash.

---

## Replay controls (sidebar)

- **Mode** — `Stub` (seed JSON, works with no other member present) or `Live`
  (auto-wires `predict.py` (M3), `data/evidence.json`, `policy/engine.py` (M4),
  `audit/`).
- **Scenario** — Attack (S1) / Look-alike / Both (attack first, then look-alike).
- **Playback** — Play, Step back, Step forward, Reset, speed.

## Done-when (from the build plan)

- Three screens render from stub JSON before M3/M4 land.
- Wired to real `predict.py`, `engine.py`, audit log when present, replaying
  `demo_stream.csv` event by event.
- The attack ends in `REVOKE_SESSION`, the look-alike ends in an alert with no
  lockout.
- Tamper button edits one audit line and the verifier reports the broken line.
- Whole demo runs from one command.
