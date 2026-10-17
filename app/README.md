# Threshold console (M5)

> **Where this goes:** this whole `app/` folder is M5's deliverable and drops in
> at the repo root (`IBM/app/`), replacing the `app/NOTHING` placeholder. It runs
> against the team layout: `data/` (M2), `predict.py` (M3), `policy/`+`audit/`
> (M4). Design docs (`ui_screens.md`, `demo_script_4min.md`) live here too,
> because the repo's `docs/` belongs to M1 & M6.

The demo UI and integration layer. It consumes the three shared contracts and
replays one attack and one legitimate look-alike:

    events.csv    (M2) -> timeline
    evidence.json (M3) -> evidence panel
    audit.jsonl   (M4) -> decision + audit panel

## Run — one command

```bash
pip install streamlit
streamlit run app/console.py
```

That is the whole demo. No other member's code is required to see it work.

## Modes (sidebar)

- **Stub** — reads the fixtures in `app/stubs/`. Works immediately; the policy
  action is computed by the read-only mirror in `app/contracts.py`.
- **Live** — reads the team repo layout:
  `data/demo_stream.csv` (M2), `data/evidence.json` (M3, published artifact),
  `audit/audit.jsonl` (M4). If `data/evidence.json` is absent it derives
  one evidence object per event from M3's `predict.py`
  (`predict_stream`, at the repo root or `model/`). A `policy/engine.py` (M4)
  and `audit/verify.py` (M4) are used automatically when present. Anything
  missing falls back to the stub fixtures and is reported under *Pipeline
  status*.

## Fixtures

Regenerate the stub stream/evidence/audit (deterministic):

```bash
python app/stubs/build_stubs.py
```

| File | Contract | Shape |
|------|----------|-------|
| `app/stubs/demo_stream.csv` | `events.csv` | attack session `s1` + look-alike `s2` |
| `app/stubs/evidence.json` | `evidence.json` | one object per keyframe, + `after_event_id` staging field |
| `app/stubs/audit.jsonl` | `audit.jsonl` | hash-chained, one entry per decision |

Runtime files (`_working_audit.jsonl`) are generated on first run and are
git-ignored.

## LinuxONE / s390x proof

`app/sysinfo.py` reads the real host at runtime (`uname -m`, `/proc/cpuinfo`,
`/etc/os-release`). The console shows the result as a badge in the sidebar, a
full panel in *About & demo*, and a deployment line on *Metrics*. On IBM
LinuxONE Community Cloud it renders `IBM LinuxONE · s390x`; on a dev machine it
says so plainly — so the demo can't accidentally claim mainframe execution.
`demo_script_4min.md` tells the presenter to point at it on camera.

## Screens

1. **Event timeline** — colour-coded by the eight fixed stages; the stage rail
   highlights the current stage.
2. **Evidence panel** — current stage, calibrated confidence, predicted next
   stage, indicators, conformal/abstention state. Severity and confidence are
   kept visually separate.
3. **Decision & audit panel** — action + rule id, analyst override
   (Confirm / Reverse / Annotate), and the hash-linked audit preview. The
   *Audit & integrity* tab adds a live **Tamper** test and a verifier that
   prints the exact broken line with expected vs actual hash.

See `app/ui_screens.md` for the sketches and `app/demo_script_4min.md` for the
presenter script.
