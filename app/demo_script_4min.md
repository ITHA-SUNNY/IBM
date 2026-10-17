# Threshold — 4-minute demo script (M5)

Owner: **M5 (UI and demo)**. Pre-hackathon draft, no code.
Target length: **4:00**. One presenter, one laptop, the Threshold console
(`streamlit run app/console.py`). Numbers marked `«…»` are placeholders and
**must be replaced with measured values** before submission.

Demo data: `demo_stream.csv` = one attack session (S1) and one look-alike
session. The attack is a stolen credential that escalates; the look-alike is an
on-call admin making a legitimate emergency change at 2 a.m.

Action vocabulary shown in the UI:
`LOG_ONLY`, `EARLY_WARNING`, `ALERT_ANALYST`, `REVOKE_SESSION`,
`STAGE_CREDENTIAL_LOCK`.

---

## 0:00–0:30 — Hook

> "Attackers don't break into mainframes any more. They log in with valid,
> stolen credentials. Each step looks harmless on its own — a login from a new
> network, a failed MFA, a privilege change, a sensitive read. The attack only
> exists in the *sequence*.
>
> IBM's tools already monitor and correlate those events. Threshold goes one
> step further: it tells you **where the attack is going**, how sure it is — and
> it isn't allowed to act on its own."

On screen: title card, then the empty timeline and the eight-stage rail.

## 0:30–1:00 — The gap (keep it fair to IBM)

> "Credit where it's due — zSecure Alert, Threat Detection for z/OS and zSecure
> Detection already monitor, baseline, correlate and can even suspend activity.
>
> Public documentation doesn't describe three things we built: which attack
> **stage** a session is in, a **forecast of the next stage** with a calibrated
> confidence, and a hard boundary between **what the model believes** and **what
> the system is allowed to do**."

On screen: the competitive table (covered vs. Threshold), then the architecture
strip: events → sequence → model → evidence → policy → action → audit.

## 1:00–2:30 — Live attack (S1), stepped

Set **Scenario = Attack**, click **Play** (or Step through).

1. `09:14` **new-network logon**, off-hours → stage `INITIAL_ACCESS`,
   confidence `«0.62»`, next `CREDENTIAL_ACCESS`.
2. MFA **failure** → confidence rises.
3. **Successful logon** after the failure → stage `CREDENTIAL_ACCESS`.
4. **Discovery sweep** → stage `DISCOVERY`.

> "Watch the middle card. Current stage: DISCOVERY. But look at the prediction:
> **PRIVILEGE_ESCALATION**, next-stage confidence `«0.81»`. The policy fires an
> **EARLY_WARNING** — a heads-up, not a lockout. This is the part a single
> event score can't do."

5. `ALTUSER … SPECIAL` arrives → severity `CRITICAL`, stage confidence `«0.93»`,
   `«4»` indicators from `«2»` sources.
   Policy: **REVOKE_SESSION** (rule P4) — and `STAGE_CREDENTIAL_LOCK` held for
   analyst approval.
6. **Crown-jewel read** → stage `COLLECTION_EXFIL`.

> "Severity is CRITICAL. Confidence is `«0.93»`. Those are two different
> numbers from two different places — severity from the rules, confidence from
> the calibrated model. The policy engine is the only thing allowed to revoke."

Point at the audit chip: `#005 REVOKE_SESSION`, hash-linked.

## 2:30–3:00 — The look-alike (the safety story)

Set **Scenario = Look-alike** (or continue interleaved).

> "Now the same shape, but legitimate. An on-call admin, 2 a.m., **known**
> network, no failures before success, one privilege change for an emergency
> fix."

On screen: severity `HIGH`, confidence `«0.62»`, conformal set size `«3»` →
policy **abstain → ALERT_ANALYST**.

> "High severity, low confidence. The model isn't sure. And because it isn't
> sure, **nobody is automatically locked out** — it goes to a human. A single
> collapsed risk score cannot do this."

## 3:00–3:30 — Trust: evidence and the audit chain

Open the evidence drill-down.

> "Here's what the model actually emits — an evidence object. Pseudonymized
> actor, no raw identity, no command, no action field. Stage, confidence,
> predicted next stage, the indicators, and the events that caused it. The model
> cannot revoke anything."

Click **Tamper test** / run the verifier.

> "Every decision is written to an append-only, hash-chained log. I'll quietly
> edit one line… and verify."

Show: `✗ chain broken at #00«X»`, expected hash vs actual hash.

> "Tamper-evident. AI predicts, policy decides, everything is on the record."

## 3:30–4:00 — Results and Why IBM Z

Show the metrics tab (filled by M6). **Point at the LinuxONE badge in the
sidebar / Metrics tab** — it reads the live host architecture, so on camera it
shows `IBM LinuxONE · s390x` (plus distro, CPUs, Python). That is the proof this
is running on the mainframe, not a laptop.

- ECE before/after calibration: `«0.xx → 0.xx»`
- stage macro-F1 vs HMM baseline: `«0.xx»`
- next-stage top-1/top-2: `«0.xx / 0.xx»`
- early-warning lead time: median `«≥2 events»` before impact
- false-containment on look-alikes: `«0»` per `«10,000»` benign sessions
- policy ablation: model→action vs model→policy→action
- ONNX Runtime on LinuxONE, throughput `«events/s»`; zDLC/NNPA as the
  production path.

> "Why IBM Z? The sensitive telemetry is already here. Identity is the primary
> attack surface, the workloads are critical, and a wrong lockout is an outage.
> So inference runs where the data lives, and the AI never gets action
> credentials.
>
> **AI predicts. Policy decides. Everything is on the record.**"

---

## Rehearsal checklist

- [ ] Rehearsed twice with M1; timed under 4:00.
- [ ] Console is running on LinuxONE (s390x) — sidebar badge shows it.
- [ ] Every `«placeholder»` replaced with a measured number.
- [ ] Backup screen recording captured.
- [ ] One command starts the demo: `streamlit run app/console.py`.
- [ ] Reset button returns the console to a clean state between runs.
