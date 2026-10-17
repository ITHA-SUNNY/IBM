"""Threshold — console presentation helpers (M5).

Pure display helpers used by app/console.py. Everything here is native
Streamlit (badges, markdown colour directives, metrics, progress, expanders) —
no custom CSS, per the project's UI policy. Severity and confidence are always
rendered as separate elements so they are never visually merged.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from app.contracts import (
    ACTION_COLOR,
    SEVERITY_COLOR,
    STAGE_COLOR,
    STAGE_FILLED,
    STAGES,
    normalize_indicators,
)


def stage_md(stage: str, filled: bool | None = None) -> str:
    color = STAGE_COLOR.get(stage, "gray")
    use_fill = (stage in STAGE_FILLED) if filled is None else filled
    token = "background" if use_fill else "badge"
    return f":{color}-{token}[{stage or '—'}]"


def action_md(action: str) -> str:
    color = ACTION_COLOR.get(action, "gray")
    return f":{color}-background[{(action or '—')}]"


def severity_md(severity: str) -> str:
    color = SEVERITY_COLOR.get((severity or "").upper(), "gray")
    return f":{color}-background[{(severity or '—').upper()}]"


def indicator_md(ind: dict[str, Any]) -> str:
    iid = ind.get("id", "?")
    src = ind.get("source")
    return f":violet-badge[{iid} · {src}]" if src else f":violet-badge[{iid}]"


def short_hash(value: str | None, n: int = 10) -> str:
    if not value:
        return "—"
    return value[:n] + "…"


def render_stage_rail(current_stage: str) -> None:
    parts = []
    for stage in STAGES:
        if stage == current_stage:
            parts.append(f"**{stage_md(stage, filled=True)}**")
        else:
            parts.append(stage_md(stage))
    st.markdown(" ▸ ".join(parts))


def render_timeline(session, upto: int, show_all: bool) -> None:
    events = session.events
    last = min(upto, len(events) - 1)
    shown = events if show_all else events[: last + 1]
    for i, e in enumerate(shown):
        is_current = (i == last) and not show_all
        marker = ":material/radio_button_checked:" if is_current else ":material/done:"
        with st.container(border=is_current):
            with st.container(horizontal=True, vertical_alignment="center"):
                st.markdown(f"{marker} {stage_md(e.get('stage_label', ''))}")
                res = e.get("resource") or "—"
                st.markdown(f"`{e.get('event_type','?')}` — {res}")
                st.caption(
                    f"{e.get('timestamp','')[11:19]} · {e.get('outcome','')} · "
                    f"{e.get('origin','')}"
                    + (" · off-hours" if e.get("off_hours") else "")
                )
    remaining = len(events) - (last + 1)
    if remaining > 0 and not show_all:
        st.caption(f"… {remaining} event(s) not yet revealed — step to continue.")


def render_evidence(evidence: dict[str, Any] | None) -> None:
    with st.container(border=True):
        st.markdown("**Evidence**")
        if not evidence:
            st.caption("No evidence object for this position yet.")
            return
        st.caption(
            f"{evidence.get('evidence_id','?')} · "
            f"{evidence.get('model_version','?')} · actor "
            f"{evidence.get('actor','?')}"
        )

        cur = evidence.get("current_stage", "")
        conf = float(evidence.get("stage_confidence") or 0.0)
        st.markdown(f"current stage — {stage_md(cur, filled=True)}")
        st.progress(min(max(conf, 0.0), 1.0), text=f"confidence {conf:.2f} (calibrated)")

        nxt = evidence.get("next_stage", "")
        nconf = float(evidence.get("next_confidence") or 0.0)
        st.markdown(f"predicted next — {stage_md(nxt)}")
        st.progress(min(max(nconf, 0.0), 1.0), text=f"next-stage confidence {nconf:.2f}")

        sev_col, conf_col = st.columns(2)
        with sev_col:
            st.markdown("**Severity** (rules)")
            st.markdown(severity_md(evidence.get('severity','')))
        with conf_col:
            st.markdown("**Confidence** (model)")
            st.markdown(f"#### {conf:.2f}")
        st.caption("Severity = what is at stake. Confidence = how sure the model is. "
                   "They are never collapsed into one number.")

        indicators = normalize_indicators(evidence.get("indicators"))
        if indicators:
            st.markdown("**Indicators**")
            st.markdown(" ".join(indicator_md(i) for i in indicators))

        conformal = evidence.get("conformal_set")
        bits = []
        if isinstance(conformal, (list, tuple)):
            bits.append(f"conformal set: {len(conformal)} "
                        f"({', '.join(conformal) if conformal else '—'})")
        if evidence.get("ood_flag"):
            bits.append("out-of-distribution: yes")
        if bits:
            st.caption(" · ".join(bits))

        with st.expander("Why this read?", icon=":material/search:"):
            tops = evidence.get("top_events") or []
            if not tops:
                st.caption("No contributing-event breakdown available.")
            for t in tops:
                if isinstance(t, str):
                    st.markdown(f"- {t}")
                else:
                    st.markdown(
                        f"- `{t.get('event_id','?')}` — {t.get('reason','')} "
                        f"_(contribution {t.get('contribution','?')})_"
                    )


def render_decision(decision: dict[str, str], policy_version: str,
                    evidence: dict[str, Any] | None) -> None:
    with st.container(border=True):
        st.markdown("**Policy decision**")
        st.caption(f"policy {policy_version} · source: {decision.get('source','—')}")
        st.markdown(action_md(decision.get("action", "")))
        st.markdown(
            f"rule fired — `{decision.get('rule_fired','—') or '—'}`"
        )
        if decision.get("reason"):
            st.caption(decision["reason"])


def render_audit_entries(entries: list[dict[str, Any]], limit: int | None = None) -> None:
    shown = entries[-limit:] if limit else entries
    if not shown:
        st.caption("No audit entries revealed yet.")
        return
    for e in shown:
        st.markdown(
            f"`#{e.get('seq',0):03d}` {action_md(e.get('action',''))} "
            f"— rule `{e.get('rule_fired','—')}` · "
            f"prev `{short_hash(e.get('prev_hash'),8)}` → "
            f"hash `{short_hash(e.get('entry_hash'),8)}`"
        )


def platform_md(info) -> str:
    """Badge for the host the console is running on (LinuxONE proof)."""
    if info.on_linuxone:
        return ":green-badge[IBM LinuxONE · s390x]"
    return f":gray-badge[{info.system} · {info.machine}]"


def render_platform_badge(info) -> None:
    """Compact host badge, used in the sidebar."""
    st.markdown(platform_md(info))
    if info.on_linuxone:
        st.caption("Running on IBM LinuxONE (s390x).")
    else:
        st.caption("Dev host — deploy on LinuxONE (s390x) for the live demo.")


def render_environment(info) -> None:
    """Environment panel, used in the About tab."""
    st.markdown("**Runtime environment** — read live from this host")
    if info.on_linuxone:
        st.success("This console is running on IBM LinuxONE / IBM Z "
                   "(architecture s390x).", icon=":material/memory:")
    else:
        st.warning("This console is running on a non-s390x host "
                   f"({info.system} {info.machine}). For the submission demo it "
                   "must run on IBM LinuxONE Community Cloud (s390x).",
                   icon=":material/developer_board:")
    st.dataframe(
        [
            {"field": "architecture (uname -m)", "value": info.machine},
            {"field": "operating system", "value": f"{info.system} {info.release}"},
            {"field": "distribution", "value": info.distro or "—"},
            {"field": "hostname", "value": info.node},
            {"field": "CPUs", "value": str(info.cpu_count)},
            {"field": "Python", "value": info.python_version},
            {"field": "on LinuxONE / s390x",
             "value": "yes" if info.on_linuxone else "no"},
        ],
        hide_index=True,
        alt="Runtime environment",
    )


def render_metrics() -> None:
    st.caption("Numbers below are filled in by M6 during the hackathon. "
               "Placeholders until then.")
    with st.container(horizontal=True):
        st.metric("Stage macro-F1", "«—»", help="vs HMM baseline", border=True)
        st.metric("Next-stage top-1", "«—»", border=True)
        st.metric("ECE after calib.", "«—»", border=True)
        st.metric("Early-warning lead", "«—»", help="median events before impact",
                  border=True)
        st.metric("False containments", "«—»", help="per 10k benign sessions",
                  border=True)

    st.markdown("**Evaluation table**")
    rows = [
        {"metric": "Stage macro-F1 (GRU vs HMM)",
         "target": "beat HMM baseline", "value": "«pending M6»"},
        {"metric": "Next-stage top-1 / top-2 accuracy",
         "target": "beat HMM baseline", "value": "«pending M6»"},
        {"metric": "ECE before → after temperature scaling",
         "target": "decreases", "value": "«pending M6»"},
        {"metric": "Conformal coverage @ alpha=0.1",
         "target": "≈ 0.90", "value": "«pending M6»"},
        {"metric": "Early-warning lead time",
         "target": "median ≥ 2 events", "value": "«pending M6»"},
        {"metric": "Containment precision",
         "target": "≥ 0.95", "value": "«pending M6»"},
        {"metric": "False-containment rate (look-alikes)",
         "target": "near zero", "value": "«pending M6»"},
        {"metric": "LinuxONE throughput",
         "target": "events / second", "value": "«pending M6»"},
        {"metric": "ONNX / zDLC path",
         "target": "accelerator where available", "value": "«pending M6»"},
    ]
    st.dataframe(rows, hide_index=True, alt="Evaluation results table")

    st.markdown("**Policy ablation — model → action vs model → policy → action**")
    st.dataframe(
        [
            {"configuration": "Model → Action (no policy)",
             "false lockouts": "«pending M6»", "notes": "baseline"},
            {"configuration": "Model → Policy → Action (Threshold)",
             "false lockouts": "«pending M6»", "notes": "gated by P0–P9"},
        ],
        hide_index=True,
        alt="Policy ablation table",
    )
