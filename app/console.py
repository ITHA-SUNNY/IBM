"""Threshold — demo console (M5).

    streamlit run app/console.py

One command, end to end. It replays demo_stream.csv event by event and shows
the three agreed screens: a stage-coloured event timeline, an evidence panel
(severity and confidence kept apart), and a decision + audit panel with an
analyst override and a live tamper test.

Modes
    Stub  - the fixtures in app/stubs/ (works before M3/M4 land)
    Live  - prefers data/demo_stream.csv, model/predict.py, policy/engine.py,
            audit/verify.py; falls back to stubs for anything missing and says
            so in the sidebar.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# `streamlit run app/console.py` puts app/ on sys.path, not the repo root.
# Add the repo root so `import app.*` resolves with no env setup.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import streamlit as st

from app import ui
from app.bridge import (
    ConsoleData,
    Session,
    compute_view,
    decide,
    load_console_data,
    local_index,
    make_playlist,
    pick_sessions,
    policy_version,
)
from app.contracts import POLICY_VERSION_FALLBACK
from app.sysinfo import detect_platform

st.set_page_config(
    page_title="Threshold console",
    page_icon=":material/security:",
    layout="wide",
)

SCENARIOS = {
    "Attack (S1)": "attack",
    "Look-alike": "lookalike",
    "Both": "both",
}
TAMPER_FIELDS = ["action", "rule_fired", "ts", "evidence_id"]

PLATFORM = detect_platform()


@st.cache_resource(show_spinner="Loading contract fixtures…")
def get_data(mode: str) -> ConsoleData:
    return load_console_data(mode)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Sidebar controls
# ---------------------------------------------------------------------------


with st.sidebar:
    st.markdown("### Threshold")
    st.caption("Predictive, policy-gated threat progression · console v0.1")
    ui.render_platform_badge(PLATFORM)
    mode_label = st.segmented_control(
        "Mode", ["Stub", "Live"], default="Stub", key="mode",
        help="Live auto-wires the other members' outputs when they exist.",
    )
    scenario_label = st.segmented_control(
        "Scenario", list(SCENARIOS), default="Attack (S1)", key="scenario",
    )
    st.space("small")
    with st.container(horizontal=True):
        play_btn = st.button("Play", type="primary", icon=":material/play_arrow:")
        back_btn = st.button("Back", icon=":material/chevron_left:")
        fwd_btn = st.button("Forward", icon=":material/chevron_right:")
        reset_btn = st.button("Reset", icon=":material/restart_alt:")
    delay = st.slider("Step delay (s)", 0.1, 2.0, 0.6, 0.1)
    show_all = st.toggle("Peek ahead (show all events)", value=False)
    show_json = st.toggle("Show raw JSON", value=False)

    st.space("small")
    st.caption("Streams: events.csv (M2) · evidence.json (M3) · audit.jsonl (M4)")

mode = "live" if mode_label == "Live" else "stub"
scenario = SCENARIOS[scenario_label]
data = get_data(mode)

if mode == "live" and data.live:
    with st.sidebar.expander("Pipeline status", icon=":material/cable:"):
        for name, status in data.live.status():
            icon = ":material/check_circle:" if status == "connected" else ":material/radio_button_unchecked:"
            st.markdown(f"{icon} **{name}** — {status}")
        for note in data.live.notes:
            st.caption(note)

playlist = make_playlist(data, scenario)
total = len(playlist)

# ---------------------------------------------------------------------------
# Replay state machine
# ---------------------------------------------------------------------------

if total == 0:
    st.error("No events loaded. Check the stream path in the sidebar.")
    st.stop()

st.session_state.setdefault("step", 0)
if st.session_state.get("_scenario") != scenario:
    st.session_state["_scenario"] = scenario
    st.session_state["step"] = 0

if reset_btn:
    data.audit_store.reset()
    st.session_state["step"] = 0
    st.session_state.pop("last_override", None)
    st.session_state.pop("verify_result", None)
    st.session_state.pop("tamper_result", None)
if fwd_btn:
    st.session_state["step"] = min(st.session_state["step"] + 1, total - 1)
if back_btn:
    st.session_state["step"] = max(st.session_state["step"] - 1, 0)
st.session_state["step"] = max(0, min(st.session_state["step"], total - 1))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def append_override(data: ConsoleData, evidence_id: str, action: str) -> None:
    entries = data.audit_store.entries()
    pv = entries[-1]["policy_version"] if entries else POLICY_VERSION_FALLBACK
    data.audit_store.append(
        {
            "ts": now_iso(),
            "evidence_id": evidence_id,
            "rule_fired": "ANALYST_OVERRIDE",
            "action": action,
            "policy_version": pv,
        }
    )
    st.session_state["last_override"] = f"{action.replace('OVERRIDE_', '').title()} recorded for {evidence_id}."


def render_override_controls(data: ConsoleData, evidence: dict | None) -> None:
    if not evidence:
        return
    ev_id = evidence.get("evidence_id", "?")
    st.markdown("**Analyst override** — audited, original kept")
    with st.container(horizontal=True):
        if st.button("Confirm", key=f"ovr_c_{ev_id}", icon=":material/check:"):
            append_override(data, ev_id, "OVERRIDE_CONFIRM")
            st.rerun()
        if st.button("Reverse", key=f"ovr_r_{ev_id}", icon=":material/undo:"):
            append_override(data, ev_id, "OVERRIDE_REVERSE")
            st.rerun()
        if st.button("Annotate", key=f"ovr_a_{ev_id}", icon=":material/edit_note:"):
            append_override(data, ev_id, "OVERRIDE_ANNOTATE")
            st.rerun()
    if st.session_state.get("last_override"):
        st.caption(st.session_state["last_override"])


def render_audit_preview(data: ConsoleData, revealed: set[str]) -> None:
    entries = [
        e for e in data.audit_store.entries()
        if e.get("evidence_id") in revealed
        or str(e.get("action", "")).startswith("OVERRIDE")
    ]
    with st.container(border=True):
        st.markdown("**Audit chain** — append-only, hash-linked")
        ui.render_audit_entries(entries, limit=4)
        st.caption(f"{len(entries)} entr(y/ies) revealed · full view in "
                   "'Audit & integrity'")


def draw(data: ConsoleData, step: int, slots: dict) -> None:
    for slot in slots.values():
        slot.empty()

    session, event, li, evidence, decision, revealed = compute_view(data, playlist, step)

    with slots["header"].container():
        kind = {"attack": ":red-badge[attack]", "lookalike": ":blue-badge[look-alike]"}.get(
            session.kind, ":gray-badge[unknown]"
        )
        with st.container(horizontal=True, vertical_alignment="center"):
            st.markdown(f"#### Session `{session.session_id}` {kind}")
            st.caption(f"actor `{session.actor}` · system `{session.system_id}` · "
                       f"scenario `{session.scenario_id}` · step {step + 1}/{total}")

    with slots["rail"].container():
        ui.render_stage_rail(evidence.get("current_stage", "BENIGN") if evidence else "BENIGN")

    with slots["timeline"].container():
        with st.container(border=True, height=520):
            st.markdown("**Event timeline** — colour-coded by stage")
            ui.render_timeline(session, li, show_all)
            if show_all:
                st.caption("(peek ahead is on — future events are visible)")

    with slots["evidence"].container():
        ui.render_evidence(evidence)

    with slots["decision"].container():
        ui.render_decision(decision, policy_version(data), evidence)
        render_override_controls(data, evidence)

    with slots["audit"].container():
        render_audit_preview(data, revealed)

    with slots["json"].container():
        if show_json and evidence:
            with st.expander("Raw evidence.json (this keyframe)", icon=":material/data_object:"):
                st.json(evidence)


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab_live, tab_audit, tab_metrics, tab_about = st.tabs(
    ["Live console", "Audit & integrity", "Metrics", "About & demo"]
)

with tab_live:
    slots = {
        "header": st.empty(),
        "rail": st.empty(),
    }
    left_col, right_col = st.columns([1.6, 1.0], gap="medium")
    with left_col:
        slots["timeline"] = st.empty()
    with right_col:
        slots["evidence"] = st.empty()
        st.space("small")
        slots["decision"] = st.empty()
    st.space("small")
    slots["audit"] = st.empty()
    slots["json"] = st.empty()

    if play_btn:
        for i in range(st.session_state["step"], total):
            st.session_state["step"] = i
            draw(data, i, slots)
            if i < total - 1:
                time.sleep(delay)
        st.session_state["step"] = total - 1
    else:
        draw(data, st.session_state["step"], slots)

with tab_audit:
    st.markdown("#### Audit log — tamper-evident chain")
    st.caption("entry_hash = SHA-256(prev_hash + canonical_json(entry)). "
               "Editing any field breaks the link.")

    audit_entries = data.audit_store.entries()
    preview = []
    for e in audit_entries:
        preview.append(
            {
                "seq": e.get("seq"),
                "ts": e.get("ts"),
                "evidence_id": e.get("evidence_id"),
                "rule_fired": e.get("rule_fired"),
                "action": e.get("action"),
                "policy_version": e.get("policy_version"),
                "prev_hash": ui.short_hash(e.get("prev_hash"), 12),
                "entry_hash": ui.short_hash(e.get("entry_hash"), 12),
            }
        )
    st.dataframe(preview, hide_index=True, alt="Audit log entries")

    with st.container(horizontal=True):
        verify_btn = st.button("Verify chain", icon=":material/verified:", key="verify_chain")
        reset_log_btn = st.button("Reset log", icon=":material/restart_alt:", key="reset_log")
    if verify_btn:
        st.session_state["verify_result"] = data.audit_store.verify()
        st.session_state.pop("tamper_result", None)
    if reset_log_btn:
        data.audit_store.reset()
        st.session_state.pop("verify_result", None)
        st.session_state.pop("tamper_result", None)

    if "verify_result" in st.session_state:
        r = st.session_state["verify_result"]
        if r.ok:
            st.success(f"Chain intact — {len(audit_entries)} entries verified "
                       f"by {r.verifier}.")
        else:
            st.error(f"Chain broken at entry #{r.broken_seq} (line {r.line_no}).")
            st.code(f"expected: {r.expected}\nactual:   {r.actual}")

    st.space("small")
    st.markdown("#### Tamper test")
    st.caption("Edit one line, then verify. Reset the log to restore it.")
    seqs = [e.get("seq") for e in audit_entries] or [1]
    t1, t2, t3 = st.columns([1, 1, 1.4])
    tamper_seq = t1.selectbox("Entry #", seqs, index=len(seqs) - 1)
    tamper_field = t2.selectbox("Field to edit", TAMPER_FIELDS)
    tamper_value = t3.text_input("New value", value="LOG_ONLY")

    if st.button("Tamper and verify", type="primary", icon=":material/warning:",
                 key="do_tamper"):
        line_no = data.audit_store.tamper(int(tamper_seq), tamper_field, tamper_value)
        result = data.audit_store.verify()
        st.session_state["tamper_result"] = (line_no, tamper_field, tamper_value, result)
        st.session_state.pop("verify_result", None)

    if "tamper_result" in st.session_state:
        line_no, field, value, result = st.session_state["tamper_result"]
        st.error(f"Edited line {line_no}: {field} → {value!r}.")
        if result.ok:
            st.warning("Verifier did not detect the edit (check canonicalisation).")
        else:
            st.markdown(f"**AUDIT CHAIN BROKEN — entry #{result.broken_seq} "
                        f"(line {result.line_no})**")
            st.code(f"expected hash: {result.expected}\nactual hash:   {result.actual}")

with tab_metrics:
    st.markdown("**Deployment** — where this demo actually runs")
    with st.container(horizontal=True, vertical_alignment="center"):
        st.markdown(ui.platform_md(PLATFORM))
        st.caption("IBM LinuxONE Community Cloud · s390x" if PLATFORM.on_linuxone
                   else "deploy on LinuxONE (s390x) for the live demo")
    st.caption("M6 fills the LinuxONE throughput/package-log numbers below.")
    ui.render_metrics()

with tab_about:
    st.markdown(
        """
        ### Threshold — predictive, policy-gated threat progression

        A reasoning layer that sits on top of IBM Z security monitoring. It
        groups RACF/SMF-shaped events by session, infers the **current attack
        stage** and the **next likely stage** with calibrated confidence, and
        emits an explainable **evidence object**. A deterministic policy engine —
        never the model — decides whether to warn, alert or revoke. Every
        decision is written to a tamper-evident, hash-chained audit log.

        **AI predicts. Policy decides. Everything is on the record.**
        """
    )
    st.markdown("**Three screens**")
    st.markdown(
        "- Event timeline — colour-coded by the eight fixed attack stages.\n"
        "- Evidence panel — current stage, confidence, predicted next stage; "
        "severity and confidence kept separate.\n"
        "- Decision & audit panel — action + rule, analyst override, live tamper test."
    )
    st.markdown("**Run**")
    st.code("streamlit run app/console.py")
    st.markdown("**Contract sources (this run)**")
    st.dataframe(
        [{"contract": k, "path": v} for k, v in data.sources.items()],
        hide_index=True,
        alt="Contract source files",
    )
    st.space("small")
    ui.render_environment(PLATFORM)
    st.caption("Full demo script: app/demo_script_4min.md · "
               "screen sketches: app/ui_screens.md")
