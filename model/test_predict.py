"""
Test Suite for Threshold M3 Prediction Module

Validates all 7 contract invariants required by M3_TASKS.md:
  1. Every evidence object has all 11 contract fields with correct types.
  2. All confidences are calibrated floats in [0, 1].
  3. All stage labels belong strictly to the 8 fixed names.
  4. The attack session ends with current_stage at or beyond PRIVILEGE_ESCALATION.
  5. The look-alike admin session never reaches CRITICAL severity with confidence above 0.90.
  6. Output is 100% deterministic and reproducible across multiple runs.
  7. Empty and malformed inputs return valid BENIGN evidence without crashing.
"""

import os
import pytest
import pandas as pd
from typing import List, Dict, Any

from predict import predict_session, predict_stream, ALLOWED_STAGES, ALLOWED_SEVERITIES

# Path to the demo stream produced by data/make_demo_stream.py (relative to the repo)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_CSV_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "data", "out", "demo_stream.csv")

ATTACK_SESSION = "sess-demo-attack"
LOOKALIKE_SESSION = "sess-demo-lookalike"


@pytest.fixture(scope="module")
def sample_events_df() -> pd.DataFrame:
    """Fixture providing the demo stream events DataFrame."""
    assert os.path.exists(SAMPLE_CSV_PATH), (
        f"demo_stream.csv missing: {SAMPLE_CSV_PATH} (run python data/make_demo_stream.py)"
    )
    df = pd.read_csv(SAMPLE_CSV_PATH)
    assert not df.empty, "demo_stream.csv is empty"
    return df


@pytest.fixture(scope="module")
def stream_evidence_records(sample_events_df) -> List[Dict[str, Any]]:
    """Fixture providing stream evidence evaluated over sample_events.csv."""
    records = predict_stream(sample_events_df)
    return records


def test_invariant_1_all_11_fields_and_types(stream_evidence_records):
    """(1) Every evidence from sample_events.csv has all 11 fields with correct types."""
    assert len(stream_evidence_records) > 0, "No evidence records returned"

    expected_fields = {
        "evidence_id": str,
        "actor": str,
        "session_id": str,
        "current_stage": str,
        "stage_confidence": float,
        "next_stage": str,
        "next_confidence": float,
        "severity": str,
        "indicators": list,
        "top_events": list,
        "model_version": str,
    }

    for idx, ev in enumerate(stream_evidence_records):
        # Exact 11 fields presence
        for field, exp_type in expected_fields.items():
            assert field in ev, f"Record {idx} missing field: {field}"
            val = ev[field]
            assert isinstance(val, exp_type), (
                f"Record {idx} field '{field}' expected type {exp_type.__name__}, got {type(val).__name__}"
            )

        # List element validations
        for ind in ev["indicators"]:
            assert isinstance(ind, str), f"Indicator '{ind}' is not string in record {idx}"
        for eid in ev["top_events"]:
            assert isinstance(eid, str), f"top_event '{eid}' is not string in record {idx}"
        assert len(ev["top_events"]) <= 5, f"top_events exceeds max 5 items in record {idx}"


def test_invariant_2_confidences_in_range(stream_evidence_records):
    """(2) All confidences are calibrated numbers in [0, 1]."""
    for idx, ev in enumerate(stream_evidence_records):
        curr_conf = ev["stage_confidence"]
        next_conf = ev["next_confidence"]

        assert 0.0 <= curr_conf <= 1.0, f"Record {idx}: stage_confidence {curr_conf} out of [0, 1]"
        assert 0.0 <= next_conf <= 1.0, f"Record {idx}: next_confidence {next_conf} out of [0, 1]"
        assert not pd.isna(curr_conf), f"Record {idx}: stage_confidence is NaN"
        assert not pd.isna(next_conf), f"Record {idx}: next_confidence is NaN"


def test_invariant_3_stages_are_allowed_names(stream_evidence_records):
    """(3) Stages are among the 8 allowed names."""
    allowed_set = set(ALLOWED_STAGES)
    assert len(allowed_set) == 8, f"Expected exactly 8 allowed stages, found {len(allowed_set)}"

    for idx, ev in enumerate(stream_evidence_records):
        c_stage = ev["current_stage"]
        n_stage = ev["next_stage"]
        assert c_stage in allowed_set, f"Record {idx}: invalid current_stage '{c_stage}'"
        assert n_stage in allowed_set, f"Record {idx}: invalid next_stage '{n_stage}'"
        assert ev["severity"] in ALLOWED_SEVERITIES, f"Record {idx}: invalid severity '{ev['severity']}'"


def test_invariant_4_attack_session_escalation(stream_evidence_records):
    """(4) The attack session ends with current_stage at or beyond PRIVILEGE_ESCALATION."""
    escalation_or_beyond = {"PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT", "COLLECTION_EXFIL", "IMPACT"}
    
    atk_records = [ev for ev in stream_evidence_records if ev["session_id"] == ATTACK_SESSION]
    assert len(atk_records) > 0, f"No attack session records found for {ATTACK_SESSION}"

    final_record = atk_records[-1]
    final_stage = final_record["current_stage"]
    assert final_stage in escalation_or_beyond, (
        f"Attack session ended at '{final_stage}', expected at or beyond PRIVILEGE_ESCALATION"
    )
    assert final_record["severity"] in ["HIGH", "CRITICAL"], (
        f"Attack session ended with unexpected severity '{final_record['severity']}'"
    )


def test_invariant_5_lookalike_session_no_false_critical(stream_evidence_records):
    """(5) The look-alike session never reaches CRITICAL severity with confidence above 0.90."""
    adm_records = [ev for ev in stream_evidence_records if ev["session_id"] == LOOKALIKE_SESSION]
    assert len(adm_records) > 0, f"No look-alike records found for {LOOKALIKE_SESSION}"

    for idx, ev in enumerate(adm_records):
        if ev["severity"] == "CRITICAL":
            assert ev["stage_confidence"] <= 0.90, (
                f"Look-alike session event {ev['evidence_id']} reached CRITICAL with confidence "
                f"{ev['stage_confidence']} > 0.90 (False Positive Violation)"
            )


def test_one_evidence_per_demo_event(sample_events_df, stream_evidence_records):
    """predict_stream emits exactly one valid evidence object per event of demo_stream.csv."""
    assert len(stream_evidence_records) == len(sample_events_df)
    demo_sessions = set(sample_events_df["session_id"])
    assert {ev["session_id"] for ev in stream_evidence_records} == demo_sessions


def test_invariant_6_output_identical_across_two_runs(sample_events_df):
    """(6) Output is identical across two runs (deterministic)."""
    run_1 = predict_stream(sample_events_df)
    run_2 = predict_stream(sample_events_df)

    assert len(run_1) == len(run_2), "Run lengths mismatch"
    assert len(run_1) > 0

    for idx, (e1, e2) in enumerate(zip(run_1, run_2)):
        assert e1 == e2, f"Mismatch at record {idx}:\n  Run 1: {e1}\n  Run 2: {e2}"


def test_invariant_7_empty_input_graceful():
    """(7) Empty input returns valid BENIGN evidence, no exception."""
    # Test None
    ev_none = predict_session(None)
    assert ev_none["current_stage"] == "BENIGN"
    assert ev_none["severity"] == "LOW"
    assert len(ev_none) == 11

    # Test empty DataFrame
    ev_empty_df = predict_session(pd.DataFrame())
    assert ev_empty_df["current_stage"] == "BENIGN"
    assert ev_empty_df["severity"] == "LOW"
    assert len(ev_empty_df) == 11

    # Test empty list
    ev_empty_list = predict_session([])
    assert ev_empty_list["current_stage"] == "BENIGN"
    assert len(ev_empty_list) == 11

    # Test stream on empty input
    stream_none = predict_stream(None)
    assert len(stream_none) == 1
    assert stream_none[0]["current_stage"] == "BENIGN"

    stream_empty_df = predict_stream(pd.DataFrame())
    assert len(stream_empty_df) == 1
    assert stream_empty_df[0]["current_stage"] == "BENIGN"


def test_lookalike_altuser_on_high_resource_no_sensitive_access():
    """
    Step 1 Fix Test:
    A look-alike session performing ALTUSER_SPECIAL on a HIGH-sensitivity resource
    without any DATASET_READ or DATASET_COPY must NOT receive the 'sensitive_access' indicator.
    """
    events = [
        {
            "event_id": "evt-test-01",
            "session_id": "sess-test-altuser-high",
            "actor_id": "U_ADMIN01",
            "timestamp": "2026-03-30T10:00:00Z",
            "event_type": "LOGON",
            "resource": "CICS",
            "sensitivity": "LOW",
            "outcome": "SUCCESS",
            "origin": "NET_KNOWN_1",
            "off_hours": 0
        },
        {
            "event_id": "evt-test-02",
            "session_id": "sess-test-altuser-high",
            "actor_id": "U_ADMIN01",
            "timestamp": "2026-03-30T10:01:00Z",
            "event_type": "ALTUSER_SPECIAL",
            "resource": "RACF_AUDITOR_ATTR",
            "sensitivity": "HIGH",
            "outcome": "SUCCESS",
            "origin": "NET_KNOWN_1",
            "off_hours": 0
        }
    ]
    ev = predict_session(pd.DataFrame(events))
    assert "sensitive_access" not in ev["indicators"], (
        f"Expected 'sensitive_access' NOT in indicators, but found: {ev['indicators']}"
    )
    assert ev["severity"] != "CRITICAL", (
        f"Expected severity != CRITICAL for ALTUSER without sensitive read, got {ev['severity']}"
    )

