"""
Stub predict.py for M3 (Threshold)
Exposes predict_session and predict_stream to unblock M4, M5, and M6.
"""

import os
import sys
import json
import argparse
from typing import Dict, List, Any, Union

try:
    import pandas as pd
except ImportError:
    pd = None


DEFAULT_BENIGN_EVIDENCE: Dict[str, Any] = {
    "evidence_id": "ev-stub-benign-001",
    "actor": "U_UNKNOWN",
    "session_id": "sess-default",
    "current_stage": "BENIGN",
    "stage_confidence": 0.95,
    "next_stage": "BENIGN",
    "next_confidence": 0.90,
    "severity": "LOW",
    "indicators": [],
    "top_events": [],
    "model_version": "m3-stub-v1.0"
}


def _to_dataframe(events_df: Any):
    """Ensure events input is a DataFrame-like structure."""
    if events_df is None:
        return None
    if pd is not None and isinstance(events_df, pd.DataFrame):
        return events_df
    if isinstance(events_df, list):
        if pd is not None:
            return pd.DataFrame(events_df)
        return events_df
    return events_df


def predict_session(events_df: Any) -> Dict[str, Any]:
    """
    Predict attack stage and calibrated confidence for a single session prefix.
    
    Args:
        events_df: pandas DataFrame or list of dicts representing events seen so far in a session.
        
    Returns:
        dict: Valid evidence object with all 11 required contract fields.
    """
    df = _to_dataframe(events_df)
    
    if df is None or (hasattr(df, "empty") and df.empty) or (isinstance(df, list) and len(df) == 0):
        return dict(DEFAULT_BENIGN_EVIDENCE)
    
    # Extract metadata from the latest event in the prefix
    if hasattr(df, "iloc"):
        last_row = df.iloc[-1]
        session_id = str(last_row.get("session_id", "sess-stub-001"))
        actor = str(last_row.get("actor_id", "U_stub_actor"))
        last_event_id = str(last_row.get("event_id", "evt-stub-001"))
        event_count = len(df)
        
        # Collect top_events from event_ids in the window (up to 5, most recent first)
        top_events = [str(eid) for eid in df.get("event_id", pd.Series([last_event_id])).tail(5).tolist()[::-1]]
        
        # Check for indicators in the prefix
        event_types = df["event_type"].tolist() if "event_type" in df else []
        outcomes = df["outcome"].tolist() if "outcome" in df else []
        sensitivities = df["sensitivity"].tolist() if "sensitivity" in df else []
    else:
        # Fallback if list of dicts without pandas
        last_row = df[-1]
        session_id = str(last_row.get("session_id", "sess-stub-001"))
        actor = str(last_row.get("actor_id", "U_stub_actor"))
        last_event_id = str(last_row.get("event_id", "evt-stub-001"))
        event_count = len(df)
        top_events = [str(r.get("event_id", f"evt-{i}")) for i, r in enumerate(df[-5:])][::-1]
        event_types = [r.get("event_type", "") for r in df]
        outcomes = [r.get("outcome", "") for r in df]
        sensitivities = [r.get("sensitivity", "") for r in df]

    # Generate realistic values based on event count & types
    indicators = []
    if any("FAIL" in str(o).upper() for o in outcomes):
        indicators.append("mfa_failure_then_success")
    if any("ALTUSER" in str(et).upper() or "SPECIAL" in str(et).upper() for et in event_types):
        indicators.append("privilege_change")
    if any(str(s).upper() in ["HIGH", "CRITICAL"] for s in sensitivities):
        indicators.append("sensitive_access")
    if not indicators and event_count > 1:
        indicators.append("new_origin")

    # If privilege change or multiple risky indicators detected, flag PRIVILEGE_ESCALATION
    if "privilege_change" in indicators or "sensitive_access" in indicators:
        current_stage = "PRIVILEGE_ESCALATION"
        stage_confidence = 0.94
        next_stage = "COLLECTION_EXFIL"
        next_confidence = 0.88
        severity = "CRITICAL" if ("privilege_change" in indicators and "sensitive_access" in indicators) else "HIGH"
    elif "mfa_failure_then_success" in indicators or "new_origin" in indicators:
        current_stage = "INITIAL_ACCESS"
        stage_confidence = 0.85
        next_stage = "DISCOVERY"
        next_confidence = 0.78
        severity = "MEDIUM"
    else:
        current_stage = "BENIGN"
        stage_confidence = 0.92
        next_stage = "BENIGN"
        next_confidence = 0.89
        severity = "LOW"

    return {
        "evidence_id": f"ev-{session_id}-{event_count}",
        "actor": actor,
        "session_id": session_id,
        "current_stage": current_stage,
        "stage_confidence": round(stage_confidence, 4),
        "next_stage": next_stage,
        "next_confidence": round(next_confidence, 4),
        "severity": severity,
        "indicators": indicators,
        "top_events": top_events,
        "model_version": "m3-stub-v1.0"
    }


def predict_stream(events_df: Any) -> List[Dict[str, Any]]:
    """
    Predict evidence after each event in a session (prefix-based replay).
    
    Args:
        events_df: pandas DataFrame or list of dicts.
        
    Returns:
        list of evidence dicts, one per event in the stream.
    """
    df = _to_dataframe(events_df)
    if df is None or (hasattr(df, "empty") and df.empty) or (isinstance(df, list) and len(df) == 0):
        return [dict(DEFAULT_BENIGN_EVIDENCE)]
    
    results = []
    total_events = len(df)
    for i in range(1, total_events + 1):
        if hasattr(df, "iloc"):
            prefix = df.iloc[:i]
        else:
            prefix = df[:i]
        evidence = predict_session(prefix)
        results.append(evidence)
        
    return results


def main():
    parser = argparse.ArgumentParser(description="M3 Model Inference CLI")
    parser.add_argument("--events", required=True, help="Path to events CSV file")
    parser.add_argument("--out", required=False, help="Path to write output evidence JSON")
    parser.add_argument("--stream", action="store_true", default=True, help="Predict stream prefix-by-prefix (default: True)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.events):
        print(f"Error: file not found: {args.events}", file=sys.stderr)
        sys.exit(1)
        
    if pd is not None:
        df = pd.read_csv(args.events)
    else:
        import csv
        with open(args.events, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            df = list(reader)
            
    evidence_list = predict_stream(df)
    
    output_json = json.dumps(evidence_list, indent=2)
    
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"Successfully wrote {len(evidence_list)} evidence records to {args.out}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
