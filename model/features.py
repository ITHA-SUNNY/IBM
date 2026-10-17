"""
Threshold M3 Feature Engineering Module

Extracts sliding window features from raw session events.
Strictly zero label leakage: 'stage_label' and 'scenario_id' are never used as features.

Extracted Features per Window (last N events, default N=10):
------------------------------------------------------------
1.  count_failed_outcomes: Total failed events in window
2.  count_mfa_failures: Failed MFA authentications in window
3.  count_privilege_changes: Administrative or privilege alterations (e.g., ALTUSER, SPECIAL, RACF)
4.  count_sensitive_access: Accesses to HIGH/CRITICAL sensitivity resources
5.  count_discovery_events: Discovery sweep operations (LIST_*, QUERY_*, FIND_*)
6.  new_origin: 1 if this IP/origin has never been seen before for this actor, 0 otherwise
7.  off_hours_any: 1 if any event in window took place during off-hours, 0 otherwise
8.  off_hours_last: 1 if latest event in window took place during off-hours, 0 otherwise
9.  events_so_far: Cumulative event counter for the session
10. window_size: Number of events currently in the sliding window (up to N)
11. seconds_since_session_start: Elapsed seconds between session start and current event
12. mean_gap_seconds: Average seconds between consecutive events in the window
13. last_gap_seconds: Seconds between the last two events in the window
14. count_event_type_<TYPE>: Frequency of each specific event type in the window
15. last_event_is_<TYPE>: One-hot indicator of the most recent event type
"""

import os
import sys
from typing import Tuple, List, Dict, Any, Optional
import pandas as pd
import numpy as np

# Constants come from data/schema.py (single source of truth, Rule 4).
# Make the repo root importable so this works from `python model/x.py` too.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from data.schema import (  # noqa: E402
    EVENT_TYPES,
    PRIVILEGE_CHANGE_TYPES,
    DISCOVERY_TYPES,
    normalize_event_type,
)

# Event vocabulary for count / last-event features (alias kept for importers)
STANDARD_EVENT_TYPES = list(EVENT_TYPES)


def _is_failed(outcome: Any) -> bool:
    s = str(outcome).strip().upper()
    return "FAIL" in s or s == "DENIED" or s == "REJECTED"


def _is_mfa_failure(event_type: Any, outcome: Any, resource: Any) -> bool:
    return normalize_event_type(event_type) == "MFA" and _is_failed(outcome)


def _is_privilege_change(event_type: Any, resource: Any) -> bool:
    return normalize_event_type(event_type) in PRIVILEGE_CHANGE_TYPES


def _is_sensitive_access(sensitivity: Any) -> bool:
    s = str(sensitivity).strip().upper()
    return s in ["HIGH", "CRITICAL", "RESTRICTED"]


def _is_discovery(event_type: Any, resource: Any) -> bool:
    return normalize_event_type(event_type) in DISCOVERY_TYPES


def _parse_timestamp(ts: Any) -> pd.Timestamp:
    try:
        return pd.to_datetime(ts, utc=True)
    except Exception:
        return pd.Timestamp.now(tz="UTC")


def extract_features_for_prefix(
    prefix_df: pd.DataFrame,
    actor_historical_origins: Optional[set] = None,
    window: int = 10,
    vocabulary: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Extract a single feature vector from a session prefix.
    
    Args:
        prefix_df: DataFrame of events seen so far in this session (ordered chronologically).
        actor_historical_origins: Set of origins seen previously for this actor before this session.
        window: Sliding window size (last N events).
        vocabulary: Known list of event types for one-hot and count features.
    
    Returns:
        Dictionary of numeric feature names to values.
    """
    if vocabulary is None:
        vocabulary = STANDARD_EVENT_TYPES

    if prefix_df is None or len(prefix_df) == 0:
        feat = {
            "count_failed_outcomes": 0,
            "count_mfa_failures": 0,
            "count_privilege_changes": 0,
            "count_sensitive_access": 0,
            "count_discovery_events": 0,
            "new_origin": 0,
            "off_hours_any": 0,
            "off_hours_last": 0,
            "events_so_far": 0,
            "window_size": 0,
            "seconds_since_session_start": 0.0,
            "mean_gap_seconds": 0.0,
            "last_gap_seconds": 0.0,
        }
        for et in vocabulary:
            feat[f"count_event_{et}"] = 0
            feat[f"last_event_is_{et}"] = 0
        return feat

    # Window slice
    win_df = prefix_df.tail(window)
    win_len = len(win_df)
    total_events = len(prefix_df)
    last_event = win_df.iloc[-1]

    # 1-5: Counts
    cnt_failed = sum(_is_failed(o) for o in win_df["outcome"])
    cnt_mfa_fail = sum(_is_mfa_failure(r.get("event_type", ""), r.get("outcome", ""), r.get("resource", ""))
                       for _, r in win_df.iterrows())
    cnt_priv = sum(_is_privilege_change(r.get("event_type", ""), r.get("resource", ""))
                   for _, r in win_df.iterrows())
    cnt_sens = sum(_is_sensitive_access(s) for s in win_df.get("sensitivity", []))
    cnt_disc = sum(_is_discovery(r.get("event_type", ""), r.get("resource", ""))
                   for _, r in win_df.iterrows())

    # 6: New origin
    current_origin = str(last_event.get("origin", "")).strip()
    is_new_origin = 0
    if actor_historical_origins is not None and current_origin:
        is_new_origin = 1 if current_origin not in actor_historical_origins else 0

    # 7-8: Off hours
    off_hours_vals = [
        str(v).strip().lower() in ["true", "1", "t", "yes"]
        for v in win_df.get("off_hours", [False])
    ]
    off_hours_any = 1 if any(off_hours_vals) else 0
    off_hours_last = 1 if (off_hours_vals and off_hours_vals[-1]) else 0

    # 9-13: Time dynamics
    timestamps = [_parse_timestamp(t) for t in win_df.get("timestamp", [])]
    first_session_ts = _parse_timestamp(prefix_df.iloc[0].get("timestamp", timestamps[0]))
    current_ts = timestamps[-1] if timestamps else first_session_ts
    
    seconds_since_start = max(0.0, (current_ts - first_session_ts).total_seconds())

    if len(timestamps) > 1:
        gaps = [(timestamps[i] - timestamps[i - 1]).total_seconds() for i in range(1, len(timestamps))]
        mean_gap = float(np.mean(gaps))
        last_gap = float(gaps[-1])
    else:
        mean_gap = 0.0
        last_gap = 0.0

    features: Dict[str, Any] = {
        "count_failed_outcomes": cnt_failed,
        "count_mfa_failures": cnt_mfa_fail,
        "count_privilege_changes": cnt_priv,
        "count_sensitive_access": cnt_sens,
        "count_discovery_events": cnt_disc,
        "new_origin": is_new_origin,
        "off_hours_any": off_hours_any,
        "off_hours_last": off_hours_last,
        "events_so_far": total_events,
        "window_size": win_len,
        "seconds_since_session_start": float(seconds_since_start),
        "mean_gap_seconds": float(mean_gap),
        "last_gap_seconds": float(last_gap),
    }

    # 14-15: Event type frequency and last event one-hot
    last_et = normalize_event_type(last_event.get("event_type", ""))
    win_et_counts = (
        win_df["event_type"].map(normalize_event_type).value_counts().to_dict()
        if "event_type" in win_df else {}
    )

    for et in vocabulary:
        features[f"count_event_{et}"] = win_et_counts.get(et, 0)
        features[f"last_event_is_{et}"] = 1 if last_et == et else 0

    return features


def build_windows(
    df: pd.DataFrame,
    window: int = 10,
    vocabulary: Optional[List[str]] = None,
    next_stage_target: str = "next_event",
    exclude_timing: bool = False
) -> Tuple[pd.DataFrame, pd.Series, pd.Series, pd.DataFrame]:
    """
    Build sliding window feature vectors and target labels across all sessions in df.
    
    Guarantees:
      - Split-safe: Windowing is contained strictly within each session_id.
      - Zero label leakage: 'stage_label' and 'scenario_id' are never included in X.
      - Target 'current_stage' = stage_label of current event.
      - Target 'next_stage' = 
          - if next_stage_target == 'next_distinct': the first subsequent event with a
            different stage_label, or curr_stage if no later different stage exists.
          - if next_stage_target == 'next_event': stage_label of next event in session
            (or 'BENIGN' for final event).
      
    Args:
        df: Raw events DataFrame matching events.csv schema.
        window: Sliding window size N (default 10).
        vocabulary: Optional explicit list of event types.
        next_stage_target: 'next_event' (default) or 'next_distinct'.
        exclude_timing: if True, drop seconds_since_session_start, mean_gap_seconds, last_gap_seconds.
        
    Returns:
        X (DataFrame): Feature matrix (all numeric).
        y_current (Series): Target stage label of the current event.
        y_next (Series): Target stage label of the subsequent event in the session.
        metadata (DataFrame): Identifiers (session_id, event_id, session_event_index, actor_id).
    """
    if vocabulary is None:
        # Fixed vocabulary from data/schema.py: stable feature columns across splits.
        # Unknown / unmapped legacy event types are simply not counted.
        vocabulary = list(STANDARD_EVENT_TYPES)

    # Pre-compute historical origins seen per actor across the dataset
    actor_known_origins: Dict[str, set] = {}
    
    x_rows: List[Dict[str, Any]] = []
    y_curr_list: List[str] = []
    y_next_list: List[str] = []
    meta_rows: List[Dict[str, Any]] = []

    # Process each session independently
    session_groups = df.groupby("session_id", sort=False)

    for session_id, session_df in session_groups:
        # Sort chronologically within session
        if "timestamp" in session_df:
            session_df = session_df.sort_values("timestamp")
        
        session_len = len(session_df)
        actor_id = str(session_df.iloc[0].get("actor_id", "UNKNOWN"))

        # Pre-extract stage labels for fast lookup
        session_stages = (
            session_df["stage_label"].astype(str).tolist()
            if "stage_label" in session_df
            else ["BENIGN"] * session_len
        )

        # Prior origins for this actor
        known_origins = actor_known_origins.setdefault(actor_id, set())

        for idx in range(session_len):
            prefix_df = session_df.iloc[: idx + 1]
            curr_row = session_df.iloc[idx]
            
            # Features
            feat = extract_features_for_prefix(
                prefix_df=prefix_df,
                actor_historical_origins=known_origins,
                window=window,
                vocabulary=vocabulary
            )
            x_rows.append(feat)

            # Targets
            curr_stage = session_stages[idx]
            y_curr_list.append(curr_stage)

            if next_stage_target == "next_distinct":
                # First subsequent event with different stage, else curr_stage
                next_stage = curr_stage
                for s in session_stages[idx + 1:]:
                    if s != curr_stage:
                        next_stage = s
                        break
            else:
                if idx + 1 < session_len:
                    next_stage = session_stages[idx + 1]
                else:
                    # Last event in session: next stage defaults to BENIGN per section 5
                    next_stage = "BENIGN"
            y_next_list.append(str(next_stage))

            # Metadata
            meta_rows.append({
                "session_id": str(session_id),
                "event_id": str(curr_row.get("event_id", f"evt-{idx}")),
                "session_event_index": idx,
                "actor_id": actor_id,
            })

            # Update known origins for actor after processing this event
            curr_orig = str(curr_row.get("origin", "")).strip()
            if curr_orig:
                known_origins.add(curr_orig)

    X = pd.DataFrame(x_rows).fillna(0)
    if exclude_timing:
        timing_cols = ["seconds_since_session_start", "mean_gap_seconds", "last_gap_seconds"]
        X = X.drop(columns=[c for c in timing_cols if c in X.columns])
    y_current = pd.Series(y_curr_list, name="current_stage")
    y_next = pd.Series(y_next_list, name="next_stage")
    metadata = pd.DataFrame(meta_rows)

    return X, y_current, y_next, metadata


if __name__ == "__main__":
    # Self-test using sample_events.csv
    import sys
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sample_path = os.path.join(os.path.dirname(script_dir), "data", "out", "events_small.csv")
    if not os.path.exists(sample_path):  # fall back to the legacy hand-made sample
        sample_path = os.path.join(script_dir, "sample_events.csv")

    if not os.path.exists(sample_path):
        # Check parent directory
        parent_sample = os.path.join(os.path.dirname(script_dir), "sample_events.csv")
        if os.path.exists(parent_sample):
            sample_path = parent_sample

    print(f"Self-testing features.py using: {sample_path}")
    raw_df = pd.read_csv(sample_path)
    X, y_curr, y_nxt, meta = build_windows(raw_df, window=10)

    print("\n--- Self-Test Verification Results ---")
    print(f"Raw events count: {len(raw_df)}")
    print(f"X feature matrix shape: {X.shape}")
    print(f"y_current count: {len(y_curr)}, unique stages: {list(y_curr.unique())}")
    print(f"y_next count: {len(y_nxt)}, unique stages: {list(y_nxt.unique())}")
    print(f"Metadata rows: {len(meta)}")

    # Verification checks
    assert len(X) == len(raw_df), f"Mismatch in row count: {len(X)} vs {len(raw_df)}"
    assert "stage_label" not in X.columns, "CRITICAL ERROR: stage_label leaked into X!"
    assert "scenario_id" not in X.columns, "CRITICAL ERROR: scenario_id leaked into X!"
    assert not X.isnull().values.any(), "CRITICAL ERROR: NaN values found in X!"
    print("\nAll checks passed successfully! Zero label leakage verified.")
