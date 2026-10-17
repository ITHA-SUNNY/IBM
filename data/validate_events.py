"""
Validate an events CSV against the Threshold contract (M2).

Checks: exact columns/order, allowed values (from data/schema.py), ISO-8601
UTC timestamps, stage labels, off_hours in {0,1}, actor_id pseudonym format
(no raw user IDs), events time-ordered within a session, one actor per
session. Prints counts per stage and scenario; exits non-zero on any error.

Usage: python data/validate_events.py path/to/events.csv [more.csv ...]
"""

import sys
from datetime import datetime

import pandas as pd

try:
    from schema import (ACTOR_ID_PATTERN, COLUMNS, EVENT_TYPES, OFF_HOURS, OUTCOMES,
                        SENSITIVITY, STAGES, TIMESTAMP_FORMAT)
except ImportError:
    from data.schema import (ACTOR_ID_PATTERN, COLUMNS, EVENT_TYPES, OFF_HOURS, OUTCOMES,
                             SENSITIVITY, STAGES, TIMESTAMP_FORMAT)

MAX_REPORTED = 5


def validate(df: pd.DataFrame):
    """Return a list of human-readable error strings (empty = valid)."""
    errors = []

    def bad(msg, mask=None):
        extra = ""
        if mask is not None and mask.any():
            extra = f" (rows {list(df.index[mask][:MAX_REPORTED])}{'...' if mask.sum() > MAX_REPORTED else ''})"
        errors.append(msg + extra)

    if list(df.columns) != COLUMNS:
        bad(f"columns must be exactly {COLUMNS}, got {list(df.columns)}")
        return errors
    if df.empty:
        return ["file has no rows"]

    for col in COLUMNS:
        nulls = df[col].isna() | (df[col].astype(str).str.strip() == "")
        if nulls.any():
            bad(f"{col}: empty values", nulls)

    for col, allowed in (("event_type", EVENT_TYPES), ("outcome", OUTCOMES),
                         ("sensitivity", SENSITIVITY), ("stage_label", STAGES)):
        mask = ~df[col].isin(allowed)
        if mask.any():
            bad(f"{col}: values outside allowed set {sorted(df.loc[mask, col].astype(str).unique())[:8]}", mask)

    off = pd.to_numeric(df["off_hours"], errors="coerce")
    mask = ~off.isin(OFF_HOURS)
    if mask.any():
        bad("off_hours must be 0 or 1", mask)

    mask = ~df["actor_id"].astype(str).str.match(ACTOR_ID_PATTERN)
    if mask.any():
        bad("actor_id must match ^U_[0-9a-f]{12}$ (raw user IDs are forbidden)", mask)

    def parse(ts):
        try:
            return datetime.strptime(str(ts), TIMESTAMP_FORMAT)
        except ValueError:
            return pd.NaT

    ts = df["timestamp"].map(parse)
    mask = ts.isna()
    if mask.any():
        bad(f"timestamp must be ISO-8601 UTC ({TIMESTAMP_FORMAT})", mask)

    if df["event_id"].duplicated().any():
        bad("event_id values must be unique", df["event_id"].duplicated())

    # Session-level checks
    actors_per_session = df.groupby("session_id")["actor_id"].nunique()
    multi = actors_per_session[actors_per_session > 1]
    if len(multi):
        errors.append(f"sessions with more than one actor: {list(multi.index[:MAX_REPORTED])}")

    if not mask.any():
        tmp = df.assign(_ts=pd.to_datetime(df["timestamp"], format=TIMESTAMP_FORMAT))
        backwards = tmp.groupby("session_id")["_ts"].apply(lambda s: not s.is_monotonic_increasing)
        if backwards.any():
            errors.append(f"sessions with events not time-ordered: {list(backwards[backwards].index[:MAX_REPORTED])}")
    return errors


def report(df: pd.DataFrame):
    print(f"Rows: {len(df)}  Sessions: {df['session_id'].nunique()}  Actors: {df['actor_id'].nunique()}")
    print("\nEvents per stage_label:")
    print(df["stage_label"].value_counts().reindex(STAGES, fill_value=0).to_string())
    print("\nEvents / sessions per scenario_id:")
    print(df.groupby("scenario_id").agg(events=("event_id", "count"),
                                        sessions=("session_id", "nunique")).to_string())


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    status = 0
    for path in argv:
        print(f"=== {path}")
        try:
            df = pd.read_csv(path, dtype={"off_hours": str})
        except Exception as e:  # unreadable file
            print(f"ERROR: cannot read: {e}")
            status = 1
            continue
        errors = validate(df)
        if errors:
            status = 1
            print("INVALID:")
            for e in errors:
                print(f"  - {e}")
        else:
            print("VALID")
            report(df)
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
