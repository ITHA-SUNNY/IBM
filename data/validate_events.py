"""Validate the exact shared events.csv schema; no dependencies."""
import argparse
import csv
from datetime import datetime
from pathlib import Path
try:
    from .schema import COLUMNS, STAGES, EVENT_TYPES, OUTCOMES, SENSITIVITY, OFF_HOURS, ACTOR_ID_PATTERN, TIMESTAMP_FORMAT, is_off_hours
except ImportError:
    from schema import COLUMNS, STAGES, EVENT_TYPES, OUTCOMES, SENSITIVITY, OFF_HOURS, ACTOR_ID_PATTERN, TIMESTAMP_FORMAT, is_off_hours


def validate_file(path, unlabeled=False):
    expected=[c for c in COLUMNS if c not in {"stage_label","scenario_id"}] if unlabeled else COLUMNS
    seen=set();count=0
    with Path(path).open(newline="",encoding="utf-8") as f:
        reader=csv.DictReader(f)
        if reader.fieldnames!=expected:raise ValueError(f"{path}: header must be {expected}")
        for line,r in enumerate(reader,2):
            if None in r or any(not r.get(k) for k in expected):raise ValueError(f"{path}:{line}: missing/extra value")
            if r["event_id"] in seen:raise ValueError(f"{path}:{line}: duplicate event_id")
            seen.add(r["event_id"])
            for col,allowed in [("event_type",EVENT_TYPES),("outcome",OUTCOMES),("sensitivity",SENSITIVITY)]:
                if r[col] not in allowed:raise ValueError(f"{path}:{line}: invalid {col}: {r[col]}")
            if not unlabeled and r["stage_label"] not in STAGES:raise ValueError(f"{path}:{line}: invalid stage")
            if not ACTOR_ID_PATTERN.fullmatch(r["actor_id"]):raise ValueError(f"{path}:{line}: invalid actor_id")
            if r["off_hours"] not in {str(x) for x in OFF_HOURS}:raise ValueError(f"{path}:{line}: invalid off_hours")
            datetime.strptime(r["timestamp"],TIMESTAMP_FORMAT)
            if int(r["off_hours"])!=is_off_hours(r["timestamp"]):raise ValueError(f"{path}:{line}: off_hours disagrees with timestamp")
            count+=1
    if not count:raise ValueError(f"{path}: no records")
    return count


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files",nargs="+",type=Path)
    parser.add_argument("--unlabeled",action="store_true")
    args=parser.parse_args()
    for file in args.files:print(f"PASS {file}: {validate_file(file,args.unlabeled)} events")
