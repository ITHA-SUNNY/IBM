"""Optional causal features for M3; no model decisions or ground-truth inputs."""
import argparse
import csv
import json
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
try:
    from .schema import PRIVILEGE_CHANGE_TYPES, DISCOVERY_TYPES
except ImportError:
    from schema import PRIVILEGE_CHANGE_TYPES, DISCOVERY_TYPES


def feature_rows(events, window=32):
    if window < 1:raise ValueError("window must be positive")
    buffers=defaultdict(lambda:deque(maxlen=window))
    previous={}
    rows=[]
    for event in sorted(events,key=lambda r:(r["timestamp"],r["event_id"])):
        key=(event["actor_id"],event["session_id"])
        prefix=buffers[key];prefix.append(event)
        current=datetime.fromisoformat(event["timestamp"].replace("Z","+00:00"))
        last=previous.get(key);previous[key]=current
        failed_mfa=False;recovered_mfa=False
        for r in prefix:
            if r["event_type"]=="MFA" and r["outcome"]=="FAILURE":failed_mfa=True
            if r["event_type"]=="MFA" and r["outcome"]=="SUCCESS" and failed_mfa:recovered_mfa=True
        failures=sum(r["outcome"]=="FAILURE" for r in prefix)
        privileges=sum(r["event_type"] in PRIVILEGE_CHANGE_TYPES and r["outcome"]=="SUCCESS" for r in prefix)
        sensitive=sum(r["event_type"] in {"DATASET_READ","DATASET_COPY"} and r["sensitivity"]=="HIGH" and r["outcome"]=="SUCCESS" for r in prefix)
        listing={r["resource"] for r in prefix if r["event_type"] in DISCOVERY_TYPES and r["outcome"]=="SUCCESS"}
        indicators=[]
        if any(r["origin"]=="NEW_NET" for r in prefix):indicators.append("new_origin")
        if any(str(r["off_hours"]).lower() in {"1","true"} for r in prefix):indicators.append("off_hours_activity")
        if recovered_mfa:indicators.append("mfa_failure_then_success")
        if privileges:indicators.append("privilege_change")
        if sensitive:indicators.append("sensitive_access")
        if len(listing)>=3:indicators.append("discovery_sweep")
        rows.append({"event_id":event["event_id"],"actor_id":event["actor_id"],"session_id":event["session_id"],"event_type":event["event_type"],"outcome":event["outcome"],"sensitivity":event["sensitivity"],"failure_count":failures,"privilege_change_count":privileges,"sensitive_access_count":sensitive,"distinct_listed_resources":len(listing),"mfa_failure_then_success":int(recovered_mfa),"new_origin":int(event["origin"]=="NEW_NET"),"off_hours":int(str(event["off_hours"]).lower() in {"1","true"}),"inter_event_seconds":0 if last is None else (current-last).total_seconds(),"indicators":json.dumps(indicators)})
    return rows


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    with args.events.open(newline="",encoding="utf-8") as f:rows=feature_rows(list(csv.DictReader(f)))
    if not rows:parser.error("events file is empty")
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("w",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
