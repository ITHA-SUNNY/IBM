"""Verify M2 contracts, causal targets, class overlap and reproducibility."""
import csv
import json
import re
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from generate import CORE_FIELDS, FIELDS, STAGES, EVENT_TYPES, OUTCOMES, SENSITIVITIES, generate, load_key


def read(path):
    with path.open(newline="",encoding="utf-8") as f:
        reader=csv.DictReader(f)
        return reader.fieldnames,list(reader)


def main():
    root=Path(__file__).resolve().parent
    manifest=json.loads((root/"manifest.json").read_text())
    seen_ids,seen_actors=set(),set();total=0
    for name in ["train","validation","test","harder_test","rare_test","demo_stream"]:
        fields,rows=read(root/f"{name}.csv");assert fields==FIELDS
        ids={r["event_id"] for r in rows};assert len(ids)==len(rows) and not ids&seen_ids;seen_ids|=ids
        actors={r["actor_id"] for r in rows};assert not actors&seen_actors;seen_actors|=actors
        assert all(re.fullmatch(r"U_[0-9a-f]{12}",r["actor_id"]) for r in rows)
        assert all(r["stage_label"] in STAGES and r["event_type"] in EVENT_TYPES and r["outcome"] in OUTCOMES and r["sensitivity"] in SENSITIVITIES for r in rows)
        assert all(r["off_hours"] in ["0","1"] for r in rows)
        for r in rows:
            allowed={"DATASET_ACCESS":{"LIST","READ","COPY","WRITE"},"COMMAND_EXEC":{"BATCH_JOB","EMERGENCY_FIX","ROUTINE_STATUS"},"CRYPTO_OP":{"KEY_ROTATE","BULK_ENCRYPT"},"LOGON":{"AUTHENTICATE"},"MFA":{"CHALLENGE"},"ALTUSER_SPECIAL":{"GRANT_SPECIAL"},"LOGOFF":{"END_SESSION"}}
            assert r["operation"] in allowed[r["event_type"]]
        assert all(int(r["off_hours"])==int(datetime.fromisoformat(r["timestamp"].replace("Z","+00:00")).hour<6 or datetime.fromisoformat(r["timestamp"].replace("Z","+00:00")).hour>=22) for r in rows)
        assert rows==sorted(rows,key=lambda r:(r["timestamp"],r["event_id"]))
        fields,features=read(root/f"{name}_events.csv");assert len(features)==len(rows)
        assert "stage_label" not in fields and "scenario_id" not in fields
        assert [r["event_id"] for r in features]==[r["event_id"] for r in rows]
        core_fields,core=read(root/f"{name}_core.csv");assert core_fields==CORE_FIELDS and len(core)==len(rows)
        _,labels=read(root/f"{name}_labels.csv");assert ids=={r["event_id"] for r in labels}
        sessions=defaultdict(list);targets={r["event_id"]:r for r in labels}
        for r in rows:sessions[r["session_id"]].append(r)
        for seq in sessions.values():
            for i,r in enumerate(seq):
                expected=next((x["stage_label"] for x in seq[i+1:] if x["stage_label"]!=r["stage_label"]),r["stage_label"])
                assert targets[r["event_id"]]["next_stage_label"]==expected
        if name=="demo_stream":
            assert len(sessions)==4 and len(actors)==2
            for actor in actors:
                own=[r for r in rows if r["actor_id"]==actor]
                baseline=[r for r in own if r["scenario_id"]=="baseline"]
                live=[r for r in own if r["scenario_id"]!="baseline"]
                assert baseline and live and baseline[-1]["timestamp"]<live[0]["timestamp"]
                assert all(r["stage_label"]=="BENIGN" and r["origin"]=="KNOWN_NET" for r in baseline)
            assert all(r["origin"]=="KNOWN_NET" for r in rows if r["scenario_id"]=="lookalike")
        else:
            assert set(STAGES)=={r["stage_label"] for r in rows}
            for kind in {r["scenario_id"] for r in rows}:
                first=[s[0] for s in sessions.values() if s[0]["scenario_id"]==kind]
                assert {r["origin"] for r in first}=={"NEW_NET","KNOWN_NET"},(name,kind)
                assert {r["off_hours"] for r in first}=={"0","1"},(name,kind)
        if name=="rare_test":assert .01<=sum(s[0]["scenario_id"].startswith("attack") for s in sessions.values())/len(sessions)<=.05
        total+=len(rows)
    key=load_key(root/".hmac_key")
    assert manifest["hmac_key_fingerprint"]==__import__("hashlib").sha256(key).hexdigest()[:12]
    with tempfile.TemporaryDirectory() as d:
        generated=Path(d);generate(generated,manifest["seed"],manifest["splits"]["train"]["sessions"],key)
        for p in generated.iterdir():assert p.read_bytes()==(root/p.name).read_bytes(),p.name
    print(f"PASS: {total} events; contract, operations, split isolation, per-class origin/time overlap, rare prevalence, demo baselines, targets and regeneration verified.")


if __name__=="__main__":main()
