"""Verify M2 contracts, causal targets, class overlap and reproducibility."""
import csv
import json
import re
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from generate import generate, load_key
from schema import COLUMNS as FIELDS, COLUMNS as CORE_FIELDS, STAGES, EVENT_TYPES, OUTCOMES, SENSITIVITY as SENSITIVITIES, is_off_hours
from validate_events import validate_file


def read(path):
    with path.open(newline="",encoding="utf-8") as f:
        reader=csv.DictReader(f)
        return reader.fieldnames,list(reader)


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir",type=Path,default=Path(__file__).resolve().parent)
    parser.add_argument("--key-file",type=Path)
    args=parser.parse_args()
    root=args.data_dir
    manifest=json.loads((root/"manifest.json").read_text())
    seen_ids,seen_actors=set(),set();total=0
    for name in ["train","validation","test","harder_test","rare_test","demo_stream"]:
        fields,rows=read(root/f"{name}.csv");assert fields==FIELDS
        ids={r["event_id"] for r in rows};assert len(ids)==len(rows) and not ids&seen_ids;seen_ids|=ids
        actors={r["actor_id"] for r in rows};assert not actors&seen_actors;seen_actors|=actors
        assert all(re.fullmatch(r"U_[0-9a-f]{12}",r["actor_id"]) for r in rows)
        assert all(r["stage_label"] in STAGES and r["event_type"] in EVENT_TYPES and r["outcome"] in OUTCOMES and r["sensitivity"] in SENSITIVITIES for r in rows)
        assert all(r["off_hours"] in ["0","1"] for r in rows)
        validate_file(root/f"{name}.csv")
        validate_file(root/f"{name}_events.csv",unlabeled=True)
        assert all(int(r["off_hours"])==is_off_hours(r["timestamp"]) for r in rows)
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
                baseline=[r for r in own if r["scenario_id"]=="demo_baseline"]
                live=[r for r in own if r["scenario_id"]!="demo_baseline"]
                assert baseline and live and baseline[-1]["timestamp"]<live[0]["timestamp"]
                assert all(r["stage_label"]=="BENIGN" and r["origin"]=="KNOWN_NET" for r in baseline)
            assert all(r["origin"]=="KNOWN_NET" and r["outcome"]=="SUCCESS" for r in rows if r["scenario_id"]=="lookalike_v1")
        else:
            assert set(STAGES)-{"IMPACT"}=={r["stage_label"] for r in rows}
            for kind in {r["scenario_id"] for r in rows}:
                first=[s[0] for s in sessions.values() if s[0]["scenario_id"]==kind]
                assert {r["origin"] for r in first}=={"NEW_NET","KNOWN_NET"},(name,kind)
                assert {r["off_hours"] for r in first}=={"0","1"},(name,kind)
        if name=="rare_test":assert .01<=sum(s[0]["scenario_id"].startswith("attack") for s in sessions.values())/len(sessions)<=.05
        total+=len(rows)
    import os
    key_path=args.key_file or root/".hmac_key"
    verified_regeneration=False
    if args.key_file is not None or os.environ.get("THRESHOLD_HMAC_KEY") or key_path.exists():
        key=load_key(key_path)
        if manifest["hmac_key_fingerprint"]!=__import__("hashlib").sha256(key).hexdigest()[:12]:
            raise ValueError("HMAC key differs from dataset fingerprint; use matching key or verify in a fresh data directory without a local key")
        with tempfile.TemporaryDirectory() as d:
            generated=Path(d);generate(generated,manifest["seed"],manifest["splits"]["train"]["sessions"],key)
            for p in generated.iterdir():assert p.read_bytes()==(root/p.name).read_bytes(),p.name
        verified_regeneration=True
    print(f"PASS: {total} events; exact schema, split isolation, class overlap, rare prevalence, demo baselines and targets verified.")
    print("Byte-identical regeneration: " + ("PASS" if verified_regeneration else "SKIPPED (private key unavailable; structural validation still passed)"))


if __name__=="__main__":main()
