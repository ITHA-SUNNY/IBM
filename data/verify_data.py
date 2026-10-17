"""Validate generated files and reproducibility without extra dependencies."""
import csv
import tempfile
from collections import defaultdict
from pathlib import Path
from generate import FIELDS, STAGES, generate


def read(path):
    with path.open(newline="", encoding="utf-8") as f:
        reader=csv.DictReader(f)
        return reader.fieldnames,list(reader)


def main():
    root=Path(__file__).resolve().parent
    seen_ids,seen_actors=set(),set()
    total=0
    for name in ["train","validation","test","harder_test","demo_stream"]:
        fields,rows=read(root/f"{name}.csv")
        assert fields==FIELDS
        ids={r["event_id"] for r in rows}
        assert len(ids)==len(rows) and not ids & seen_ids
        seen_ids |= ids
        actors={r["actor_id"] for r in rows}
        assert not actors & seen_actors
        seen_actors |= actors
        assert all(r["stage_label"] in STAGES for r in rows)
        assert rows==sorted(rows,key=lambda r:(r["timestamp"],r["event_id"]))
        _,features=read(root/f"{name}_events.csv")
        assert len(features)==len(rows)
        assert all("stage_label" not in r and "scenario_id" not in r for r in features)
        _,labels=read(root/f"{name}_labels.csv")
        assert ids=={r["event_id"] for r in labels}
        sessions=defaultdict(list)
        targets={r["event_id"]:r for r in labels}
        for r in rows:sessions[r["session_id"]].append(r)
        for seq in sessions.values():
            for i,r in enumerate(seq):
                expected=next((x["stage_label"] for x in seq[i+1:] if x["stage_label"]!=r["stage_label"]),r["stage_label"])
                assert targets[r["event_id"]]["next_stage_label"]==expected
        if name=="demo_stream":
            assert len(sessions)==2
            assert {r["scenario_id"] for r in rows}=={"attack","lookalike"}
        else:assert {r["stage_label"] for r in rows}==set(STAGES)
        total+=len(rows)
    import json
    manifest=json.loads((root/"manifest.json").read_text())
    if manifest["public_demo_key"]:
        with tempfile.TemporaryDirectory() as d:
            generated=Path(d)
            generate(generated,manifest["seed"],manifest["splits"]["train"]["sessions"])
            for p in generated.iterdir():assert p.read_bytes()==(root/p.name).read_bytes(),p.name
    print(f"PASS: {total} events; CSV schema, isolated splits, targets, demo and deterministic regeneration verified.")


if __name__=="__main__":main()
