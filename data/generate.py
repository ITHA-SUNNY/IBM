"""M2 synthetic security events. Python stdlib only; no pip install."""
import argparse
import csv
import hashlib
import hmac
import json
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

FIELDS = "event_id timestamp system_id actor_id session_id event_type outcome resource sensitivity origin off_hours stage_label scenario_id".split()
STAGES = "BENIGN INITIAL_ACCESS CREDENTIAL_ACCESS DISCOVERY PRIVILEGE_ESCALATION LATERAL_MOVEMENT COLLECTION_EXFIL IMPACT".split()
EVENT_TYPES = ["LOGON", "MFA", "DATASET_ACCESS", "ALTUSER_SPECIAL", "COMMAND_EXEC", "CRYPTO_OP", "LOGOFF"]
BASE = datetime(2026, 10, 17, tzinfo=timezone.utc)
DEMO_KEY = b"threshold-public-synthetic-demo-key-not-for-real-identities"


def pseudonym(user, key):
    return "act_" + hmac.new(key, user.encode(), hashlib.sha256).hexdigest()[:24]


def session_rows(rng, split, index, kind, key, harder=False):
    sid = f"{split}-{index:05d}"
    user = f"SYNTH_{split}_{index:05d}"
    actor = pseudonym(user, key)
    attack = kind.startswith("attack")
    origin = "NEW_NET" if attack else "KNOWN_NET"
    off_hours = attack or kind == "lookalike" or rng.random() < .1
    now = BASE + timedelta(days=index + {"train": 0, "validation": 500, "test": 1000, "harder_test": 1500, "demo": 2000}[split], hours=2 if off_hours else 10)
    steps = []
    def add(et, outcome, sensitivity, stage, system="SYS1", resource=None):
        steps.append((et, outcome, sensitivity, stage, system, resource))
    if attack:
        add("LOGON", "SUCCESS", "INTERNAL", "INITIAL_ACCESS")
        add("MFA", "FAIL", "INTERNAL", "CREDENTIAL_ACCESS")
        add("MFA", "SUCCESS", "INTERNAL", "CREDENTIAL_ACCESS")
        for _ in range(rng.randint(3, 5)):
            add("DATASET_ACCESS", "SUCCESS", "INTERNAL", "DISCOVERY")
        add("ALTUSER_SPECIAL", "SUCCESS", "CRITICAL", "PRIVILEGE_ESCALATION")
        system = "SYS1"
        if kind == "attack_lateral":
            system = "SYS2"
            add("LOGON", "SUCCESS", "INTERNAL", "LATERAL_MOVEMENT", system)
        add("DATASET_ACCESS", "SUCCESS", "CRITICAL", "COLLECTION_EXFIL", system)
        if kind == "attack_impact":
            add("CRYPTO_OP", "SUCCESS", "CRITICAL", "IMPACT", system)
        add("LOGOFF", "SUCCESS", "INTERNAL", steps[-1][3], system)
    else:
        if kind == "background" and rng.random() < .2:
            add("LOGON", "FAIL", "INTERNAL", "BENIGN")
        add("LOGON", "SUCCESS", "INTERNAL", "BENIGN")
        for _ in range(rng.randint(1, 3)):
            add("DATASET_ACCESS", "SUCCESS", "INTERNAL", "BENIGN")
        if kind == "lookalike":
            add("ALTUSER_SPECIAL", "SUCCESS", "CRITICAL", "BENIGN")
            add("DATASET_ACCESS", "SUCCESS", "CRITICAL", "BENIGN")
        else:
            add("COMMAND_EXEC", "SUCCESS", "INTERNAL", "BENIGN", resource="BATCH_JOB")
        add("LOGOFF", "SUCCESS", "INTERNAL", "BENIGN")
    if harder:
        # Extra noise and slower pacing; no future stage is moved before its causes.
        pos = rng.randint(1, len(steps)-1)
        prev = steps[pos-1]
        steps.insert(pos, ("COMMAND_EXEC", "SUCCESS", "INTERNAL", prev[3], prev[4], "ROUTINE_STATUS"))
        if not attack and rng.random() < .5:
            origin = "NEW_NET"
    rows=[]
    for n, (et, outcome, sensitivity, stage, system, resource) in enumerate(steps):
        now += timedelta(seconds=rng.randint(5, 40) * (4 if harder else 1))
        resource = resource or {"LOGON":"RACF", "LOGOFF":"RACF", "MFA":"MFA_CHALLENGE", "ALTUSER_SPECIAL":"RACF_DB", "CRYPTO_OP":"SYNTH_KEYSTORE"}.get(et, "SYNTH_DATASET_"+sensitivity)
        rows.append(dict(zip(FIELDS, [f"{sid}-e{n:03d}", now.isoformat().replace("+00:00", "Z"), system, actor, sid, et, outcome, resource, sensitivity, origin, str(off_hours), stage, kind])))
    return rows


def write_csv(path, rows, fields=FIELDS):
    with path.open("w", encoding="utf-8", newline="") as f:
        writer=csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows({k:r[k] for k in fields} for r in rows)


def generate(output, seed=42, sessions=400, key=DEMO_KEY):
    output.mkdir(parents=True, exist_ok=True)
    manifest={"schema_version":"1.0", "seed":seed, "synthetic_only":True, "public_demo_key":key == DEMO_KEY, "splits":{}}
    for split in ["train", "validation", "test", "harder_test", "demo"]:
        rng=random.Random(f"{seed}:{split}")
        kinds=["attack", "lookalike"] if split == "demo" else (["background", "lookalike", "attack", "attack_lateral", "attack_impact"] * ((sessions+4)//5))[:sessions]
        if split != "demo": rng.shuffle(kinds)
        rows=[]
        for i,kind in enumerate(kinds): rows.extend(session_rows(rng,split,i,kind,key,split=="harder_test"))
        rows.sort(key=lambda r:(r["timestamp"],r["event_id"]))
        name="demo_stream" if split=="demo" else split
        write_csv(output/f"{name}.csv", rows)
        # Live inference copy contains no ground truth or scenario identifiers.
        write_csv(output/f"{name}_events.csv", rows, [x for x in FIELDS if x not in ["stage_label","scenario_id"]])
        labels=[]
        groups={}
        for r in rows: groups.setdefault(r["session_id"],[]).append(r)
        for seq in groups.values():
            for i,r in enumerate(seq):
                next_stage=next((x["stage_label"] for x in seq[i+1:] if x["stage_label"]!=r["stage_label"]),r["stage_label"])
                labels.append({"event_id":r["event_id"],"stage_label":r["stage_label"],"next_stage_label":next_stage,"is_malicious":str(r["scenario_id"].startswith("attack"))})
        write_csv(output/f"{name}_labels.csv",labels,["event_id","stage_label","next_stage_label","is_malicious"])
        manifest["splits"][split]={"sessions":len(groups),"events":len(rows),"stages":sorted({r["stage_label"] for r in rows})}
    (output/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=Path(__file__).resolve().parent)
    parser.add_argument("--seed",type=int,default=42)
    parser.add_argument("--sessions",type=int,default=400)
    args=parser.parse_args()
    if args.sessions < 20: parser.error("--sessions must be at least 20")
    key=os.environ.get("THRESHOLD_HMAC_KEY")
    print(json.dumps(generate(args.output,args.seed,args.sessions,key.encode() if key else DEMO_KEY),indent=2))
