"""Seeded synthetic security CSVs. Python standard library only."""
import argparse
import csv
import hashlib
import hmac
import json
import os
import random
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from .schema import COLUMNS, STAGES, EVENT_TYPES, OUTCOMES, SENSITIVITY, DISCOVERY_TYPES, is_off_hours
except ImportError:
    from schema import COLUMNS, STAGES, EVENT_TYPES, OUTCOMES, SENSITIVITY, DISCOVERY_TYPES, is_off_hours
CORE_FIELDS = COLUMNS
FIELDS = COLUMNS
SENSITIVITIES = SENSITIVITY
BASE = datetime(2026, 10, 17, tzinfo=timezone.utc)


def pseudonym(raw_id, key):
    return "U_" + hmac.new(key, raw_id.encode(), hashlib.sha256).hexdigest()[:12]


def load_key(path):
    env = os.environ.get("THRESHOLD_HMAC_KEY")
    if env:
        return env.encode()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        # Private local key, never included in the dataset or Git.
        with path.open("xb") as f:
            f.write(secrets.token_bytes(32))
    key = path.read_bytes()
    if len(key) < 16:
        raise ValueError("local HMAC key must have at least 16 bytes")
    return key


def session_rows(rng, split, index, kind, key, harder=False, raw_id=None,
                 baseline=False, force_origin=None, force_hour=None):
    sid = f"{split}-{index:05d}"
    actor = pseudonym(raw_id or f"SYNTH_{split}_{index:05d}", key)
    attack = kind.startswith("attack") and not baseline
    # Origin and hour have the same marginal distribution in each class.
    origin = force_origin or ("NEW_NET" if rng.random() < .4 else "KNOWN_NET")
    hour = force_hour if force_hour is not None else (rng.choice([0, 1, 2, 3, 4, 5, 22]) if rng.random() < .5 else rng.randint(9, 16))
    offset = {"train":0, "validation":1, "test":2, "harder_test":3, "rare_test":4, "demo":0}[split]
    now = BASE + timedelta(days=offset, hours=hour, seconds=index % 60)
    steps=[]
    def add(et, stage="BENIGN", sensitivity="LOW", outcome="SUCCESS", system="SYS1", resource=None):
        steps.append([et, stage, sensitivity, outcome, system, resource])
    if attack:
        add("LOGON", "INITIAL_ACCESS")
        add("MFA", "CREDENTIAL_ACCESS", outcome="FAILURE")
        add("MFA", "CREDENTIAL_ACCESS")
        for _ in range(rng.randint(3, 6)):
            et=rng.choice(DISCOVERY_TYPES)
            resource="RACF_DB" if et=="RACF_LISTUSER" else rng.choice(["FINANCE.DATA","PAYROLL.DATA","OPS.DATA"])
            add(et,"DISCOVERY","MEDIUM",resource=resource)
        if harder and rng.random()<.5:
            add("ALTUSER_SPECIAL","DISCOVERY","HIGH","FAILURE")
        add("ALTUSER_SPECIAL","PRIVILEGE_ESCALATION","HIGH")
        system="SYS2" if kind=="attack_v2" else "SYS1"
        if system=="SYS2":add("LOGON","LATERAL_MOVEMENT",system=system)
        add("DATASET_READ","COLLECTION_EXFIL","HIGH",system=system)
        for _ in range(rng.randint(2,4)):
            add("DATASET_COPY","COLLECTION_EXFIL","HIGH",system=system)
        add("LOGOFF",steps[-1][1],system=system)
    else:
        if not baseline and split!="demo" and rng.random()<.2:add("LOGON",outcome="FAILURE")
        add("LOGON")
        if not baseline and split!="demo" and rng.random()<.25:
            add("MFA",outcome="FAILURE");add("MFA")
        add("DATASET_LIST",sensitivity="MEDIUM")
        if kind=="lookalike_v1" and not baseline:
            add("ALTUSER_SPECIAL",sensitivity="HIGH")
            add("DATASET_READ",sensitivity="HIGH")
            if split!="demo" and rng.random()<.25:add("DATASET_COPY",sensitivity="HIGH")
        else:
            add("DATASET_READ",sensitivity="MEDIUM")
            if not baseline:
                add("JOB_SUBMIT",resource="OVERNIGHT_BATCH" if hour<6 or hour>=20 else "BATCH_JOB")
                if rng.random()<.3:add("DATASET_COPY",sensitivity="HIGH")
                if rng.random()<.2:add("PASSWORD_CHANGE",sensitivity="MEDIUM")
                if rng.random()<.15:add("PERMIT",sensitivity="HIGH")
        add("LOGOFF")
    if harder:
        indices=[i for i,s in enumerate(steps) if s[0] in DISCOVERY_TYPES]
        if len(indices)>1:
            values=[steps[i] for i in indices];rng.shuffle(values)
            for i,value in zip(indices,values):steps[i]=value
        for _ in range(rng.randint(2,4)):
            pos=rng.randint(1,len(steps)-1);prev=steps[pos-1]
            steps.insert(pos,["JOB_SUBMIT",prev[1],"LOW","SUCCESS",prev[4],"BACKGROUND_BATCH"])
    rows=[]
    for n,(et,stage,sensitivity,outcome,system,resource) in enumerate(steps):
        resource=resource or {"LOGON":"RACF","MFA":"MFA_CHALLENGE","ALTUSER_SPECIAL":"RACF_DB","PERMIT":"RACF_DB","LOGOFF":"RACF","PASSWORD_CHANGE":"RACF"}.get(et,rng.choice(["FINANCE.DATA","PAYROLL.DATA","OPS.DATA"]))
        now+=timedelta(seconds=rng.randint(10,45)*(4 if harder else 1))
        rows.append(dict(zip(FIELDS,[f"{sid}-e{n:03d}",now.isoformat().replace("+00:00","Z"),system,actor,sid,et,outcome,resource,sensitivity,origin,is_off_hours(now),stage,"demo_baseline" if baseline else kind])))
    return rows


def write_csv(path,rows,fields=FIELDS):
    with path.open("w",encoding="utf-8",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
        writer.writerows({k:r[k] for k in fields} for r in rows)


def generate(output,seed=42,sessions=400,key=None):
    if key is None:raise ValueError("provide a private HMAC key")
    output.mkdir(parents=True,exist_ok=True)
    manifest={"schema_version":"3.0","seed":seed,"synthetic_only":True,"hmac_key_fingerprint":hashlib.sha256(key).hexdigest()[:12],"splits":{}}
    for split in ["train","validation","test","harder_test","rare_test","demo"]:
        rng=random.Random(f"{seed}:{split}")
        rows=[]
        if split=="demo":
            # Baselines for the SAME actors, before their two main sessions.
            for i,raw in enumerate(["SYNTH_demo_attacker","SYNTH_demo_admin"]):
                rows+=session_rows(rng,split,i,"benign",key,raw_id=raw,baseline=True,force_origin="KNOWN_NET",force_hour=0)
            rows+=session_rows(rng,split,2,"attack_v1",key,raw_id="SYNTH_demo_attacker",force_origin="NEW_NET",force_hour=2)
            rows+=session_rows(rng,split,3,"lookalike_v1",key,raw_id="SYNTH_demo_admin",force_origin="KNOWN_NET",force_hour=2)
        else:
            count=max(1000,sessions) if split=="rare_test" else sessions
            n_attack=max(1,round(count*.03)) if split=="rare_test" else round(count*.4)
            kinds=["attack_v1","attack_v2"]*(n_attack//2+1)
            kinds=kinds[:n_attack]+["lookalike_v1" if i%2 else "benign" for i in range(count-n_attack)]
            rng.shuffle(kinds)
            for i,kind in enumerate(kinds):rows+=session_rows(rng,split,i,kind,key,split=="harder_test")
        rows.sort(key=lambda r:(r["timestamp"],r["event_id"]))
        name="demo_stream" if split=="demo" else split
        write_csv(output/f"{name}.csv",rows)
        write_csv(output/f"{name}_events.csv",rows,[x for x in FIELDS if x not in ["stage_label","scenario_id"]])
        # Compatibility alias; canonical files already have the exact 13 columns.
        write_csv(output/f"{name}_core.csv",rows,CORE_FIELDS)
        groups={}
        for row in rows:groups.setdefault(row["session_id"],[]).append(row)
        labels=[]
        stats={}
        for seq in groups.values():
            first=seq[0];kind=first["scenario_id"]
            stat=stats.setdefault(kind,{"sessions":0,"new_net":0,"off_hours":0})
            stat["sessions"]+=1;stat["new_net"]+=int(first["origin"]=="NEW_NET");stat["off_hours"]+=int(first["off_hours"])
            for i,r in enumerate(seq):
                nxt=next((x["stage_label"] for x in seq[i+1:] if x["stage_label"]!=r["stage_label"]),r["stage_label"])
                labels.append({"event_id":r["event_id"],"stage_label":r["stage_label"],"next_stage_label":nxt,"is_malicious":int(r["scenario_id"].startswith("attack"))})
        write_csv(output/f"{name}_labels.csv",labels,["event_id","stage_label","next_stage_label","is_malicious"])
        malicious=sum(s[0]["scenario_id"].startswith("attack") for s in groups.values())
        manifest["splits"][split]={"sessions":len(groups),"events":len(rows),"malicious_sessions":malicious,"attack_prevalence":malicious/len(groups),"actors":len({r["actor_id"] for r in rows}),"stages":sorted({r["stage_label"] for r in rows}),"scenario_counts":stats}
    (output/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    return manifest


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=Path(__file__).resolve().parent)
    parser.add_argument("--seed",type=int,default=42)
    parser.add_argument("--sessions",type=int,default=400)
    parser.add_argument("--key-file",type=Path,default=Path(__file__).resolve().parent/".hmac_key")
    args=parser.parse_args()
    if args.sessions<30:parser.error("--sessions must be at least 30")
    manifest=generate(args.output,args.seed,args.sessions,load_key(args.key_file))
    print(json.dumps({k:{f:v[f] for f in ["sessions","events","malicious_sessions","attack_prevalence"]} for k,v in manifest["splits"].items()},indent=2))
