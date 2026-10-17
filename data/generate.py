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

CORE_FIELDS = "event_id timestamp system_id actor_id session_id event_type outcome resource sensitivity origin off_hours stage_label scenario_id".split()
FIELDS = CORE_FIELDS + ["operation"]
STAGES = "BENIGN INITIAL_ACCESS CREDENTIAL_ACCESS DISCOVERY PRIVILEGE_ESCALATION LATERAL_MOVEMENT COLLECTION_EXFIL IMPACT".split()
EVENT_TYPES = ["LOGON", "MFA", "DATASET_ACCESS", "ALTUSER_SPECIAL", "COMMAND_EXEC", "CRYPTO_OP", "LOGOFF"]
OUTCOMES = ["SUCCESS", "FAILURE"]
SENSITIVITIES = ["LOW", "MEDIUM", "HIGH"]
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
    def add(et, operation, stage="BENIGN", sensitivity="LOW", outcome="SUCCESS", system="SYS1", resource=None):
        steps.append([et, operation, stage, sensitivity, outcome, system, resource])
    if attack:
        add("LOGON", "AUTHENTICATE", "INITIAL_ACCESS")
        add("MFA", "CHALLENGE", "CREDENTIAL_ACCESS", outcome="FAILURE")
        add("MFA", "CHALLENGE", "CREDENTIAL_ACCESS")
        for _ in range(rng.randint(3, 6)):
            add("DATASET_ACCESS", "LIST", "DISCOVERY", "MEDIUM", resource=rng.choice(["FINANCE.DATA", "PAYROLL.DATA", "OPS.DATA"]))
        # Harder variants can include failed privilege probes before success.
        if harder and rng.random() < .5:
            add("ALTUSER_SPECIAL", "GRANT_SPECIAL", "DISCOVERY", "HIGH", "FAILURE")
        add("ALTUSER_SPECIAL", "GRANT_SPECIAL", "PRIVILEGE_ESCALATION", "HIGH")
        system="SYS2" if kind=="attack_lateral" else "SYS1"
        if system=="SYS2":add("LOGON", "AUTHENTICATE", "LATERAL_MOVEMENT", system=system)
        add("DATASET_ACCESS", "READ", "COLLECTION_EXFIL", "HIGH", system=system)
        for _ in range(rng.randint(2, 4)):
            add("DATASET_ACCESS", "COPY", "COLLECTION_EXFIL", "HIGH", system=system)
        if kind=="attack_impact":
            add("DATASET_ACCESS", "WRITE", "IMPACT", "HIGH", system=system)
            add("CRYPTO_OP", "BULK_ENCRYPT", "IMPACT", "HIGH", system=system)
        add("LOGOFF", "END_SESSION", steps[-1][2], system=system)
    else:
        if not baseline and split != "demo" and rng.random() < .2:add("LOGON", "AUTHENTICATE", outcome="FAILURE")
        add("LOGON", "AUTHENTICATE")
        if not baseline and split != "demo" and rng.random() < .25:
            add("MFA", "CHALLENGE", outcome="FAILURE")
            add("MFA", "CHALLENGE")
        add("DATASET_ACCESS", "LIST", sensitivity="MEDIUM")
        if kind=="lookalike" and not baseline:
            add("ALTUSER_SPECIAL", "GRANT_SPECIAL", sensitivity="HIGH")
            add("DATASET_ACCESS", "READ", sensitivity="HIGH")
            if split != "demo" and rng.random()<.25:add("DATASET_ACCESS", "COPY", sensitivity="HIGH")
            add("COMMAND_EXEC", "EMERGENCY_FIX", sensitivity="HIGH")
        else:
            add("DATASET_ACCESS", "READ", sensitivity="MEDIUM")
            if not baseline:
                add("COMMAND_EXEC", "BATCH_JOB")
                if rng.random()<.3:add("DATASET_ACCESS", "COPY", sensitivity="HIGH")
                if rng.random()<.25:add("CRYPTO_OP", "KEY_ROTATE", sensitivity="HIGH")
                if rng.random()<.15:add("CRYPTO_OP", "BULK_ENCRYPT", sensitivity="HIGH")
        add("LOGOFF", "END_SESSION")
    if harder:
        # Shuffle adjacent LIST observations only, preserving stage prerequisites.
        lists=[i for i,s in enumerate(steps) if s[1]=="LIST"]
        if len(lists)>1:
            values=[steps[i] for i in lists];rng.shuffle(values)
            for i,value in zip(lists,values):steps[i]=value
        for _ in range(rng.randint(2, 4)):
            pos=rng.randint(1,len(steps)-1)
            prev=steps[pos-1]
            steps.insert(pos,["COMMAND_EXEC","ROUTINE_STATUS",prev[2],"LOW","SUCCESS",prev[5],None])
    rows=[]
    for n,(et,operation,stage,sensitivity,outcome,system,resource) in enumerate(steps):
        # Shared resource vocabulary: resource names do not encode attack labels.
        resource=resource or {"LOGON":"RACF","MFA":"MFA_CHALLENGE","ALTUSER_SPECIAL":"RACF_DB","LOGOFF":"RACF","CRYPTO_OP":"SYNTH_KEYSTORE","COMMAND_EXEC":"SYSTEM_COMMAND"}.get(et,rng.choice(["FINANCE.DATA","PAYROLL.DATA","OPS.DATA"]))
        now+=timedelta(seconds=rng.randint(10,45)*(4 if harder else 1))
        rows.append(dict(zip(FIELDS,[f"{sid}-e{n:03d}",now.isoformat().replace("+00:00","Z"),system,actor,sid,et,outcome,resource,sensitivity,origin,int(now.hour<6 or now.hour>=22),stage,"baseline" if baseline else kind,operation])))
    return rows


def write_csv(path,rows,fields=FIELDS):
    with path.open("w",encoding="utf-8",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
        writer.writerows({k:r[k] for k in fields} for r in rows)


def generate(output,seed=42,sessions=400,key=None):
    if key is None:raise ValueError("provide a private HMAC key")
    output.mkdir(parents=True,exist_ok=True)
    manifest={"schema_version":"2.1","seed":seed,"synthetic_only":True,"hmac_key_fingerprint":hashlib.sha256(key).hexdigest()[:12],"splits":{}}
    for split in ["train","validation","test","harder_test","rare_test","demo"]:
        rng=random.Random(f"{seed}:{split}")
        rows=[]
        if split=="demo":
            # Baselines for the SAME actors, before their two main sessions.
            for i,raw in enumerate(["SYNTH_demo_attacker","SYNTH_demo_admin"]):
                rows+=session_rows(rng,split,i,"background",key,raw_id=raw,baseline=True,force_origin="KNOWN_NET",force_hour=0)
            rows+=session_rows(rng,split,2,"attack",key,raw_id="SYNTH_demo_attacker",force_origin="NEW_NET",force_hour=2)
            rows+=session_rows(rng,split,3,"lookalike",key,raw_id="SYNTH_demo_admin",force_origin="KNOWN_NET",force_hour=2)
        else:
            count=max(1000,sessions) if split=="rare_test" else sessions
            n_attack=max(1,round(count*.03)) if split=="rare_test" else round(count*.4)
            kinds=["attack","attack_lateral","attack_impact"]*(n_attack//3+1)
            kinds=kinds[:n_attack]+["lookalike" if i%2 else "background" for i in range(count-n_attack)]
            rng.shuffle(kinds)
            for i,kind in enumerate(kinds):rows+=session_rows(rng,split,i,kind,key,split=="harder_test")
        rows.sort(key=lambda r:(r["timestamp"],r["event_id"]))
        name="demo_stream" if split=="demo" else split
        write_csv(output/f"{name}.csv",rows)
        write_csv(output/f"{name}_events.csv",rows,[x for x in FIELDS if x not in ["stage_label","scenario_id"]])
        # Strict 13-column copy for callers that cannot yet accept operation.
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
