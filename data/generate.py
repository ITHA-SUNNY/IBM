"""
Threshold synthetic event generator (M2).

Produces benign background plus N randomized copies each of attack_v1,
attack_v2 and lookalike_v1 in the events.csv contract (13 columns).
Scenario definitions live in data/event_vocab.md. All constants come from
data/schema.py. Raw user names are pseudonymized at ingest (HMAC; needs the
THRESHOLD_HMAC_KEY env var).

Usage (from repo root):
    python data/generate.py --small          # ~60 rows -> data/out/events_small.csv
    python data/generate.py                  # full set  -> data/out/events_full.csv
    python data/generate.py --seed 7 --benign 500 --attack-v1 80
"""

import argparse
import os
import random
import sys
from datetime import datetime, timedelta, timezone

import pandas as pd

try:
    from schema import COLUMNS, TIMESTAMP_FORMAT, is_off_hours
    from pseudonymize import pseudonymize
except ImportError:
    from data.schema import COLUMNS, TIMESTAMP_FORMAT, is_off_hours
    from data.pseudonymize import pseudonymize

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
BASE_DATE = datetime(2026, 3, 2, tzinfo=timezone.utc)

SYSTEMS = ["SYS_PROD_01", "SYS_PROD_02", "SYS_PROD_03"]
KNOWN_ORIGINS = [f"NET_KNOWN_{i:02d}" for i in range(1, 21)]
NEW_ORIGINS = [f"NET_NEW_{i:02d}" for i in range(1, 41)]

LOGON_RES = ["TSO", "CICS", "SSH"]
LIST_RES = ["SYS1.PROCLIB", "USER.CATALOG", "PROD.CATALOG", "APP.CATALOG", "TEST.CATALOG"]
RACF_RES = ["RACF_USERDB", "RACF_GROUPDB", "RACF_PROFILES"]
LOW_READ_RES = ["DEV.SRC.COBOL", "TEST.DATA.SET", "APP.LOGS.DAILY", "DEV.COPYLIB", "USER.NOTES"]
MED_READ_RES = ["APP.CONFIG", "BATCH.CONTROL", "REPORTS.MONTHLY"]
HIGH_READ_RES = ["SYS1.PARMLIB", "CUSTOMER.FINANCIAL.DB", "PAYROLL.MASTER", "SYS1.RACF.DB"]
COPY_LOW_RES = ["DEV.SRC.BACKUP", "TEST.DATA.COPY"]
COPY_HIGH_RES = ["CUSTOMER.FINANCIAL.DB", "PAYROLL.MASTER", "SYS1.RACF.DB"]
JOB_RES = ["NIGHTLY.BATCH", "PAYROLL.JOB", "BACKUP.JOB", "REPORT.JOB", "DB2.UNLOAD"]
ALTUSER_RES = ["RACF_SPECIAL_ATTR", "RACF_OPER_ATTR", "RACF_AUDITOR_ATTR"]


def S(event_type, outcome, resource, sensitivity, stage, **kw):
    """One event spec; times, ids and users are filled in by materialize()."""
    d = dict(event_type=event_type, outcome=outcome, resource=resource,
             sensitivity=sensitivity, stage_label=stage)
    d.update(kw)
    return d


def _noise_spec(rng, prev):
    """Routine-looking noise event that inherits stage/system/origin from prev."""
    choice = rng.random()
    if choice < 0.5:
        s = S("JOB_SUBMIT", "SUCCESS", rng.choice(JOB_RES), "LOW", prev["stage_label"])
    elif choice < 0.85:
        s = S("DATASET_READ", "SUCCESS", rng.choice(LOW_READ_RES), "LOW", prev["stage_label"])
    else:
        s = S("DATASET_READ", "SUCCESS", rng.choice(MED_READ_RES), "MEDIUM", prev["stage_label"])
    for k in ("system", "origin"):
        if k in prev:
            s[k] = prev[k]
    return s


def add_noise(rng, specs, lo=0, hi=5):
    """Insert lo..hi noise events at random positions after the first event."""
    specs = list(specs)
    for _ in range(rng.randint(lo, hi)):
        pos = rng.randint(1, len(specs))
        specs.insert(pos, _noise_spec(rng, specs[pos - 1]))
    return specs


def materialize(rng, specs, session_id, user_raw, start, system, origin,
                scenario, gap=(5, 90)):
    """Turn specs into row dicts (event_id left None; assigned by finalize())."""
    rows, t = [], start
    for i, sp in enumerate(specs):
        if i > 0:
            t = t + timedelta(seconds=int(rng.uniform(*gap)))
        rows.append({
            "event_id": None,
            "timestamp": t.strftime(TIMESTAMP_FORMAT),
            "system_id": sp.get("system", system),
            "actor_id": pseudonymize(user_raw),
            "session_id": session_id,
            "event_type": sp["event_type"],
            "outcome": sp["outcome"],
            "resource": sp["resource"],
            "sensitivity": sp["sensitivity"],
            "origin": sp.get("origin", origin),
            "off_hours": is_off_hours(t),
            "stage_label": sp["stage_label"],
            "scenario_id": scenario,
        })
    return rows


# --- Scenario builders --------------------------------------------------------
def benign_specs(rng, night_batch=False):
    B = "BENIGN"
    specs = []
    if night_batch:
        specs.append(S("LOGON", "SUCCESS", "SSH", "LOW", B))
        for _ in range(rng.randint(2, 4)):
            specs.append(S("JOB_SUBMIT", "SUCCESS", rng.choice(JOB_RES), "LOW", B))
        specs.append(S("LOGOFF", "SUCCESS", "SSH", "LOW", B))
        return specs
    res = rng.choice(LOGON_RES)
    if rng.random() < 0.08:  # occasional password typo
        specs.append(S("LOGON", "FAILURE", res, "LOW", B))
    specs.append(S("LOGON", "SUCCESS", res, "LOW", B))
    if rng.random() < 0.7:
        specs.append(S("MFA", "SUCCESS", "MFA_PORTAL", "LOW", B))
    kinds = ["job", "read_low", "read_med", "list", "copy", "listuser", "pwd", "read_high"]
    weights = [3, 3, 1.5, 1, 1, 0.3, 0.3, 0.15]
    for _ in range(rng.randint(3, 9)):
        k = rng.choices(kinds, weights)[0]
        if k == "job":
            specs.append(S("JOB_SUBMIT", "SUCCESS", rng.choice(JOB_RES), "LOW", B))
        elif k == "read_low":
            specs.append(S("DATASET_READ", "SUCCESS", rng.choice(LOW_READ_RES), "LOW", B))
        elif k == "read_med":
            specs.append(S("DATASET_READ", "SUCCESS", rng.choice(MED_READ_RES), "MEDIUM", B))
        elif k == "list":
            specs.append(S("DATASET_LIST", "SUCCESS", rng.choice(LIST_RES), rng.choice(["LOW", "MEDIUM"]), B))
        elif k == "copy":
            specs.append(S("DATASET_COPY", "SUCCESS", rng.choice(COPY_LOW_RES), "LOW", B))
        elif k == "listuser":
            specs.append(S("RACF_LISTUSER", "SUCCESS", rng.choice(RACF_RES), "MEDIUM", B))
        elif k == "pwd":
            specs.append(S("PASSWORD_CHANGE", "SUCCESS", "RACF_PASSWORD", "LOW", B))
        else:
            specs.append(S("DATASET_READ", "SUCCESS", rng.choice(HIGH_READ_RES), "HIGH", B))
    if rng.random() < 0.85:
        specs.append(S("LOGOFF", "SUCCESS", res, "LOW", B))
    return specs


def attack_specs(rng, version, second_system):
    """attack_v1 / attack_v2 per data/event_vocab.md."""
    specs = [S("LOGON", "SUCCESS", rng.choice(LOGON_RES), "LOW", "INITIAL_ACCESS")]
    for _ in range(rng.randint(1, 3)):
        specs.append(S("MFA", "FAILURE", "MFA_PORTAL", "LOW", "CREDENTIAL_ACCESS"))
    specs.append(S("MFA", "SUCCESS", "MFA_PORTAL", "LOW", "CREDENTIAL_ACCESS"))
    for _ in range(rng.randint(2, 6)):
        if rng.random() < 0.55:
            specs.append(S("DATASET_LIST", "SUCCESS", rng.choice(LIST_RES), "MEDIUM", "DISCOVERY"))
        else:
            specs.append(S("RACF_LISTUSER", "SUCCESS", rng.choice(RACF_RES), "MEDIUM", "DISCOVERY"))
    specs.append(S("ALTUSER_SPECIAL", "SUCCESS", rng.choice(ALTUSER_RES),
                   "HIGH" if rng.random() < 0.8 else "MEDIUM", "PRIVILEGE_ESCALATION"))
    if version == "attack_v2":
        specs.append(S("LOGON", "SUCCESS", rng.choice(LOGON_RES), "LOW", "LATERAL_MOVEMENT",
                       system=second_system))
        if rng.random() < 0.5:
            specs.append(S("JOB_SUBMIT", "SUCCESS", rng.choice(JOB_RES), "MEDIUM", "LATERAL_MOVEMENT",
                           system=second_system))
        for _ in range(rng.randint(1, 3)):
            specs.append(S("DATASET_READ", "SUCCESS", rng.choice(HIGH_READ_RES), "HIGH",
                           "COLLECTION_EXFIL", system=second_system))
        if rng.random() < 0.5:
            specs.append(S("DATASET_COPY", "SUCCESS", rng.choice(COPY_HIGH_RES), "HIGH",
                           "COLLECTION_EXFIL", system=second_system))
        if rng.random() < 0.5:
            specs.append(S("JOB_SUBMIT", "SUCCESS", "DELETE.PROD.ALL", "HIGH", "IMPACT",
                           system=second_system))
    else:
        for _ in range(rng.randint(1, 3)):
            specs.append(S("DATASET_READ", "SUCCESS", rng.choice(HIGH_READ_RES), "HIGH", "COLLECTION_EXFIL"))
    return specs


def lookalike_specs(rng):
    """Legitimate admin change at night; everything BENIGN."""
    B = "BENIGN"
    res = rng.choice(LOGON_RES)
    specs = [S("LOGON", "SUCCESS", res, "LOW", B),
             S("MFA", "SUCCESS", "MFA_PORTAL", "LOW", B),
             S("ALTUSER_SPECIAL", "SUCCESS", rng.choice(ALTUSER_RES),
               "HIGH" if rng.random() < 0.5 else "MEDIUM", B)]
    for _ in range(rng.randint(2, 4)):
        if rng.random() < 0.7:
            r = rng.choice(LOW_READ_RES + MED_READ_RES)
            specs.append(S("DATASET_READ", "SUCCESS", r, "MEDIUM" if r in MED_READ_RES else "LOW", B))
        else:
            specs.append(S("JOB_SUBMIT", "SUCCESS", rng.choice(JOB_RES), "LOW", B))
    specs.append(S("LOGOFF", "SUCCESS", res, "LOW", B))
    return specs


def build_attack_rows(rng, version, session_id, user_raw, start, home_system, new_origin):
    specs = add_noise(rng, attack_specs(rng, version, second_system=_other_system(rng, home_system)))
    return materialize(rng, specs, session_id, user_raw, start, home_system, new_origin,
                       version, gap=(5, 90))


def build_lookalike_rows(rng, session_id, user_raw, start, home_system, home_origin):
    specs = add_noise(rng, lookalike_specs(rng), 0, 3)
    return materialize(rng, specs, session_id, user_raw, start, home_system, home_origin,
                       "lookalike_v1", gap=(20, 240))


def build_benign_rows(rng, session_id, user_raw, start, home_system, home_origin, night_batch=False, scenario="benign"):
    return materialize(rng, benign_specs(rng, night_batch), session_id, user_raw, start,
                       home_system, home_origin, scenario, gap=(10, 600))


def benign_offhours_specs(rng):
    """Legitimate off-hours benign sessions: night-shift logons, overnight batch jobs,
    on-call logons with no privilege change. Known origins, all labeled BENIGN."""
    B = "BENIGN"
    mode = rng.choice(["night_shift", "batch", "on_call"])
    res = rng.choice(LOGON_RES)
    specs = [S("LOGON", "SUCCESS", res, "LOW", B)]

    if mode == "night_shift":
        specs.append(S("MFA", "SUCCESS", "MFA_PORTAL", "LOW", B))
        for _ in range(rng.randint(3, 7)):
            choice = rng.random()
            if choice < 0.4:
                specs.append(S("JOB_SUBMIT", "SUCCESS", rng.choice(JOB_RES), "LOW", B))
            elif choice < 0.7:
                specs.append(S("DATASET_READ", "SUCCESS", rng.choice(LOW_READ_RES), "LOW", B))
            elif choice < 0.9:
                specs.append(S("DATASET_READ", "SUCCESS", rng.choice(MED_READ_RES), "MEDIUM", B))
            else:
                specs.append(S("DATASET_LIST", "SUCCESS", rng.choice(LIST_RES), "LOW", B))
        specs.append(S("LOGOFF", "SUCCESS", res, "LOW", B))

    elif mode == "batch":
        for _ in range(rng.randint(2, 6)):
            if rng.random() < 0.7:
                specs.append(S("JOB_SUBMIT", "SUCCESS", rng.choice(JOB_RES), "LOW", B))
            else:
                specs.append(S("DATASET_READ", "SUCCESS", rng.choice(LOW_READ_RES), "LOW", B))
        specs.append(S("LOGOFF", "SUCCESS", res, "LOW", B))

    else:  # on_call
        specs.append(S("MFA", "SUCCESS", "MFA_PORTAL", "LOW", B))
        for _ in range(rng.randint(2, 5)):
            choice = rng.random()
            if choice < 0.5:
                specs.append(S("DATASET_READ", "SUCCESS", rng.choice(LOW_READ_RES + MED_READ_RES), "LOW", B))
            elif choice < 0.8:
                specs.append(S("DATASET_LIST", "SUCCESS", rng.choice(LIST_RES), "LOW", B))
            else:
                specs.append(S("JOB_SUBMIT", "SUCCESS", rng.choice(JOB_RES), "LOW", B))
        specs.append(S("LOGOFF", "SUCCESS", res, "LOW", B))

    return specs


def build_benign_offhours_rows(rng, session_id, user_raw, start, home_system, home_origin):
    specs = add_noise(rng, benign_offhours_specs(rng), 0, 2)
    return materialize(rng, specs, session_id, user_raw, start, home_system, home_origin,
                       "benign_offhours", gap=(10, 400))


def _offhours_start(rng, day):
    hour = rng.randint(20, 23) if rng.random() < 0.4 else rng.randint(0, 5)
    return BASE_DATE + timedelta(days=day, hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))


def _other_system(rng, system):
    return rng.choice([s for s in SYSTEMS if s != system])


def _business_start(rng, day):
    return BASE_DATE + timedelta(days=day, hours=rng.randint(8, 17), minutes=rng.randint(0, 59),
                                 seconds=rng.randint(0, 59))


def _attack_start(rng, day):
    hour = rng.randint(0, 5) if rng.random() < 0.8 else rng.randint(9, 16)
    return BASE_DATE + timedelta(days=day, hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))


def _lookalike_start(rng, day):
    return BASE_DATE + timedelta(days=day, hours=2, minutes=rng.randint(-10, 10), seconds=rng.randint(0, 59))


def finalize(rows):
    """Sort by time (stable within session), assign event ids, return a DataFrame."""
    rows = sorted(rows, key=lambda r: (r["timestamp"], r["session_id"]))
    for i, r in enumerate(rows, 1):
        r["event_id"] = f"evt-{i:07d}"
    return pd.DataFrame(rows, columns=COLUMNS)


def generate(seed=42, n_benign=300, n_benign_offhours=100, n_v1=60, n_v2=60, n_look=60):
    rng = random.Random(seed)
    rows, sess_n = [], 0

    def new_sid():
        nonlocal sess_n
        sess_n += 1
        return f"sess-{sess_n:05d}"

    def profile(prefix, n):
        return f"{prefix}{n:04d}", rng.choice(KNOWN_ORIGINS), rng.choice(SYSTEMS)

    # Benign background: a pool of users with several sessions each
    n_users = max(2, (n_benign + n_benign_offhours) // 4)
    users = [profile("usr", i) for i in range(n_users)]
    for i in range(n_benign):
        user, home, system = users[i % n_users] if i < n_users else rng.choice(users)
        night = rng.random() < 0.1
        day = rng.randint(1, 60)
        start = (BASE_DATE + timedelta(days=day, hours=rng.randint(21, 23) if rng.random() < 0.5 else rng.randint(0, 4),
                                       minutes=rng.randint(0, 59))) if night else _business_start(rng, day)
        rows += build_benign_rows(rng, new_sid(), user, start, system, home, night_batch=night)

    # Legitimate off-hours benign sessions (night-shift, overnight batch, on-call)
    for i in range(n_benign_offhours):
        user, home, system = users[i % n_users] if i < n_users else rng.choice(users)
        day = rng.randint(1, 60)
        start = _offhours_start(rng, day)
        rows += build_benign_offhours_rows(rng, new_sid(), user, start, system, home)

    # Attack / look-alike actors each get an earlier benign history session
    def with_history(user, home, system, incident_start):
        hist = incident_start - timedelta(days=rng.randint(1, 7))
        hist = hist.replace(hour=rng.randint(9, 16), minute=rng.randint(0, 59))
        return build_benign_rows(rng, new_sid(), user, hist, system, home)

    for kind, n in (("attack_v1", n_v1), ("attack_v2", n_v2)):
        for i in range(n):
            user, home, system = profile("atk_" + kind[-2:] + "_", i)
            start = _attack_start(rng, rng.randint(8, 60))
            rows += with_history(user, home, system, start)
            rows += build_attack_rows(rng, kind, new_sid(), user, start, system, rng.choice(NEW_ORIGINS))
    for i in range(n_look):
        user, home, system = profile("adm_", i)
        start = _lookalike_start(rng, rng.randint(8, 60))
        rows += with_history(user, home, system, start)
        rows += build_lookalike_rows(rng, new_sid(), user, start, system, home)

    return finalize(rows)


def main():
    p = argparse.ArgumentParser(description="Threshold synthetic event generator")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--benign", type=int, default=300, help="benign sessions")
    p.add_argument("--benign-offhours", type=int, default=100, help="legitimate off-hours benign sessions")
    p.add_argument("--attack-v1", type=int, default=60)
    p.add_argument("--attack-v2", type=int, default=60)
    p.add_argument("--lookalike", type=int, default=60)
    p.add_argument("--small", action="store_true", help="tiny file (~60 rows) for quick tests")
    p.add_argument("--out", default=None, help="output CSV path")
    a = p.parse_args()

    if a.small:
        a.benign, a.benign_offhours, a.attack_v1, a.attack_v2, a.lookalike = 1, 1, 1, 1, 1
    out = a.out or os.path.join(OUT_DIR, "events_small.csv" if a.small else "events_full.csv")
    try:
        df = generate(a.seed, a.benign, a.benign_offhours, a.attack_v1, a.attack_v2, a.lookalike)
    except RuntimeError as e:  # missing THRESHOLD_HMAC_KEY
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    df.to_csv(out, index=False)
    print(f"Wrote {len(df)} events / {df['session_id'].nunique()} sessions to {out} (seed={a.seed})")
    print(df.groupby("scenario_id")["session_id"].nunique().to_string())


if __name__ == "__main__":
    main()
