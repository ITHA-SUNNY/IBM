"""
Threshold Hard Test Variants Generator (M2).

Generates held-out challenge variants that do NOT appear in training data:
- attack_reordered: reordered steps (e.g. discovery before credential access)
- attack_noisy: heavy noise (6-12 benign actions interspersed)
- attack_slow_paced: slow pacing (long gaps of 15-45 minutes between steps)
- lookalike_high_read: admin reads HIGH-sensitivity dataset AFTER privilege change (all BENIGN)
- lookalike_high_altuser: admin ALTUSER_SPECIAL with HIGH sensitivity (all BENIGN)
- lookalike_batch_admin: automated scheduled admin maintenance batch job (all BENIGN)
- lookalike_helpdesk_reset: helpdesk operator performing user queries and password resets (all BENIGN)

Output: data/out/test_hard.csv
"""

import argparse
import os
import random
import sys
from datetime import datetime, timedelta, timezone

import pandas as pd

try:
    from schema import (
        COLUMNS, TIMESTAMP_FORMAT, is_off_hours
    )
    from pseudonymize import pseudonymize
    import generate as g
except ImportError:
    from data.schema import (
        COLUMNS, TIMESTAMP_FORMAT, is_off_hours
    )
    from data.pseudonymize import pseudonymize
    from data import generate as g

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
BASE_DATE = datetime(2026, 6, 1, tzinfo=timezone.utc)  # Held-out month (June 2026)


def S(event_type, outcome, resource, sensitivity, stage, **kw):
    d = dict(event_type=event_type, outcome=outcome, resource=resource,
             sensitivity=sensitivity, stage_label=stage)
    d.update(kw)
    return d


def build_attack_reordered_specs(rng, second_system):
    """Discovery sweep occurs BEFORE credential access / MFA prompt."""
    specs = [
        S("LOGON", "SUCCESS", rng.choice(g.LOGON_RES), "LOW", "INITIAL_ACCESS"),
    ]
    # Early discovery before MFA
    for _ in range(rng.randint(2, 4)):
        specs.append(S("DATASET_LIST", "SUCCESS", rng.choice(g.LIST_RES), "MEDIUM", "DISCOVERY"))
    # Then credential access
    for _ in range(rng.randint(1, 2)):
        specs.append(S("MFA", "FAILURE", "MFA_PORTAL", "LOW", "CREDENTIAL_ACCESS"))
    specs.append(S("MFA", "SUCCESS", "MFA_PORTAL", "LOW", "CREDENTIAL_ACCESS"))
    # More discovery
    for _ in range(rng.randint(1, 3)):
        specs.append(S("RACF_LISTUSER", "SUCCESS", rng.choice(g.RACF_RES), "MEDIUM", "DISCOVERY"))
    # Privilege escalation
    specs.append(S("ALTUSER_SPECIAL", "SUCCESS", rng.choice(g.ALTUSER_RES), "HIGH", "PRIVILEGE_ESCALATION"))
    # Lateral movement to second system
    specs.append(S("LOGON", "SUCCESS", rng.choice(g.LOGON_RES), "LOW", "LATERAL_MOVEMENT", system=second_system))
    # Exfiltration
    specs.append(S("DATASET_READ", "SUCCESS", rng.choice(g.HIGH_READ_RES), "HIGH", "COLLECTION_EXFIL", system=second_system))
    specs.append(S("DATASET_COPY", "SUCCESS", rng.choice(g.COPY_HIGH_RES), "HIGH", "COLLECTION_EXFIL", system=second_system))
    return specs


def build_attack_noisy_specs(rng, second_system):
    """Standard attack v2 with heavy noise (7-12 noise events interspersed)."""
    base = g.attack_specs(rng, "attack_v2", second_system=second_system)
    return g.add_noise(rng, base, lo=7, hi=12)


def build_attack_slow_specs(rng, second_system):
    """Attack with standard sequence but materialized with 900-2700s gaps."""
    return g.attack_specs(rng, "attack_v2", second_system=second_system)


def build_lookalike_high_read_specs(rng):
    """Admin off-hours: one ALTUSER_SPECIAL, followed by reading a HIGH dataset (e.g. SYS1.PARMLIB) to audit."""
    B = "BENIGN"
    res = rng.choice(g.LOGON_RES)
    specs = [
        S("LOGON", "SUCCESS", res, "LOW", B),
        S("MFA", "SUCCESS", "MFA_PORTAL", "LOW", B),
        S("ALTUSER_SPECIAL", "SUCCESS", rng.choice(g.ALTUSER_RES), "MEDIUM", B),
        # Crucial test: HIGH sensitivity read after privilege escalation!
        S("DATASET_READ", "SUCCESS", "SYS1.PARMLIB", "HIGH", B),
        S("DATASET_READ", "SUCCESS", rng.choice(g.LOW_READ_RES), "LOW", B),
        S("JOB_SUBMIT", "SUCCESS", rng.choice(g.JOB_RES), "LOW", B),
        S("LOGOFF", "SUCCESS", res, "LOW", B)
    ]
    return specs


def build_lookalike_high_altuser_specs(rng):
    """Admin off-hours: ALTUSER_SPECIAL specifically on a HIGH sensitivity resource (all BENIGN)."""
    B = "BENIGN"
    res = rng.choice(g.LOGON_RES)
    specs = [
        S("LOGON", "SUCCESS", res, "LOW", B),
        S("MFA", "SUCCESS", "MFA_PORTAL", "LOW", B),
        # Crucial test: ALTUSER_SPECIAL with HIGH sensitivity
        S("ALTUSER_SPECIAL", "SUCCESS", "RACF_SPECIAL_ATTR", "HIGH", B),
        S("DATASET_READ", "SUCCESS", rng.choice(g.LOW_READ_RES), "LOW", B),
        S("JOB_SUBMIT", "SUCCESS", rng.choice(g.JOB_RES), "LOW", B),
        S("DATASET_READ", "SUCCESS", rng.choice(g.MED_READ_RES), "MEDIUM", B),
        S("LOGOFF", "SUCCESS", res, "LOW", B)
    ]
    return specs


def build_lookalike_batch_admin_specs(rng):
    """Batch-job automated administrator maintenance (all BENIGN)."""
    B = "BENIGN"
    specs = [
        S("LOGON", "SUCCESS", "SSH", "LOW", B),
        S("JOB_SUBMIT", "SUCCESS", "SYS1.MAINT.BATCH", "MEDIUM", B),
        S("ALTUSER_SPECIAL", "SUCCESS", "RACF_OPER_ATTR", "MEDIUM", B),
        S("JOB_SUBMIT", "SUCCESS", "SYS1.INDEX.REORG", "LOW", B),
        S("DATASET_READ", "SUCCESS", rng.choice(g.LOW_READ_RES), "LOW", B),
        S("LOGOFF", "SUCCESS", "SSH", "LOW", B)
    ]
    return specs


def build_lookalike_helpdesk_reset_specs(rng):
    """Helpdesk operator: querying accounts and resetting passwords (all BENIGN)."""
    B = "BENIGN"
    res = rng.choice(g.LOGON_RES)
    specs = [
        S("LOGON", "SUCCESS", res, "LOW", B),
        S("MFA", "SUCCESS", "MFA_PORTAL", "LOW", B),
        S("RACF_LISTUSER", "SUCCESS", "RACF_USERDB", "MEDIUM", B),
        S("RACF_LISTUSER", "SUCCESS", "RACF_PROFILES", "MEDIUM", B),
        S("PASSWORD_CHANGE", "SUCCESS", "RACF_PASSWORD", "LOW", B),
        S("PERMIT", "SUCCESS", "SYS1.DEVTAB", "MEDIUM", B),
        S("LOGOFF", "SUCCESS", res, "LOW", B)
    ]
    return specs


def make_hard_variants(seed=777, n_per_variant=10):
    rng = random.Random(seed)
    rows = []
    sess_n = 0

    def new_sid(variant_name):
        nonlocal sess_n
        sess_n += 1
        return f"sess-hard-{variant_name}-{sess_n:04d}"

    # Attack Variants (each gets an earlier benign baseline session)
    attack_variants = [
        ("attack_reordered", build_attack_reordered_specs, (15, 90)),
        ("attack_noisy", build_attack_noisy_specs, (15, 90)),
        ("attack_slow_paced", build_attack_slow_specs, (600, 1800)),
    ]

    for variant_name, spec_builder, gap in attack_variants:
        for i in range(n_per_variant):
            user = f"hard_{variant_name}_{i:03d}"
            home_origin = rng.choice(g.KNOWN_ORIGINS)
            new_origin = rng.choice(g.NEW_ORIGINS)
            home_system = rng.choice(g.SYSTEMS)
            second_system = rng.choice([s for s in g.SYSTEMS if s != home_system])

            day = rng.randint(1, 20)
            base_start = BASE_DATE + timedelta(days=day, hours=rng.randint(9, 16), minutes=rng.randint(0, 59))
            atk_start = base_start + timedelta(days=rng.randint(1, 3), hours=rng.randint(0, 5))

            # 1. Baseline session (earlier, known origin)
            rows += g.build_benign_rows(rng, new_sid(f"{variant_name}-base"), user, base_start, home_system, home_origin)
            # 2. Hard attack session (new origin)
            specs = spec_builder(rng, second_system=second_system)
            rows += g.materialize(rng, specs, new_sid(variant_name), user, atk_start, home_system, new_origin,
                                 variant_name, gap=gap)

    # Look-Alike Variants (each gets an earlier benign baseline session)
    lookalike_variants = [
        ("lookalike_high_read", build_lookalike_high_read_specs, (20, 180)),
        ("lookalike_high_altuser", build_lookalike_high_altuser_specs, (20, 180)),
        ("lookalike_batch_admin", build_lookalike_batch_admin_specs, (10, 60)),
        ("lookalike_helpdesk_reset", build_lookalike_helpdesk_reset_specs, (30, 240)),
    ]

    for variant_name, spec_builder, gap in lookalike_variants:
        for i in range(n_per_variant):
            user = f"hard_{variant_name}_{i:03d}"
            home_origin = rng.choice(g.KNOWN_ORIGINS)
            home_system = rng.choice(g.SYSTEMS)

            day = rng.randint(1, 20)
            base_start = BASE_DATE + timedelta(days=day, hours=rng.randint(9, 16), minutes=rng.randint(0, 59))
            if variant_name == "lookalike_helpdesk_reset":
                # Helpdesk is during business hours
                incident_start = base_start + timedelta(days=rng.randint(1, 3), hours=rng.randint(9, 16))
            else:
                # Off-hours admin changes at ~02:00
                incident_start = base_start + timedelta(days=rng.randint(1, 3), hours=2, minutes=rng.randint(-15, 15))

            # 1. Baseline session
            rows += g.build_benign_rows(rng, new_sid(f"{variant_name}-base"), user, base_start, home_system, home_origin)
            # 2. Challenge look-alike session
            specs = spec_builder(rng)
            rows += g.materialize(rng, specs, new_sid(variant_name), user, incident_start, home_system, home_origin,
                                 variant_name, gap=gap)

    return g.finalize(rows)


def main():
    parser = argparse.ArgumentParser(description="Generate hard challenge test variants")
    parser.add_argument("--seed", type=int, default=777)
    parser.add_argument("--count", type=int, default=10, help="Sessions per variant")
    parser.add_argument("--out", default=os.path.join(OUT_DIR, "test_hard.csv"))
    args = parser.parse_args()

    df = make_hard_variants(seed=args.seed, n_per_variant=args.count)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} events / {df['session_id'].nunique()} sessions to {args.out}")
    print("\nSessions per variant:")
    print(df.groupby("scenario_id")["session_id"].nunique().to_string())


if __name__ == "__main__":
    main()
