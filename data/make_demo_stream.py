"""
Build demo_stream.csv: exactly ONE attack session and ONE look-alike session,
interleaved in time, with users and parameters never seen in the generator
output (different seed, different raw user names, different HMAC pseudonyms).

The attack is attack_v2 so the demo shows lateral movement.
No history sessions are added (the file holds exactly two sessions); the
first event of each session therefore looks like a "new origin" to any
history-based feature. Mentioned as a known limitation in README_data.md.

Usage: python data/make_demo_stream.py [--seed 9001] [--out data/out/demo_stream.csv]
"""

import argparse
import os
import random
import sys
from datetime import timedelta

import pandas as pd

try:
    import generate as g
except ImportError:
    from data import generate as g


def build_demo(seed=9001):
    rng = random.Random(seed)
    base_day = 89  # baseline sessions occur 1 day earlier during business hours
    day = 90       # incident sessions occur on day 90

    # 1. Establish actor profiles
    lk_origin, lk_system = rng.choice(g.KNOWN_ORIGINS), rng.choice(g.SYSTEMS)
    victim_known_origin = rng.choice(g.KNOWN_ORIGINS)
    atk_system = rng.choice(g.SYSTEMS)
    atk_new_origin = rng.choice(g.NEW_ORIGINS)

    # 2. Baseline benign sessions on day 89 (business hours, scenario_id="demo_baseline")
    lk_base_start = g._business_start(rng, base_day)
    atk_base_start = lk_base_start + timedelta(minutes=rng.randint(20, 60))

    rows = []
    # Baseline for look-alike admin on their known origin
    rows += g.build_benign_rows(
        rng, "sess-demo-lookalike-base", "demo_admin_unseen",
        lk_base_start, lk_system, lk_origin, scenario="demo_baseline"
    )
    # Baseline for attack victim on their known origin (which attack logon will NOT come from)
    rows += g.build_benign_rows(
        rng, "sess-demo-attack-base", "demo_victim_unseen",
        atk_base_start, atk_system, victim_known_origin, scenario="demo_baseline"
    )

    # 3. Incident sessions on day 90 (interleaved)
    lk_start = g._lookalike_start(rng, day)
    atk_start = lk_start + timedelta(seconds=rng.randint(20, 90))

    # Look-alike on known origin
    rows += g.build_lookalike_rows(
        rng, "sess-demo-lookalike", "demo_admin_unseen",
        lk_start, lk_system, lk_origin
    )
    # Attack on NEW origin
    rows += g.build_attack_rows(
        rng, "attack_v2", "sess-demo-attack", "demo_victim_unseen",
        atk_start, atk_system, atk_new_origin
    )

    return g.finalize(rows)


def main():
    p = argparse.ArgumentParser(description="Create demo_stream.csv")
    p.add_argument("--seed", type=int, default=9001)
    p.add_argument("--out", default=os.path.join(g.OUT_DIR, "demo_stream.csv"))
    a = p.parse_args()
    try:
        df = build_demo(a.seed)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    df.to_csv(a.out, index=False)
    print(f"Wrote {len(df)} events ({df['session_id'].nunique()} sessions) to {a.out}")

    # Unseen-user check against training data, if present
    full = os.path.join(g.OUT_DIR, "events_full.csv")
    if os.path.exists(full):
        seen = set(pd.read_csv(full, usecols=["actor_id"])["actor_id"])
        overlap = seen & set(df["actor_id"])
        print(f"Actor overlap with events_full.csv: {len(overlap)} (must be 0)")
        if overlap:
            sys.exit(1)


if __name__ == "__main__":
    main()
