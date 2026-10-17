"""
Split an events CSV into train / val / test BY SESSION (never by row),
about 70/15/15, stratified by scenario_id. Row order (time order) is kept.

Usage: python data/make_splits.py [--events data/out/events_full.csv] [--seed 42]
Writes data/out/train.csv, val.csv, test.csv
"""

import argparse
import os
import random

import pandas as pd

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")


def split_sessions(df, seed=42, ratios=(0.70, 0.15, 0.15)):
    """Return {'train': set, 'val': set, 'test': set} of session_ids."""
    rng = random.Random(seed)
    sess = df.groupby("session_id")["scenario_id"].first()
    parts = {"train": set(), "val": set(), "test": set()}
    for scenario, group in sess.groupby(sess):
        ids = sorted(group.index)
        rng.shuffle(ids)
        n = len(ids)
        n_val = round(n * ratios[1])
        n_test = round(n * ratios[2])
        if n >= 3:  # keep every scenario in every split when possible
            n_val, n_test = max(n_val, 1), max(n_test, 1)
        n_train = n - n_val - n_test
        parts["train"].update(ids[:n_train])
        parts["val"].update(ids[n_train:n_train + n_val])
        parts["test"].update(ids[n_train + n_val:])
    return parts


def main():
    p = argparse.ArgumentParser(description="Session-level train/val/test split")
    p.add_argument("--events", default=os.path.join(OUT_DIR, "events_full.csv"))
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out-dir", default=OUT_DIR)
    a = p.parse_args()

    df = pd.read_csv(a.events)
    parts = split_sessions(df, a.seed)
    os.makedirs(a.out_dir, exist_ok=True)
    for name, ids in parts.items():
        sub = df[df["session_id"].isin(ids)]
        path = os.path.join(a.out_dir, f"{name}.csv")
        sub.to_csv(path, index=False)
        print(f"{name}: {len(sub)} events, {len(ids)} sessions -> {path}")
        print("   " + ", ".join(f"{k}={v}" for k, v in sub.groupby('scenario_id')['session_id'].nunique().items()))
    assert not (parts["train"] & parts["val"] or parts["train"] & parts["test"] or parts["val"] & parts["test"])


if __name__ == "__main__":
    main()
