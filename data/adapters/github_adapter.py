"""
Threshold: GitHub M2 Synthetic Data Adapter

Folds the 14-column GitHub telemetry (event_type + operation) into the
strict 13-column schema defined in data/schema.py.

Conversions:
- DATASET_ACCESS + LIST  -> DATASET_LIST
- DATASET_ACCESS + READ  -> DATASET_READ
- DATASET_ACCESS + COPY  -> DATASET_COPY
- DATASET_ACCESS + WRITE -> DATASET_READ
- COMMAND_EXEC           -> JOB_SUBMIT
- CRYPTO_OP              -> JOB_SUBMIT
- outcome: FAILURE       -> FAILED
- sensitivity: CRITICAL  -> HIGH, INTERNAL -> MEDIUM
- off_hours: boolean     -> 0 / 1
- Drops the 14th 'operation' column, yielding exact 13-column contract files.
"""

import os
import sys
import argparse
import pandas as pd

# Ensure repo root is in path
repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from data.schema import COLUMNS, normalize_event_type, OUTCOMES, SENSITIVITY


def normalize_outcome_val(oc: str) -> str:
    s = str(oc).strip().upper()
    if s in ["FAILURE", "FAILED", "FAIL", "DENIED"]:
        return "FAILURE"
    return "SUCCESS"


def normalize_sensitivity_val(sens: str) -> str:
    s = str(sens).strip().upper()
    if s == "CRITICAL":
        return "HIGH"
    if s == "INTERNAL":
        return "MEDIUM"
    if s in ["LOW", "MEDIUM", "HIGH"]:
        return s
    return "LOW"


def fold_row(row: dict) -> dict:
    out = dict(row)
    et = str(out.get("event_type", "")).strip().upper()
    op = str(out.get("operation", "")).strip().upper()
    oc = str(out.get("outcome", "")).strip().upper()
    sens = str(out.get("sensitivity", "")).strip().upper()
    off = out.get("off_hours", 0)

    # 1. Fold event_type + operation
    if et == "DATASET_ACCESS":
        if "LIST" in op:
            new_et = "DATASET_LIST"
        elif "COPY" in op:
            new_et = "DATASET_COPY"
        else:
            new_et = "DATASET_READ"
    elif et in ["COMMAND_EXEC", "CRYPTO_OP"]:
        new_et = "JOB_SUBMIT"
    else:
        new_et = normalize_event_type(et)
    out["event_type"] = new_et

    # 2. Normalize outcome
    out["outcome"] = normalize_outcome_val(oc)

    # 3. Normalize sensitivity
    out["sensitivity"] = normalize_sensitivity_val(sens)

    # 4. Normalize off_hours to 0 / 1 integer
    if str(off).strip().lower() in ["true", "1", "yes"]:
        out["off_hours"] = 1
    else:
        out["off_hours"] = 0

    # 5. Drop extra operation column
    if "operation" in out:
        del out["operation"]

    # Reorder exactly to 13 contract columns
    return {c: out.get(c, "") for c in COLUMNS}


def convert_file(src_path: str, dst_path: str) -> pd.DataFrame:
    df = pd.read_csv(src_path)
    converted_rows = [fold_row(row) for _, row in df.iterrows()]
    out_df = pd.DataFrame(converted_rows)[COLUMNS]
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    out_df.to_csv(dst_path, index=False)
    return out_df


def convert_all(src_dir: str, dst_dir: str):
    os.makedirs(dst_dir, exist_ok=True)
    files = [
        "demo_stream.csv",
        "train.csv",
        "validation.csv",
        "test.csv",
        "harder_test.csv",
        "rare_test.csv"
    ]
    converted_files = []
    for f in files:
        src = os.path.join(src_dir, f)
        if not os.path.exists(src):
            continue
        dst = os.path.join(dst_dir, f)
        print(f"Folding {f} -> {dst}...")
        df = convert_file(src, dst)
        converted_files.append((f, len(df), len(df.columns)))
    return converted_files


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fold GitHub synthetic data into Threshold 13-column schema")
    parser.add_argument("--src", default=os.path.join(repo_root, "data", "external", "github_m2_synthetic"))
    parser.add_argument("--dst", default=os.path.join(repo_root, "data", "external", "converted_clean"))
    args = parser.parse_args()

    results = convert_all(args.src, args.dst)
    print("\nSuccessfully converted all files:")
    for f, rows, cols in results:
        print(f"  - {f}: {rows:,} rows, {cols} columns (exact contract match)")
