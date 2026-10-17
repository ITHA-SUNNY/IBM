"""
Threshold M3 Training Pipeline

Trains dual-head classifiers:
  - Head 1: current_stage
  - Head 2: next_stage

Compares Logistic Regression vs LightGBM (with graceful sklearn fallback).
Picks the best model by validation Macro-F1.
Strictly splits by session_id to prevent window leakage across splits.
Saves model artifacts with joblib to model_artifacts/.
"""

import os
import sys
import json
import argparse
from typing import Dict, Tuple, Any, List, Optional
import numpy as np
import pandas as pd
import joblib

from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split

# Import feature extractor from local module
try:
    from features import build_windows
except ImportError:
    from model.features import build_windows

# Check LightGBM availability
try:
    import lightgbm as lgb
    from lightgbm import LGBMClassifier
    HAS_LIGHTGBM = True
except (ImportError, Exception):
    HAS_LIGHTGBM = False


# Stages come from data/schema.py (single source of truth). features.py puts the
# repo root on sys.path, so this import works from `python model/train.py` too.
from data.schema import STAGES  # noqa: E402

FIXED_STAGES = list(STAGES)


def split_by_session(df: pd.DataFrame, test_size: float = 0.25, random_state: int = 42) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Split events DataFrame by session_id so that windows from one session
    never leak across train and validation splits.
    """
    sessions = df["session_id"].unique()
    
    # If very few sessions, ensure at least 1 in val and 1+ in train
    if len(sessions) <= 2:
        train_sess = sessions[:1]
        val_sess = sessions[1:]
    else:
        # Check if we can stratify by whether session contains attack events
        attack_sessions = set(df[df["stage_label"] != "BENIGN"]["session_id"].unique())
        labels = [1 if s in attack_sessions else 0 for s in sessions]
        
        # Stratified split if multiple classes present, else simple split
        if len(set(labels)) > 1 and min(pd.Series(labels).value_counts()) >= 2:
            train_sess, val_sess = train_test_split(
                sessions, test_size=test_size, random_state=random_state, stratify=labels
            )
        else:
            train_sess, val_sess = train_test_split(
                sessions, test_size=test_size, random_state=random_state
            )

    train_df = df[df["session_id"].isin(train_sess)].copy()
    val_df = df[df["session_id"].isin(val_sess)].copy()
    
    return train_df, val_df


def train_and_evaluate_head(
    head_name: str,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    random_state: int = 42
) -> Tuple[Any, str, Dict[str, Any]]:
    """
    Train candidate models (Logistic Regression vs LightGBM), evaluate on validation,
    and pick the winner by validation Macro-F1.
    """
    print(f"\n=======================================================")
    print(f" Training Head: {head_name.upper()}")
    print(f" Train samples: {len(X_train)}, Validation samples: {len(X_val)}")
    print(f" Classes in train: {sorted(list(y_train.unique()))}")
    print(f" Classes in val:   {sorted(list(y_val.unique()))}")
    print(f"=======================================================")

    candidates: Dict[str, Any] = {}

    # 1. Logistic Regression Pipeline (StandardScaler + Balanced LR)
    lr_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            max_iter=1000,
            random_state=random_state,
            class_weight="balanced",
            solver="lbfgs"
        ))
    ])
    candidates["LogisticRegression"] = lr_pipe

    # 2. LightGBM (or Sklearn RandomForest fallback)
    if HAS_LIGHTGBM:
        lgb_clf = LGBMClassifier(
            random_state=random_state,
            class_weight="balanced",
            n_estimators=50,
            min_child_samples=1,
            learning_rate=0.05,
            verbose=-1
        )
        candidates["LightGBM"] = lgb_clf
    else:
        print("[INFO] LightGBM not installed; using RandomForestClassifier as gradient/tree candidate.")
        rf_clf = RandomForestClassifier(
            random_state=random_state,
            class_weight="balanced",
            n_estimators=50,
            min_samples_split=2
        )
        candidates["RandomForest"] = rf_clf

    results: Dict[str, Dict[str, Any]] = {}
    best_model_name = None
    best_macro_f1 = -1.0
    best_model = None

    for name, model in candidates.items():
        try:
            model.fit(X_train, y_train)
            val_preds = model.predict(X_val)

            acc = accuracy_score(y_val, val_preds)
            macro_f1 = f1_score(y_val, val_preds, average="macro", zero_division=0)
            
            # Confusion matrix
            labels_union = sorted(list(set(y_val.unique()).union(set(val_preds))))
            cm = confusion_matrix(y_val, val_preds, labels=labels_union)

            results[name] = {
                "accuracy": float(acc),
                "macro_f1": float(macro_f1),
                "labels": labels_union,
                "confusion_matrix": cm.tolist(),
                "model": model
            }

            print(f"\n  Candidate [{name}]:")
            print(f"    - Accuracy: {acc:.4f}")
            print(f"    - Macro-F1: {macro_f1:.4f}")

            if macro_f1 > best_macro_f1:
                best_macro_f1 = macro_f1
                best_model_name = name
                best_model = model

        except Exception as e:
            print(f"  [WARNING] Candidate {name} failed: {e}")

    # Fallback if tie or issue
    if best_model is None:
        best_model_name = "LogisticRegression"
        best_model = candidates["LogisticRegression"]
        best_model.fit(X_train, y_train)

    print(f"\n >>> Selected for {head_name}: {best_model_name} (Macro-F1: {best_macro_f1:.4f})")
    
    # Print Confusion Matrix for best model
    best_info = results[best_model_name]
    print(f"\nConfusion Matrix for {head_name} ({best_model_name}):")
    labels = best_info["labels"]
    cm = np.array(best_info["confusion_matrix"])
    print(f"{'':>25} | " + " | ".join(f"{lbl:>12}" for lbl in labels))
    print("-" * (27 + 15 * len(labels)))
    for i, actual in enumerate(labels):
        row_str = " | ".join(f"{cm[i, j]:>12}" for j in range(len(labels)))
        print(f"{actual:>25} | {row_str}")

    return best_model, best_model_name, results[best_model_name]


def train(
    events_path: Optional[str] = None,
    train_path: Optional[str] = None,
    val_path: Optional[str] = None,
    artifacts_dir: str = "model_artifacts",
    window: int = 10,
    random_state: int = 42,
    next_stage_target: str = "next_event",
    exclude_timing: bool = False
):
    """
    Main training execution function.
    """
    os.makedirs(artifacts_dir, exist_ok=True)

    # 1. Load data
    presplit = bool(train_path and val_path and os.path.exists(train_path) and os.path.exists(val_path))
    if presplit:
        print(f"Loading separate train/val files:\n  Train: {train_path}\n  Val:   {val_path}")
        train_events = pd.read_csv(train_path)
        val_events = pd.read_csv(val_path)
    else:
        if not events_path or not os.path.exists(events_path):
            raise FileNotFoundError(f"Cannot find events file at: {events_path}")
        print(f"Loading single events file: {events_path}")
        events_df = pd.read_csv(events_path)
        print(f"Splitting {len(events_df)} events by session_id (never by row)...")
        train_events, val_events = split_by_session(events_df, test_size=0.3, random_state=random_state)

    print(f"Train sessions: {train_events['session_id'].nunique()}, events: {len(train_events)}")
    print(f"Val sessions:   {val_events['session_id'].nunique()}, events: {len(val_events)}")

    # 2. Build feature windows
    print(f"\nExtracting sliding window features (next_target={next_stage_target}, exclude_timing={exclude_timing})...")
    X_train, y_curr_train, y_next_train, meta_train = build_windows(
        train_events, window=window, next_stage_target=next_stage_target, exclude_timing=exclude_timing
    )
    X_val, y_curr_val, y_next_val, meta_val = build_windows(
        val_events, window=window, next_stage_target=next_stage_target, exclude_timing=exclude_timing
    )

    # Align feature columns between train and val
    all_feature_cols = sorted(list(set(X_train.columns).union(set(X_val.columns))))
    X_train = X_train.reindex(columns=all_feature_cols, fill_value=0)
    X_val = X_val.reindex(columns=all_feature_cols, fill_value=0)

    # 3. Train Head 1: current_stage
    current_model, current_type, current_metrics = train_and_evaluate_head(
        head_name="current_stage",
        X_train=X_train,
        y_train=y_curr_train,
        X_val=X_val,
        y_val=y_curr_val,
        random_state=random_state
    )

    # 4. Train Head 2: next_stage
    next_model, next_type, next_metrics = train_and_evaluate_head(
        head_name="next_stage",
        X_train=X_train,
        y_train=y_next_train,
        X_val=X_val,
        y_val=y_next_val,
        random_state=random_state
    )

    # 5. Final fit. With M2's pre-made splits the models stay trained on TRAIN ONLY so the
    #    validation set remains held-out for calibration (temperature fitting) and honest ECE.
    #    Only in single-file mode (tiny sample data) do we refit on everything for class coverage.
    if not presplit:
        print("\nRefitting selected model architectures on complete dataset for maximum coverage...")
        X_all = pd.concat([X_train, X_val], ignore_index=True)
        y_curr_all = pd.concat([y_curr_train, y_curr_val], ignore_index=True)
        y_next_all = pd.concat([y_next_train, y_next_val], ignore_index=True)

        current_model.fit(X_all, y_curr_all)
        next_model.fit(X_all, y_next_all)
    else:
        print("\nPre-made splits used: keeping models fitted on train only (val stays held-out).")

    # 6. Save models with joblib
    curr_model_path = os.path.join(artifacts_dir, "current_stage_model.joblib")
    next_model_path = os.path.join(artifacts_dir, "next_stage_model.joblib")
    meta_path = os.path.join(artifacts_dir, "model_metadata.json")

    joblib.dump(current_model, curr_model_path)
    joblib.dump(next_model, next_model_path)

    metadata_payload = {
        "model_version": "m3-threshold-v1.0",
        "random_state": random_state,
        "window_size": window,
        "next_stage_target": next_stage_target,
        "exclude_timing": exclude_timing,
        "feature_names": all_feature_cols,
        "current_stage": {
            "model_type": current_type,
            "classes": [str(c) for c in current_model.classes_],
            "val_accuracy": current_metrics["accuracy"],
            "val_macro_f1": current_metrics["macro_f1"]
        },
        "next_stage": {
            "model_type": next_type,
            "classes": [str(c) for c in next_model.classes_],
            "val_accuracy": next_metrics["accuracy"],
            "val_macro_f1": next_metrics["macro_f1"]
        }
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata_payload, f, indent=2)

    print(f"\n=======================================================")
    print(f" Training Complete!")
    print(f" Artifacts saved to: {os.path.abspath(artifacts_dir)}")
    print(f"  - {curr_model_path}")
    print(f"  - {next_model_path}")
    print(f"  - {meta_path}")
    print(f"=======================================================")


def main():
    parser = argparse.ArgumentParser(description="M3 Model Training Pipeline")
    parser.add_argument("--events", default=None, help="Path to single events CSV (default: sample_events.csv)")
    parser.add_argument("--train", default=None, help="Path to train CSV")
    parser.add_argument("--val", default=None, help="Path to validation CSV")
    parser.add_argument("--artifacts", default=None, help="Directory to save model artifacts")
    parser.add_argument("--window", type=int, default=10, help="Sliding window size N (default: 10)")
    parser.add_argument("--next-target", choices=["next_event", "next_distinct"], default="next_event",
                        help="Target definition for next_stage head: next_event or next_distinct (default: next_event)")
    parser.add_argument("--exclude-timing", action="store_true",
                        help="Exclude timing features (seconds_since_session_start, mean_gap_seconds, last_gap_seconds)")
    
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    events_path = args.events
    train_arg, val_arg = args.train, args.val
    if not events_path and not (train_arg and val_arg):
        # Default: M2's splits in data/out/ (relative to the repo, no absolute paths)
        data_out = os.path.join(os.path.dirname(script_dir), "data", "out")
        cand_train = os.path.join(data_out, "train.csv")
        cand_val = os.path.join(data_out, "val.csv")
        if os.path.exists(cand_train) and os.path.exists(cand_val):
            train_arg, val_arg = cand_train, cand_val
        else:
            events_path = os.path.join(script_dir, "sample_events.csv")

    artifacts_dir = args.artifacts
    if not artifacts_dir:
        artifacts_dir = os.path.join(script_dir, "model_artifacts")

    train(
        events_path=events_path,
        train_path=train_arg,
        val_path=val_arg,
        artifacts_dir=artifacts_dir,
        window=args.window,
        random_state=42,
        next_stage_target=args.next_target,
        exclude_timing=args.exclude_timing
    )


if __name__ == "__main__":
    main()
