"""
Threshold M3 Calibration Module

Implements Temperature Scaling (Guo et al. 2017) and Expected Calibration Error (ECE).
Fits separate temperature scalar T > 0 for:
  - Head 1: current_stage
  - Head 2: next_stage

Generates:
  1. model_artifacts/calibration.json
  2. model_artifacts/reliability_diagram.png
  3. Presentation-ready ECE reduction table for Datathon slides.
"""

import os
import sys
import json
import argparse
from typing import Dict, Tuple, Any, List, Optional
import numpy as np
import pandas as pd
import joblib
from scipy.optimize import minimize_scalar
from scipy.special import logsumexp, softmax
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless / server environments
import matplotlib.pyplot as plt

try:
    from features import build_windows
    from train import split_by_session
except ImportError:
    from model.features import build_windows
    from model.train import split_by_session


def compute_ece(
    probs: np.ndarray,
    labels: np.ndarray,
    n_bins: int = 10
) -> Tuple[float, Dict[str, Any]]:
    """
    Compute Expected Calibration Error (ECE) with equal-width confidence bins.
    
    Formula:
        ECE = sum_{m=1}^M (|acc(B_m) - conf(B_m)| * |B_m| / N)
        
    Args:
        probs: Array of shape (N, K) containing predicted class probabilities.
        labels: Array of shape (N,) containing ground-truth integer class indices.
        n_bins: Number of equal-width bins in [0, 1] (default 10).
        
    Returns:
        ece (float): Expected calibration error.
        details (dict): Per-bin stats for reliability diagram.
    """
    confidences = np.max(probs, axis=1)
    predictions = np.argmax(probs, axis=1)
    accuracies = (predictions == labels).astype(float)
    n_samples = len(labels)

    bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
    bin_centers = 0.5 * (bin_boundaries[:-1] + bin_boundaries[1:])
    
    bin_accs = []
    bin_confs = []
    bin_counts = []
    ece = 0.0

    for i in range(n_bins):
        low, high = bin_boundaries[i], bin_boundaries[i + 1]
        if i == n_bins - 1:
            in_bin = (confidences >= low) & (confidences <= high)
        else:
            in_bin = (confidences >= low) & (confidences < high)
            
        n_bin = np.sum(in_bin)
        bin_counts.append(int(n_bin))
        
        if n_bin > 0:
            avg_acc = float(np.mean(accuracies[in_bin]))
            avg_conf = float(np.mean(confidences[in_bin]))
            bin_accs.append(avg_acc)
            bin_confs.append(avg_conf)
            ece += np.abs(avg_acc - avg_conf) * (n_bin / n_samples)
        else:
            bin_accs.append(0.0)
            bin_confs.append(bin_centers[i])

    details = {
        "bin_boundaries": bin_boundaries.tolist(),
        "bin_centers": bin_centers.tolist(),
        "bin_accs": bin_accs,
        "bin_confs": bin_confs,
        "bin_counts": bin_counts,
        "ece": float(ece)
    }
    return float(ece), details


def fit_temperature(
    logits: np.ndarray,
    labels: np.ndarray,
    bounds: Tuple[float, float] = (0.05, 10.0)
) -> float:
    """
    Find scalar temperature T > 0 that minimizes Negative Log-Likelihood (NLL) on validation set.
    """
    n_samples = len(labels)
    y_indices = labels

    def nll_objective(T: float) -> float:
        scaled_logits = logits / max(T, 1e-6)
        log_denominators = logsumexp(scaled_logits, axis=1)
        gt_logits = scaled_logits[np.arange(n_samples), y_indices]
        return float(-np.mean(gt_logits - log_denominators))

    res = minimize_scalar(nll_objective, bounds=bounds, method="bounded")
    return float(res.x)


def apply_temperature(logits: np.ndarray, T: float) -> np.ndarray:
    """Apply temperature scaling and return calibrated softmax probabilities."""
    scaled = logits / max(T, 1e-6)
    return softmax(scaled, axis=1)


def plot_reliability_diagrams(
    current_uncal: Dict[str, Any],
    current_cal: Dict[str, Any],
    next_uncal: Dict[str, Any],
    next_cal: Dict[str, Any],
    t_current: float,
    t_next: float,
    output_path: str
):
    """
    Plot and save 2x2 comparison reliability diagrams before and after temperature scaling.
    Uses clean non-overlapping bars, shaded calibration gaps, and top-corner metrics badges.
    """
    fig, axes = plt.subplots(2, 2, figsize=(15, 12), dpi=250)
    fig.patch.set_facecolor('#ffffff')
    fig.suptitle(
        "Dual-Head Reliability & Calibration Assessment (Validation Set, 10-Bin ECE) — Threshold M3",
        fontsize=16,
        fontweight="bold",
        y=0.98,
        color="#1f2937"
    )

    plots_config = [
        (axes[0, 0], current_uncal, "Current Stage: Uncalibrated (T=1.00)", 1.00, "#ef4444"),
        (axes[0, 1], current_cal, f"Current Stage: Calibrated (T={t_current:.2f})", t_current, "#10b981"),
        (axes[1, 0], next_uncal, "Next Stage: Uncalibrated (T=1.00)", 1.00, "#f59e0b"),
        (axes[1, 1], next_cal, f"Next Stage: Calibrated (T={t_next:.2f})", t_next, "#2563eb"),
    ]

    for ax, details, title, temp, bar_color in plots_config:
        ax.set_facecolor("#fafbfc")
        centers = np.array(details["bin_centers"])
        accs = np.array(details["bin_accs"])
        confs = np.array(details["bin_confs"])
        counts = np.array(details["bin_counts"])
        ece_val = details["ece"] * 100
        
        # Plot diagonal ideal line
        ax.plot([0, 1], [0, 1], "--", color="#4b5563", linewidth=2.0, label="Perfect Calibration ($y = x$)", zorder=3)
        
        active = counts > 0
        width = 0.075

        # Shaded calibration gap
        for c, a in zip(confs[active], accs[active]):
            low = min(c, a)
            high = max(c, a)
            ax.fill_between([c - width/2, c + width/2], low, high, color="#fca5a5", alpha=0.45, hatch="//", zorder=2)
        
        # Plot empirical accuracy bars
        bars = ax.bar(confs[active], accs[active], width=width, alpha=0.85, color=bar_color, edgecolor="#1f2937", linewidth=1.2, label="Empirical Accuracy", zorder=4)
        
        if np.any(active):
            ax.scatter(confs[active], accs[active], color="#111827", s=50, zorder=6, edgecolors="white", linewidth=1.5, label="Observed (Conf, Acc)")
            
            for bar, a, cnt in zip(bars, accs[active], counts[active]):
                height = bar.get_height()
                y_pos = height + 0.02 if height < 0.90 else height - 0.06
                text_col = "#111827" if height < 0.90 else "#ffffff"
                ax.text(
                    bar.get_x() + bar.get_width() / 2.0,
                    y_pos,
                    f"{a*100:.0f}%\n(n={cnt})",
                    ha="center",
                    va="bottom" if height < 0.90 else "top",
                    fontsize=8.5,
                    fontweight="bold",
                    color=text_col,
                    zorder=7
                )

        # Sleek, single-line metrics banner in upper left (completely outside bar region)
        badge_text = f"ECE: {ece_val:.2f}%  |  Temp T = {temp:.2f}"
        ax.text(
            0.03,
            0.94,
            badge_text,
            transform=ax.transAxes,
            fontsize=10,
            fontweight="bold",
            color="#1e293b",
            bbox=dict(boxstyle="round,pad=0.45", facecolor="#ffffff", edgecolor="#cbd5e1", alpha=0.95, lw=1.2),
            zorder=8
        )

        ax.set_xlim([0.0, 1.02])
        ax.set_ylim([0.0, 1.12])
        ax.set_xlabel("Mean Confidence Score", fontsize=11, fontweight="bold", color="#334155")
        ax.set_ylabel("Empirical Accuracy", fontsize=11, fontweight="bold", color="#334155")
        ax.set_title(f"{title}", fontsize=12, fontweight="bold", pad=10, color="#1e293b")
        ax.legend(loc="lower right", fontsize=9, framealpha=0.95, facecolor="#ffffff", edgecolor="#cbd5e1")
        ax.grid(True, linestyle=":", alpha=0.5, color="#94a3b8")

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Clean, non-overlapping reliability diagram saved to: {output_path}")


def calibrate(
    events_path: Optional[str] = None,
    val_path: Optional[str] = None,
    test_path: Optional[str] = None,
    artifacts_dir: str = "model_artifacts",
    random_state: int = 42,
    next_stage_target: Optional[str] = None
):
    """
    Main calibration execution workflow.
    """
    # 1. Load trained models and metadata
    curr_model_path = os.path.join(artifacts_dir, "current_stage_model.joblib")
    next_model_path = os.path.join(artifacts_dir, "next_stage_model.joblib")
    meta_path = os.path.join(artifacts_dir, "model_metadata.json")

    if not os.path.exists(curr_model_path) or not os.path.exists(next_model_path):
        raise FileNotFoundError(f"Missing saved models in {artifacts_dir}. Run train.py first!")

    current_model = joblib.load(curr_model_path)
    next_model = joblib.load(next_model_path)
    
    with open(meta_path, "r", encoding="utf-8") as f:
        meta_info = json.load(f)
    feature_names = meta_info["feature_names"]
    window = meta_info.get("window_size", 10)
    target_mode = next_stage_target or meta_info.get("next_stage_target", "next_event")
    exclude_timing = meta_info.get("exclude_timing", False)

    # 2. Prepare validation and test splits
    if val_path and test_path and os.path.exists(val_path) and os.path.exists(test_path):
        val_df = pd.read_csv(val_path)
        test_df = pd.read_csv(test_path)
    else:
        # Split single events file
        if not events_path or not os.path.exists(events_path):
            raise FileNotFoundError(f"Cannot find events file at: {events_path}")
        events_df = pd.read_csv(events_path)
        sessions = events_df["session_id"].unique()
        
        # Multi-session split (val & test)
        if len(sessions) >= 4:
            # 50% train/val, 50% test or 3 train/val, 2 test
            train_val_df, test_df = split_by_session(events_df, test_size=0.4, random_state=random_state)
            train_df, val_df = split_by_session(train_val_df, test_size=0.5, random_state=random_state)
        else:
            val_df = events_df.copy()
            test_df = events_df.copy()

    # Build windows
    print(f"Building windows with next_stage_target={target_mode}, exclude_timing={exclude_timing}...")
    X_val, y_curr_val, y_next_val, _ = build_windows(
        val_df, window=window, next_stage_target=target_mode, exclude_timing=exclude_timing
    )
    X_test, y_curr_test, y_next_test, _ = build_windows(
        test_df, window=window, next_stage_target=target_mode, exclude_timing=exclude_timing
    )

    X_val = X_val.reindex(columns=feature_names, fill_value=0)
    X_test = X_test.reindex(columns=feature_names, fill_value=0)

    # 3. Process Current Stage Head
    print("\n-------------------------------------------------------")
    print(" Calibrating Head 1: CURRENT_STAGE")
    print("-------------------------------------------------------")
    curr_classes = list(current_model.classes_)
    class_to_idx_curr = {c: i for i, c in enumerate(curr_classes)}

    # Filter val/test samples to known classes
    val_curr_mask = y_curr_val.isin(curr_classes)
    y_curr_val_idx = np.array([class_to_idx_curr[c] for c in y_curr_val[val_curr_mask]])
    X_val_curr = X_val[val_curr_mask]

    test_curr_mask = y_curr_test.isin(curr_classes)
    y_curr_test_idx = np.array([class_to_idx_curr[c] for c in y_curr_test[test_curr_mask]])
    X_test_curr = X_test[test_curr_mask]

    # Probabilities and logits
    val_curr_probs_raw = current_model.predict_proba(X_val_curr)
    test_curr_probs_raw = current_model.predict_proba(X_test_curr)
    
    val_curr_logits = np.log(np.clip(val_curr_probs_raw, 1e-12, 1.0))
    test_curr_logits = np.log(np.clip(test_curr_probs_raw, 1e-12, 1.0))

    # Fit temperature T_curr
    t_current = fit_temperature(val_curr_logits, y_curr_val_idx)
    print(f"Optimal Temperature (Current Stage): T = {t_current:.4f}")

    val_curr_probs_cal = apply_temperature(val_curr_logits, t_current)
    test_curr_probs_cal = apply_temperature(test_curr_logits, t_current)

    curr_val_ece_before, curr_val_uncal_details = compute_ece(val_curr_probs_raw, y_curr_val_idx)
    curr_val_ece_after, curr_val_cal_details = compute_ece(val_curr_probs_cal, y_curr_val_idx)

    curr_test_ece_before, curr_test_uncal_details = compute_ece(test_curr_probs_raw, y_curr_test_idx)
    curr_test_ece_after, curr_test_cal_details = compute_ece(test_curr_probs_cal, y_curr_test_idx)

    print(f"Validation ECE: {curr_val_ece_before:.4f} -> {curr_val_ece_after:.4f} (Reduction: {(1 - curr_val_ece_after/max(curr_val_ece_before,1e-6))*100:.1f}%)")
    print(f"Test ECE:       {curr_test_ece_before:.4f} -> {curr_test_ece_after:.4f} (Reduction: {(1 - curr_test_ece_after/max(curr_test_ece_before,1e-6))*100:.1f}%)")

    # 4. Process Next Stage Head
    print("\n-------------------------------------------------------")
    print(" Calibrating Head 2: NEXT_STAGE")
    print("-------------------------------------------------------")
    next_classes = list(next_model.classes_)
    class_to_idx_next = {c: i for i, c in enumerate(next_classes)}

    val_next_mask = y_next_val.isin(next_classes)
    y_next_val_idx = np.array([class_to_idx_next[c] for c in y_next_val[val_next_mask]])
    X_val_next = X_val[val_next_mask]

    test_next_mask = y_next_test.isin(next_classes)
    y_next_test_idx = np.array([class_to_idx_next[c] for c in y_next_test[test_next_mask]])
    X_test_next = X_test[test_next_mask]

    val_next_probs_raw = next_model.predict_proba(X_val_next)
    test_next_probs_raw = next_model.predict_proba(X_test_next)

    val_next_logits = np.log(np.clip(val_next_probs_raw, 1e-12, 1.0))
    test_next_logits = np.log(np.clip(test_next_probs_raw, 1e-12, 1.0))

    # Fit temperature T_next
    t_next = fit_temperature(val_next_logits, y_next_val_idx)
    print(f"Optimal Temperature (Next Stage):    T = {t_next:.4f}")

    val_next_probs_cal = apply_temperature(val_next_logits, t_next)
    test_next_probs_cal = apply_temperature(test_next_logits, t_next)

    next_val_ece_before, next_val_uncal_details = compute_ece(val_next_probs_raw, y_next_val_idx)
    next_val_ece_after, next_val_cal_details = compute_ece(val_next_probs_cal, y_next_val_idx)

    next_test_ece_before, next_test_uncal_details = compute_ece(test_next_probs_raw, y_next_test_idx)
    next_test_ece_after, next_test_cal_details = compute_ece(test_next_probs_cal, y_next_test_idx)

    print(f"Validation ECE: {next_val_ece_before:.4f} -> {next_val_ece_after:.4f} (Reduction: {(1 - next_val_ece_after/max(next_val_ece_before,1e-6))*100:.1f}%)")
    print(f"Test ECE:       {next_test_ece_before:.4f} -> {next_test_ece_after:.4f} (Reduction: {(1 - next_test_ece_after/max(next_test_ece_before,1e-6))*100:.1f}%)")

    # 5. Save calibration.json
    cal_json_path = os.path.join(artifacts_dir, "calibration.json")
    cal_payload = {
        "model_version": meta_info.get("model_version", "m3-threshold-v1.0"),
        "current_stage": {
            "temperature": round(float(t_current), 4),
            "val_ece_before": round(float(curr_val_ece_before), 4),
            "val_ece_after": round(float(curr_val_ece_after), 4),
            "test_ece_before": round(float(curr_test_ece_before), 4),
            "test_ece_after": round(float(curr_test_ece_after), 4)
        },
        "next_stage": {
            "temperature": round(float(t_next), 4),
            "val_ece_before": round(float(next_val_ece_before), 4),
            "val_ece_after": round(float(next_val_ece_after), 4),
            "test_ece_before": round(float(next_test_ece_before), 4),
            "test_ece_after": round(float(next_test_ece_after), 4)
        }
    }

    with open(cal_json_path, "w", encoding="utf-8") as f:
        json.dump(cal_payload, f, indent=2)
    print(f"\nCalibration constants saved to: {cal_json_path}")

    # 6. Save reliability diagrams
    plot_path = os.path.join(artifacts_dir, "reliability_diagram.png")
    plot_reliability_diagrams(
        current_uncal=curr_val_uncal_details,
        current_cal=curr_val_cal_details,
        next_uncal=next_val_uncal_details,
        next_cal=next_val_cal_details,
        t_current=t_current,
        t_next=t_next,
        output_path=plot_path
    )

    # 7. Print Slide-Ready Table
    print("\n" + "=" * 80)
    print(" SLIDE-READY CALIBRATION TABLE (Copy & Paste for Datathon Presentation)")
    print("=" * 80)
    print("| Head          | Split      | ECE (Uncalibrated) | ECE (Calibrated) | Temperature (T) | ECE Reduction |")
    print("|:--------------|:-----------|:-------------------|:-----------------|:----------------|:--------------|")
    
    def row(head, split, before, after, temp):
        red = max(0.0, (1.0 - (after / max(before, 1e-6))) * 100.0)
        return f"| {head:<13} | {split:<10} | {before*100:>15.2f}% | {after*100:>14.2f}% | {temp:>15.2f} | {red:>11.1f}% |"

    print(row("Current Stage", "Validation", curr_val_ece_before, curr_val_ece_after, t_current))
    print(row("Current Stage", "Test", curr_test_ece_before, curr_test_ece_after, t_current))
    print(row("Next Stage",    "Validation", next_val_ece_before, next_val_ece_after, t_next))
    print(row("Next Stage",    "Test", next_test_ece_before, next_test_ece_after, t_next))
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="M3 Model Temperature Calibration")
    parser.add_argument("--events", default=None, help="Path to single events CSV")
    parser.add_argument("--val", default=None, help="Path to validation CSV")
    parser.add_argument("--test", default=None, help="Path to test CSV")
    parser.add_argument("--artifacts", default=None, help="Path to model artifacts directory")
    parser.add_argument("--next-target", choices=["next_event", "next_distinct"], default=None,
                        help="Target formulation for next_stage head (default: from metadata)")

    args = parser.parse_args()
    script_dir = os.path.dirname(os.path.abspath(__file__))

    events_path = args.events
    val_arg, test_arg = args.val, args.test
    if not events_path and not (val_arg and test_arg):
        # Default: M2's splits in data/out/ (relative to the repo, no absolute paths)
        data_out = os.path.join(os.path.dirname(script_dir), "data", "out")
        cand_val = os.path.join(data_out, "val.csv")
        cand_test = os.path.join(data_out, "test.csv")
        if os.path.exists(cand_val) and os.path.exists(cand_test):
            val_arg, test_arg = cand_val, cand_test
        else:
            events_path = os.path.join(script_dir, "sample_events.csv")

    artifacts_dir = args.artifacts
    if not artifacts_dir:
        artifacts_dir = os.path.join(script_dir, "model_artifacts")

    calibrate(
        events_path=events_path,
        val_path=val_arg,
        test_path=test_arg,
        artifacts_dir=artifacts_dir,
        random_state=42,
        next_stage_target=args.next_target
    )


if __name__ == "__main__":
    main()
