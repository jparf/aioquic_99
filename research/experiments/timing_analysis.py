"""Timing analysis: Mann-Whitney U test + linear classifier on probe_timing_data.csv.

Reads the CSV produced by probe_timing.py (columns: hit_ns, reinsertion_ns),
runs a two-sided Mann-Whitney U test, then trains a linear classifier
(Logistic Regression) to distinguish re-insertions from hits using only the
latency value as a feature.  Performance is estimated with stratified 5-fold
cross-validation.

Usage
-----
    cd aioquic_99/research/experiments
    python3 timing_analysis.py [path/to/probe_timing_data.csv]
"""

from __future__ import annotations

import os
import sys
import csv

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import numpy as np
from scipy import stats as scipy_stats
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import (
    make_scorer,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# ---------------------------------------------------------------------------
# Load CSV
# ---------------------------------------------------------------------------

DEFAULT_CSV = os.path.join(_HERE, "probe_timing_data.csv")


def load_csv(path: str) -> tuple[np.ndarray, np.ndarray]:
    """Return (X, y) where X is shape (2N,1) latency in ns, y is 0=hit/1=reinsertion."""
    hit_ns: list[float] = []
    reins_ns: list[float] = []
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            hit_ns.append(float(row["hit_ns"]))
            reins_ns.append(float(row["reinsertion_ns"]))

    X = np.array(hit_ns + reins_ns, dtype=np.float64).reshape(-1, 1)
    y = np.array([0] * len(hit_ns) + [1] * len(reins_ns), dtype=int)
    return X, y


# ---------------------------------------------------------------------------
# Mann-Whitney U test
# ---------------------------------------------------------------------------


def run_mannwhitney(hit_ns: np.ndarray, reins_ns: np.ndarray) -> None:
    print("Mann-Whitney U test  (two-sided, H0: distributions are identical)")
    print("─" * 70)
    result = scipy_stats.mannwhitneyu(hit_ns, reins_ns, alternative="two-sided")
    u = result.statistic
    p = result.pvalue
    print(f"  U statistic : {u:.1f}")
    p_fmt = f"{p:.4f}" if p >= 0.0001 else f"{p:.2e}"
    print(f"  p-value     : {p_fmt}")
    alpha = 0.05
    if p < alpha:
        print(f"  Result      : REJECT H0 at α={alpha} — distributions are distinct")
    else:
        print(f"  Result      : FAIL TO REJECT H0 at α={alpha} — no significant difference")
    print()


# ---------------------------------------------------------------------------
# Linear classifier
# ---------------------------------------------------------------------------


def run_classifier(X: np.ndarray, y: np.ndarray, n_splits: int = 5) -> None:
    print(f"Linear Classifier  (Logistic Regression, {n_splits}-fold stratified CV)")
    print("─" * 70)
    print(f"  Feature : raw RTT latency (ns), single dimension")
    print(f"  Labels  : 0 = hit,  1 = re-insertion")
    print(f"  N       : {len(y)} samples total  ({(y == 0).sum()} hits, {(y == 1).sum()} reinsertions)")
    print()

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000)),
    ])

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    scorers = {
        "accuracy":  make_scorer(accuracy_score),
        "precision": make_scorer(precision_score, zero_division=0),
        "recall":    make_scorer(recall_score, zero_division=0),
        "f1":        make_scorer(f1_score, zero_division=0),
        "roc_auc":   make_scorer(roc_auc_score, needs_proba=True),
    }

    cv_results = cross_validate(pipeline, X, y, cv=cv, scoring=scorers, return_train_score=False)

    metrics = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    labels  = ["Accuracy", "Precision", "Recall", "F1-score", "ROC AUC"]
    for key, label in zip(metrics, labels):
        scores = cv_results[f"test_{key}"]
        print(f"  {label:<12} {np.mean(scores):.4f}  ±  {np.std(scores):.4f}  "
              f"(folds: {', '.join(f'{s:.3f}' for s in scores)})")

    print()

    # Confusion matrix from a single full fit for display purposes only.
    pipeline.fit(X, y)
    y_pred = pipeline.predict(X)
    cm = confusion_matrix(y, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print("  Confusion matrix (fit on full dataset — for display only):")
    print(f"                Predicted hit  Predicted reinsertion")
    print(f"  Actual hit         {tn:>6}             {fp:>6}")
    print(f"  Actual reinsertion {fn:>6}             {tp:>6}")
    print()

    coef = pipeline.named_steps["clf"].coef_[0][0]
    intercept = pipeline.named_steps["clf"].intercept_[0]
    scaler = pipeline.named_steps["scaler"]
    # Decision boundary in original ns units: coef * (x - mean) / std + intercept = 0
    # → x = mean - intercept * std / coef
    if coef != 0:
        boundary_ns = scaler.mean_[0] - (intercept * scaler.scale_[0] / coef)
        boundary_µs = boundary_ns / 1_000
        print(f"  Decision boundary : {boundary_ns:.0f} ns  ({boundary_µs:.2f} µs)")
        print(f"  Interpretation    : RTT > {boundary_µs:.2f} µs → classified as re-insertion")
    print()


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------


def print_summary(hit_ns: np.ndarray, reins_ns: np.ndarray) -> None:
    def _µs(ns: float) -> str:
        return f"{ns / 1_000:.2f} µs"

    def _row(label: str, arr: np.ndarray) -> None:
        print(
            f"  {label:<14} n={len(arr):>5}   "
            f"mean={_µs(arr.mean()):>10}  ±{_µs(arr.std()):>9}   "
            f"median={_µs(float(np.median(arr))):>10}   "
            f"[{_µs(arr.min())} – {_µs(arr.max())}]"
        )

    print("Summary statistics")
    print("─" * 70)
    _row("hit", hit_ns)
    _row("re-insertion", reins_ns)
    delta = reins_ns.mean() - hit_ns.mean()
    print(f"  Mean difference (re-insertion − hit): {_µs(abs(delta))}  "
          f"({'SLOWER' if delta > 0 else 'FASTER'})")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    csv_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CSV

    if not os.path.exists(csv_path):
        print(f"ERROR: CSV not found: {csv_path}")
        print("Run probe_timing.py first to generate data.")
        sys.exit(1)

    print("=" * 70)
    print(f"TIMING ANALYSIS  —  {os.path.basename(csv_path)}")
    print("=" * 70)
    print()

    X, y = load_csv(csv_path)
    hit_ns   = X[y == 0].ravel()
    reins_ns = X[y == 1].ravel()

    print_summary(hit_ns, reins_ns)
    run_mannwhitney(hit_ns, reins_ns)
    run_classifier(X, y)