"""
Trains the Layer-3 Random Forest Classifier.

IMPORTANT / HONESTY NOTE:
No real labeled malware/benign dataset was provided with this project. This
script generates a SYNTHETIC dataset built from well-documented malware
behavior patterns (SMS abuse, dynamic code loading, overlay attacks,
accessibility-service abuse, self-signed+debuggable certs, etc.) so the app
is runnable end-to-end out of the box.

For real-world accuracy you MUST retrain on a real dataset, e.g.:
  - CICMalDroid 2020 (Canadian Institute for Cybersecurity)
  - Drebin dataset
  - AndroZoo (with VirusTotal labels)
Replace `build_synthetic_dataset()` with a loader for your real feature CSV
(same column layout as FEATURE_NAMES in modules/ml_classifier.py) and rerun
this script.
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report
import joblib

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from modules.ml_classifier import FEATURE_NAMES  # noqa: E402

RNG = np.random.default_rng(42)
N_SAMPLES = 2000


def build_synthetic_dataset(n=N_SAMPLES) -> pd.DataFrame:
    rows = []
    for i in range(n):
        is_malicious = RNG.random() < 0.5

        if is_malicious:
            num_dangerous_perms = RNG.integers(3, 14)
            num_suspicious_apis = RNG.integers(1, 6)
            is_debuggable = RNG.random() < 0.35
            is_self_signed = RNG.random() < 0.85
            has_internet = RNG.random() < 0.9
            num_activities = RNG.integers(1, 8)
            num_services = RNG.integers(1, 6)
            num_receivers = RNG.integers(1, 6)
            has_sms_perms = RNG.random() < 0.55
            has_dex_loader = RNG.random() < 0.45
            has_overlay_perm = RNG.random() < 0.4
            has_accessibility_perm = RNG.random() < 0.3
        else:
            num_dangerous_perms = RNG.integers(0, 4)
            num_suspicious_apis = RNG.integers(0, 2)
            is_debuggable = RNG.random() < 0.05
            is_self_signed = RNG.random() < 0.5
            has_internet = RNG.random() < 0.6
            num_activities = RNG.integers(2, 15)
            num_services = RNG.integers(0, 3)
            num_receivers = RNG.integers(0, 3)
            has_sms_perms = RNG.random() < 0.05
            has_dex_loader = RNG.random() < 0.03
            has_overlay_perm = RNG.random() < 0.05
            has_accessibility_perm = RNG.random() < 0.03

        rows.append({
            "num_dangerous_permissions": num_dangerous_perms,
            "num_suspicious_apis": num_suspicious_apis,
            "is_debuggable": int(is_debuggable),
            "is_self_signed": int(is_self_signed),
            "has_internet": int(has_internet),
            "num_activities": num_activities,
            "num_services": num_services,
            "num_receivers": num_receivers,
            "has_sms_perms": int(has_sms_perms),
            "has_dex_loader": int(has_dex_loader),
            "has_overlay_perm": int(has_overlay_perm),
            "has_accessibility_perm": int(has_accessibility_perm),
            "label": int(is_malicious),
        })
    return pd.DataFrame(rows)


def load_dataset(csv_path: str = None) -> pd.DataFrame:
    """
    If --csv is given, load a REAL labeled dataset (must contain all
    FEATURE_NAMES columns + a 'label' column: 1=malicious, 0=benign).
    Otherwise falls back to the synthetic dataset (demo/dev only).
    """
    if csv_path:
        df = pd.read_csv(csv_path)
        missing = [c for c in FEATURE_NAMES + ["label"] if c not in df.columns]
        if missing:
            raise ValueError(f"CSV is missing required columns: {missing}")
        print(f"Loaded REAL dataset from {csv_path} ({len(df)} rows)")
        return df

    df = build_synthetic_dataset()
    out_path = os.path.join(os.path.dirname(__file__), "..", "sample_data", "training_data.csv")
    df.to_csv(out_path, index=False)
    print(f"⚠️  No --csv given — using SYNTHETIC demo data ({len(df)} rows), written to {out_path}")
    print("    For real-world accuracy, retrain with: python train_model.py --csv your_real_dataset.csv")
    return df


def main():
    parser = argparse.ArgumentParser(description="Train the OneClick Layer-3 classifier.")
    parser.add_argument("--csv", type=str, default=None,
                         help="Path to a real labeled dataset CSV (columns: FEATURE_NAMES + 'label').")
    parser.add_argument("--model", type=str, default="rf", choices=["rf", "xgboost"],
                         help="Which model to train (default: rf).")
    args = parser.parse_args()

    df = load_dataset(args.csv)

    X = df[FEATURE_NAMES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    if args.model == "xgboost":
        if not HAS_XGBOOST:
            print("xgboost not installed (pip install xgboost). Falling back to Random Forest.")
            args.model = "rf"
        else:
            clf = XGBClassifier(
                n_estimators=300,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                eval_metric="logloss",
            )

    if args.model == "rf":
        clf = RandomForestClassifier(
            n_estimators=300,
            max_depth=12,
            min_samples_leaf=3,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1,
        )

    clf.fit(X_train, y_train)

    cv_scores = cross_val_score(clf, X, y, cv=5)
    print(f"5-fold CV accuracy: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")

    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    model_path = os.path.join(os.path.dirname(__file__), "rf_model.joblib")
    joblib.dump(clf, model_path)
    print(f"Model saved to {model_path}")

    importances = sorted(
        zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: -x[1]
    )
    print("\nFeature importances:")
    for name, imp in importances:
        print(f"  {name:30s} {imp:.3f}")


if __name__ == "__main__":
    main()
