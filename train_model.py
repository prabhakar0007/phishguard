#!/usr/bin/env python3
"""
Train the PhishGuard model on data/dataset.csv.

- Extracts lexical features with features.py
- Trains a RandomForest classifier
- Prints honest held-out test metrics (accuracy / precision / recall / F1)
- Saves the model bundle to model/phishguard_model.joblib
  and the metrics to model/metrics.json

Run:  python3 build_dataset.py   (once)
      python3 train_model.py
"""

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score)
from sklearn.model_selection import train_test_split

from features import FEATURE_NAMES, feature_vector

ROOT = Path(__file__).parent


def main() -> None:
    df = pd.read_csv(ROOT / "dataset.csv")
    print(f"Dataset: {len(df)} URLs "
          f"({(df.label == 1).sum()} phishing, {(df.label == 0).sum()} legit)")

    print("Extracting features...")
    X = pd.DataFrame([feature_vector(u) for u in df["url"]],
                     columns=FEATURE_NAMES)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y)
    print(f"Train: {len(X_train)}  Test: {len(X_test)}")

    model = RandomForestClassifier(
        n_estimators=300, n_jobs=-1, random_state=42,
        class_weight="balanced_subsample", min_samples_leaf=2)
    print("Training RandomForest (300 trees)...")
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    metrics = {
        "test_rows": int(len(X_test)),
        "accuracy": round(accuracy_score(y_test, pred), 4),
        "precision_phishing": round(precision_score(y_test, pred), 4),
        "recall_phishing": round(recall_score(y_test, pred), 4),
        "f1_phishing": round(f1_score(y_test, pred), 4),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
        "dataset_rows": int(len(df)),
        "features": FEATURE_NAMES,
    }
    print("\n=== HELD-OUT TEST RESULTS ===")
    print(f"Accuracy : {metrics['accuracy']:.2%}")
    print(f"Precision: {metrics['precision_phishing']:.2%} "
          "(flagged phishing me se sahi)")
    print(f"Recall   : {metrics['recall_phishing']:.2%} "
          "(asal phishing me se pakde gaye)")
    print(f"F1       : {metrics['f1_phishing']:.4f}")
    print("\n" + classification_report(y_test, pred,
                                       target_names=["legit", "phishing"]))
    print("Top features by importance:")
    importances = sorted(zip(FEATURE_NAMES, model.feature_importances_),
                         key=lambda t: -t[1])
    for name, imp in importances[:8]:
        print(f"  {name:<22} {imp:.3f}")
    metrics["top_features"] = [[n, round(float(i), 4)]
                               for n, i in importances[:10]]

    joblib.dump({"model": model, "features": FEATURE_NAMES},
                ROOT / "phishguard_model.joblib", compress=3)
    (ROOT / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nSaved model -> {ROOT / 'phishguard_model.joblib'}")
    print(f"Saved metrics -> {ROOT / 'metrics.json'}")


if __name__ == "__main__":
    main()
