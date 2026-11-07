#!/usr/bin/env python3
"""
PhishGuard — web app (Flask).

  GET  /           -> checker UI
  POST /api/check  -> {"url": "..."} JSON verdict:
                      verdict, phishing_probability (0-1), risk level,
                      human-readable reasons

Run:  pip install -r requirements.txt
      python3 train_model.py     (once, creates the model file)
      python3 app.py             (http://127.0.0.1:5000)
"""

import json
from pathlib import Path

import joblib
import pandas as pd
from flask import Flask, jsonify, render_template, request

from features import explain, extract_features

ROOT = Path(__file__).parent
app = Flask(__name__, template_folder=".")

_bundle = joblib.load(ROOT / "phishguard_model.joblib")
MODEL = _bundle["model"]
FEATURES = _bundle["features"]
METRICS = json.loads((ROOT / "metrics.json").read_text())


def check_url(url: str) -> dict:
    feats = extract_features(url)
    X = pd.DataFrame([[feats[f] for f in FEATURES]], columns=FEATURES)
    prob = float(MODEL.predict_proba(X)[0][1])
    reasons = explain(url)

    if prob >= 0.65:
        verdict, level = "PHISHING", "high"
        if not reasons:
            reasons.append("Model ko is link ke kai patterns phishing jaise "
                           "lage hain.")
    elif prob >= 0.40:
        verdict, level = "SUSPICIOUS", "medium"
        if not reasons:
            reasons.append("Kuch patterns ajeeb hain — bina jaanch ke login "
                           "ya payment mat karo.")
    else:
        verdict, level = "LIKELY SAFE", "low"
        reasons = reasons or ["Koi bada khatre wala pattern nahi mila. "
                              "Phir bhi, anjaan link par hamesha dhyaan do."]

    return {
        "url": url,
        "verdict": verdict,
        "risk_level": level,
        "phishing_probability": round(prob, 4),
        "risk_percent": round(prob * 100, 1),
        "reasons": reasons,
    }


@app.get("/")
def home():
    return render_template("index.html", metrics=METRICS)


@app.post("/api/check")
def api_check():
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL too long"}), 400
    return jsonify(check_url(url))


@app.get("/api/metrics")
def api_metrics():
    return jsonify(METRICS)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
