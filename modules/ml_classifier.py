"""
Layer 3 - AI-based threat intelligence.
Turns the Layer-2 static features into a numeric vector and scores it with a
pre-trained Random Forest Classifier. Also produces human-readable
explanations for the dashboard's "why is this flagged" panel.
"""

import os
import joblib
import numpy as np
import pandas as pd

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "rf_model.joblib")

FEATURE_NAMES = [
    "num_dangerous_permissions",
    "num_suspicious_apis",
    "is_debuggable",
    "is_self_signed",
    "has_internet",
    "num_activities",
    "num_services",
    "num_receivers",
    "has_sms_perms",
    "has_dex_loader",
    "has_overlay_perm",
    "has_accessibility_perm",
]


def _load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            "No trained model found. Run models/train_model.py first to "
            "generate models/rf_model.joblib."
        )
    return joblib.load(MODEL_PATH)


def featurize(static_features: dict) -> np.ndarray:
    perms = static_features.get("requested_permissions", [])
    apis = static_features.get("suspicious_apis", [])

    has_sms_perms = any("SMS" in p for p in perms)
    has_dex_loader = any("DexClassLoader" in a or "PathClassLoader" in a for a in apis)
    has_overlay_perm = "android.permission.SYSTEM_ALERT_WINDOW" in perms
    has_accessibility_perm = "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms

    vec = {
        "num_dangerous_permissions": static_features.get("num_dangerous_permissions", 0),
        "num_suspicious_apis": static_features.get("num_suspicious_apis", 0),
        "is_debuggable": int(static_features.get("is_debuggable", False)),
        "is_self_signed": int(static_features.get("is_self_signed", True)),
        "has_internet": int(static_features.get("has_internet", False)),
        "num_activities": static_features.get("num_activities", 0),
        "num_services": static_features.get("num_services", 0),
        "num_receivers": static_features.get("num_receivers", 0),
        "has_sms_perms": int(has_sms_perms),
        "has_dex_loader": int(has_dex_loader),
        "has_overlay_perm": int(has_overlay_perm),
        "has_accessibility_perm": int(has_accessibility_perm),
    }
    return pd.DataFrame([vec], columns=FEATURE_NAMES)


def predict_risk(static_features: dict) -> dict:
    """
    Returns:
      {"risk_score": float 0-100, "label": "Safe"|"Suspicious"|"Malicious",
       "reasons": [str, ...]}
    """
    model = _load_model()
    X = featurize(static_features)
    proba = model.predict_proba(X)[0]
    # proba[1] = probability of the "malicious" class
    malicious_idx = list(model.classes_).index(1) if 1 in model.classes_ else -1
    risk_score = float(proba[malicious_idx] * 100) if malicious_idx != -1 else float(proba[-1] * 100)

    if risk_score >= 70:
        label = "Malicious"
    elif risk_score >= 35:
        label = "Suspicious"
    else:
        label = "Safe"

    reasons = _explain(static_features, risk_score)

    return {"risk_score": round(risk_score, 1), "label": label, "reasons": reasons}


def _explain(f: dict, risk_score: float) -> list:
    reasons = []
    perms = f.get("requested_permissions", [])
    apis = f.get("suspicious_apis", [])

    if f.get("num_dangerous_permissions", 0) >= 5:
        reasons.append(
            f"Requests {f['num_dangerous_permissions']} dangerous permissions "
            f"(e.g. {', '.join(p.split('.')[-1] for p in f.get('dangerous_permissions', [])[:4])})."
        )
    elif f.get("num_dangerous_permissions", 0) > 0:
        reasons.append(
            f"Requests {f['num_dangerous_permissions']} sensitive permission(s): "
            f"{', '.join(p.split('.')[-1] for p in f.get('dangerous_permissions', []))}."
        )

    if any("SMS" in p for p in perms):
        reasons.append("Can read/send SMS messages, a common trait of banking trojans and OTP-stealers.")

    if any("DexClassLoader" in a or "PathClassLoader" in a for a in apis):
        reasons.append("Uses dynamic code loading (DexClassLoader/PathClassLoader), often used to hide payloads.")

    if any("Runtime;->exec" in a for a in apis):
        reasons.append("Calls Runtime.exec(), which can execute arbitrary shell commands.")

    if "android.permission.SYSTEM_ALERT_WINDOW" in perms:
        reasons.append("Can draw overlays on top of other apps (used in phishing/click-jacking attacks).")

    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms:
        reasons.append("Requests Accessibility Service access, which can be abused to read screen content and auto-click.")

    if f.get("is_self_signed", True) and f.get("is_debuggable", False):
        reasons.append("App is self-signed AND debuggable — unusual for a production release.")
    elif f.get("is_debuggable", False):
        reasons.append("App is marked debuggable, which is unusual for a store-released app.")

    if not f.get("has_internet", False) and f.get("num_dangerous_permissions", 0) > 0:
        reasons.append("Has dangerous permissions but no internet access, so exfiltration risk is limited — proceed with caution.")

    if not reasons:
        reasons.append("No high-risk permissions or suspicious API calls were detected during static analysis.")

    return reasons
