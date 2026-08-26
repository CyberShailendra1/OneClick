"""
Model-driven explainability using SHAP, as an upgrade over the hand-written
rule-based reasons in ml_classifier.py. SHAP tells you exactly how much each
feature pushed THIS specific prediction toward "malicious" vs "benign",
rather than relying on a fixed if/else rulebook.

This is intentionally a separate, optional module: if `shap` isn't installed
or errors out for some reason, the app should keep working using the
rule-based explanations in ml_classifier.py.
"""

from modules.ml_classifier import FEATURE_NAMES, _load_model, featurize

_explainer_cache = {"explainer": None, "model_id": None}


def _get_explainer(model):
    """Cache the SHAP TreeExplainer so we don't rebuild it on every scan."""
    import shap
    if _explainer_cache["explainer"] is None or _explainer_cache["model_id"] != id(model):
        _explainer_cache["explainer"] = shap.TreeExplainer(model)
        _explainer_cache["model_id"] = id(model)
    return _explainer_cache["explainer"]


def explain_with_shap(static_features: dict, top_k: int = 6) -> list:
    """
    Returns a ranked list of {"feature", "value", "impact", "direction"} dicts
    describing which features pushed the prediction toward malicious ("+") or
    benign ("-"), ordered by absolute impact.
    """
    model = _load_model()
    X = featurize(static_features)
    explainer = _get_explainer(model)

    shap_values = explainer.shap_values(X)

    # shap_values shape differs across sklearn/shap versions for binary RF:
    # could be a list [class0_vals, class1_vals] or a single 2D/3D array.
    if isinstance(shap_values, list):
        values = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
    else:
        arr = shap_values
        if arr.ndim == 3:  # (n_samples, n_features, n_classes)
            values = arr[0, :, 1]
        else:
            values = arr[0]

    impacts = []
    for name, val, feat_value in zip(FEATURE_NAMES, values, X.iloc[0].values):
        impacts.append({
            "feature": name,
            "value": feat_value,
            "impact": round(float(val), 4),
            "direction": "toward malicious" if val > 0 else "toward benign",
        })

    impacts.sort(key=lambda x: abs(x["impact"]), reverse=True)
    return impacts[:top_k]


def explain_readable(static_features: dict, top_k: int = 6) -> list:
    """Human-readable sentences built from SHAP impacts, for the dashboard."""
    friendly_names = {
        "num_dangerous_permissions": "number of dangerous permissions requested",
        "num_suspicious_apis": "number of suspicious API calls (e.g. DexClassLoader)",
        "is_debuggable": "app being marked debuggable",
        "is_self_signed": "self-signed certificate",
        "has_internet": "internet access permission",
        "num_activities": "number of activities",
        "num_services": "number of background services",
        "num_receivers": "number of broadcast receivers",
        "has_sms_perms": "SMS read/send permission",
        "has_dex_loader": "dynamic code loading (DexClassLoader)",
        "has_overlay_perm": "screen overlay permission",
        "has_accessibility_perm": "accessibility service access",
    }
    try:
        impacts = explain_with_shap(static_features, top_k=top_k)
    except Exception as e:
        return [f"(SHAP explainability unavailable: {e})"]

    sentences = []
    for item in impacts:
        if abs(item["impact"]) < 0.001:
            continue
        name = friendly_names.get(item["feature"], item["feature"])
        sentences.append(
            f"{name} (value={item['value']}) pushed the score {item['direction']} "
            f"(impact {item['impact']:+.3f})"
        )
    return sentences or ["No individual feature had a strong influence on this prediction."]
