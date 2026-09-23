"""
Single shared pipeline function so app.py (Streamlit), api.py (FastAPI),
and batch_scan.py (CLI) all run the EXACT same logic — no duplicated/drifted
scan code across entry points.
"""

import os
import sys
from loguru import logger as _androguard_logger
_androguard_logger.remove()
_androguard_logger.add(sys.stderr, level="ERROR")  # androguard is very chatty at DEBUG/INFO

from modules.hash_scanner import compute_sha256, query_virustotal
from modules.static_analyzer import analyze_apk
from modules.ml_classifier import predict_risk, MODEL_PATH
from modules.advanced_static import run_advanced_analysis
from modules.fake_app_detector import check_fake_banking_app
from modules import database

try:
    from androguard.misc import AnalyzeAPK
    HAS_ANDROGUARD = True
except Exception:
    AnalyzeAPK = None
    HAS_ANDROGUARD = False



def scan_apk(file_path: str, filename: str, vt_api_key: str = None,
             run_advanced: bool = True, use_vt_cache: bool = True) -> dict:
    """
    Runs the full OneClick pipeline (Layers 1-3, optionally advanced Layer 2)
    on a single APK file and records it in scan history.

    Returns a dict:
      {
        "sha256": str,
        "known_threat": bool,          # True => short-circuited at Layer 1
        "vt_result": dict,
        "features": dict | None,
        "advanced": dict | None,
        "ml_result": dict | None,
        "error": str | None,
      }
    """
    result = {
        "sha256": None, "known_threat": False, "vt_result": None,
        "features": None, "advanced": None, "ml_result": None, "error": None,
    }

    sha256 = compute_sha256(file_path)
    result["sha256"] = sha256

    # ---- Layer 1 ----
    vt_result = None
    if use_vt_cache:
        vt_result = database.get_cached_vt_result(sha256)
    if vt_result is None:
        vt_result = query_virustotal(sha256, vt_api_key)
        if vt_result.get("error") is None:
            database.cache_vt_result(sha256, vt_result)
    result["vt_result"] = vt_result

    if vt_result.get("found"):
        result["known_threat"] = True
        database.save_scan(
            filename=filename, sha256=sha256, verdict="Known Threat",
            risk_score=100.0, source="virustotal", features={}, reasons=[],
        )
        return result

    # ---- Layer 2 ----
    if not HAS_ANDROGUARD or AnalyzeAPK is None:
        result["error"] = "Androguard is not installed on this system. APK decompilation is unavailable."
        return result

    try:
        a, d, dx = AnalyzeAPK(file_path)
        features = analyze_apk_from_objs(a, d)
    except Exception as e:
        result["error"] = f"Static analysis failed: {e}"
        return result
    result["features"] = features

    # ---- Fake banking/UPI app check (package/name impersonation) ----
    result["fake_app_check"] = check_fake_banking_app(
        features.get("package_name", ""), features.get("app_name", "")
    )

    # ---- Layer 2b: advanced ----
    if run_advanced:
        try:
            result["advanced"] = run_advanced_analysis(file_path, androguard_apk_obj=a, androguard_dex_obj=d)
        except Exception as e:
            result["advanced"] = {"error": str(e)}

    # ---- Layer 3 ----
    ml_result = predict_risk(features)


    # A detected banking-app impersonation is a strong, deterministic signal -
    # override the verdict rather than leaving it to the (synthetic-trained)
    # ML score alone, similar to how a known VT threat short-circuits Layer 1.
    if result["fake_app_check"]["is_suspicious"]:
        ml_result["label"] = "Malicious"
        ml_result["risk_score"] = max(ml_result["risk_score"], 95.0)
        ml_result["reasons"] = result["fake_app_check"]["reasons"] + ml_result["reasons"]

    result["ml_result"] = ml_result

    database.save_scan(
        filename=filename, sha256=sha256, verdict=ml_result["label"],
        risk_score=ml_result["risk_score"], source="ml_model",
        features=features, reasons=ml_result["reasons"],
        package_name=features.get("package_name"),
    )

    return result


def analyze_apk_from_objs(a, d) -> dict:
    """Same feature extraction as static_analyzer.analyze_apk() but reuses
    already-parsed Androguard objects instead of re-decompiling (used by the
    shared pipeline so we only call AnalyzeAPK once per file)."""
    from modules.static_analyzer import DANGEROUS_PERMISSIONS, SUSPICIOUS_APIS

    requested_permissions = list(a.get_permissions())
    dangerous_found = [p for p in requested_permissions if p in DANGEROUS_PERMISSIONS]

    suspicious_found = []
    try:
        for dex in d if isinstance(d, list) else [d]:
            for method in dex.get_methods():
                mstr = str(method.get_class_name()) + str(method.get_name())
                for api in SUSPICIOUS_APIS:
                    if api in mstr:
                        suspicious_found.append(api)
    except Exception:
        pass
    suspicious_found = sorted(set(suspicious_found))

    is_self_signed = True
    cert_issuer = "Unknown"
    try:
        certs = a.get_certificates()
        if certs:
            cert = certs[0]
            issuer = cert.issuer.human_friendly if hasattr(cert, "issuer") else "Unknown"
            subject = cert.subject.human_friendly if hasattr(cert, "subject") else "Unknown"
            cert_issuer = issuer
            is_self_signed = (issuer == subject)
    except Exception:
        pass

    has_internet = "android.permission.INTERNET" in requested_permissions

    return {
        "package_name": a.get_package(),
        "app_name": a.get_app_name(),
        "requested_permissions": requested_permissions,
        "dangerous_permissions": dangerous_found,
        "num_dangerous_permissions": len(dangerous_found),
        "suspicious_apis": suspicious_found,
        "num_suspicious_apis": len(suspicious_found),
        "is_debuggable": bool(a.is_debuggable()) if hasattr(a, "is_debuggable") else False,
        "is_self_signed": bool(is_self_signed),
        "cert_issuer": cert_issuer,
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "has_internet": has_internet,
        "num_activities": len(a.get_activities()),
        "num_services": len(a.get_services()),
        "num_receivers": len(a.get_receivers()),
    }
