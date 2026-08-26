"""
Layer 2 - Static analysis using Androguard.
Decompiles the APK (no execution involved -> safe, static-only) and extracts
manifest permissions, suspicious API/method calls, and certificate metadata.
"""

# Permissions widely treated as "dangerous" / high-risk by Android + threat intel feeds
DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.INTERNET",
    "android.permission.READ_CALL_LOG",
]

# Method/API signatures frequently abused by malware for dynamic loading,
# obfuscation, native execution, or reflection-based evasion.
SUSPICIOUS_APIS = [
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
    "Ljava/lang/Runtime;->exec",
    "Ljava/lang/reflect/Method;->invoke",
    "Landroid/telephony/SmsManager;->sendTextMessage",
    "Ljava/net/HttpURLconnection;",
    "Ljavax/crypto/Cipher;",
    "Landroid/os/Process;->killProcess",
    "Landroid/app/admin/DevicePolicyManager;",
    "Ljava/lang/System;->loadLibrary",
]


def analyze_apk(file_path: str) -> dict:
    """
    Runs Androguard against the APK and returns a structured feature dict.
    Raises RuntimeError with a readable message if the file cannot be parsed
    (corrupt / not a valid APK).
    """
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError as e:
        raise RuntimeError(
            "Androguard is not installed. Run: pip install androguard"
        ) from e

    try:
        a, d, dx = AnalyzeAPK(file_path)
    except Exception as e:
        raise RuntimeError(f"Failed to decompile APK (corrupt or invalid file): {e}")

    # ---- Manifest permissions ----
    requested_permissions = list(a.get_permissions())
    dangerous_found = [p for p in requested_permissions if p in DANGEROUS_PERMISSIONS]

    # ---- Suspicious API / method usage ----
    all_strings_seen = set()
    suspicious_found = []
    try:
        for dex in d if isinstance(d, list) else [d]:
            for method in dex.get_methods():
                mstr = str(method.get_class_name()) + str(method.get_name())
                for api in SUSPICIOUS_APIS:
                    if api in mstr:
                        suspicious_found.append(api)
    except Exception:
        # Fall back to a coarser scan over class names if method-level scan fails
        pass

    suspicious_found = sorted(set(suspicious_found))

    # ---- Metadata / certificate ----
    package_name = a.get_package()
    app_name = a.get_app_name()
    is_debuggable = a.is_debuggable() if hasattr(a, "is_debuggable") else False
    min_sdk = a.get_min_sdk_version()
    target_sdk = a.get_target_sdk_version()

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
    has_network_access = has_internet or "android.permission.ACCESS_NETWORK_STATE" in requested_permissions

    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()

    return {
        "package_name": package_name,
        "app_name": app_name,
        "requested_permissions": requested_permissions,
        "dangerous_permissions": dangerous_found,
        "num_dangerous_permissions": len(dangerous_found),
        "suspicious_apis": suspicious_found,
        "num_suspicious_apis": len(suspicious_found),
        "is_debuggable": bool(is_debuggable),
        "is_self_signed": bool(is_self_signed),
        "cert_issuer": cert_issuer,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "has_internet": has_internet,
        "has_network_access": has_network_access,
        "num_activities": len(activities),
        "num_services": len(services),
        "num_receivers": len(receivers),
    }
