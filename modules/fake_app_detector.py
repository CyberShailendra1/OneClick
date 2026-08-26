"""
Fake banking/UPI app detector.

Compares an APK's package name and app name against a curated list of
well-known Indian banking/payment apps, using the same typosquat-detection
approach as the URL phishing scanner (Levenshtein distance), to catch fake
"SBI YONO", "PhonePe", "Paytm" clones - a very common malware distribution
pattern in India (fake banking APKs sent via WhatsApp/SMS).
"""

import re

# (package prefix, app display name) for well-known Indian banking/payment apps.
# Not exhaustive - a curated starting list, intended to be extended.
KNOWN_BANKING_APPS = [
    ("com.sbi.lotusintouch", "SBI YONO"),
    ("com.sbi.SBIFreedomPlus", "SBI Freedom"),
    ("net.one97.paytm", "Paytm"),
    ("com.phonepe.app", "PhonePe"),
    ("com.google.android.apps.nbu.paisa.user", "Google Pay"),
    ("com.csam.icici.bank.imobile", "iMobile by ICICI"),
    ("com.snapwork.hdfc", "HDFC Bank"),
    ("com.axis.mobile", "Axis Mobile"),
    ("com.msf.kbank.mobile", "Kotak Mobile Banking"),
    ("com.irctc.mobile", "IRCTC Rail Connect"),
    ("in.amazon.mShop.android.shopping", "Amazon Shopping"),
    ("com.flipkart.android", "Flipkart"),
    ("com.whatsapp", "WhatsApp"),
    ("com.ubi.UnionBankMPay", "Union Bank Mobile"),
    ("com.bankofbaroda.upi", "Bank of Baroda UPI"),
]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def check_fake_banking_app(package_name: str, app_name: str) -> dict:
    """
    Returns {"is_suspicious": bool, "matched_brand": str|None, "reasons": [...]}.

    Two independent checks:
      1. Package name is close-but-not-exact to a known banking app's real
         package identifier (typosquatting at the Android package level).
      2. App display name closely matches a known bank/payment brand name,
         but the package name is completely unrelated to any known real
         package for that brand (classic "fake YONO SBI" clone pattern).
    """
    reasons = []
    matched_brand = None
    package_name = (package_name or "").lower()
    app_name_lower = (app_name or "").lower()

    known_packages = {p.lower() for p, _ in KNOWN_BANKING_APPS}

    # If this IS a known real package exactly, it's legitimate - skip both checks.
    if package_name in known_packages:
        return {"is_suspicious": False, "matched_brand": None, "reasons": []}

    # Check 1: package name typosquat
    if package_name:
        for known_pkg, brand in KNOWN_BANKING_APPS:
            known_pkg_l = known_pkg.lower()
            dist = _levenshtein(package_name, known_pkg_l)
            if 0 < dist <= 3 and abs(len(package_name) - len(known_pkg_l)) <= 4:
                matched_brand = brand
                reasons.append(
                    f"Package name '{package_name}' is suspiciously close to the real "
                    f"'{brand}' package ('{known_pkg}') - possible clone/repackaging."
                )
                break

    # Check 2: app display name claims to be a known bank (matches the FULL brand
    # name, not just a loose single-word token - avoids collisions between
    # similarly-named products from the same bank, e.g. "SBI YONO" vs "SBI Freedom").
    if not matched_brand:
        for known_pkg, brand in KNOWN_BANKING_APPS:
            if brand.lower() in app_name_lower or app_name_lower in brand.lower():
                known_pkg_l = known_pkg.lower()
                if _levenshtein(package_name, known_pkg_l) > 5:
                    matched_brand = brand
                    reasons.append(
                        f"App calls itself '{app_name}' (matching the brand '{brand}'), but its "
                        f"package name ('{package_name}') is completely unrelated to {brand}'s real "
                        f"app package ('{known_pkg}') - a strong sign of a fake/clone banking app."
                    )
                    break

    return {
        "is_suspicious": matched_brand is not None,
        "matched_brand": matched_brand,
        "reasons": reasons,
    }
