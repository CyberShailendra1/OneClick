"""
Advanced Layer 2 extensions:
  - Embedded string / URL / IP extraction (possible C2 servers)
  - Obfuscation / packing detection via Shannon entropy
  - Native (.so) library inventory
  - Exported component risk check
  - Third-party SDK / ad-network / tracker fingerprinting
"""

import re
import math
import zipfile
from collections import Counter

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Known SDK / library package-prefix fingerprints (extend as needed)
KNOWN_SDKS = {
    "com/google/firebase": "Firebase",
    "com/google/android/gms/ads": "Google AdMob",
    "com/facebook/ads": "Facebook Audience Network",
    "com/unity3d/ads": "Unity Ads",
    "com/appsflyer": "AppsFlyer (tracking)",
    "com/adjust/sdk": "Adjust (tracking)",
    "com/flurry": "Flurry Analytics",
    "com/crashlytics": "Crashlytics",
    "com/mopub": "MoPub Ads",
    "com/vungle": "Vungle Ads",
    "com/inmobi": "InMobi Ads",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def extract_strings_and_iocs(file_path: str, min_len: int = 5, max_scan_bytes: int = 20_000_000) -> dict:
    """
    Extracts printable ASCII strings from the DEX/APK bytes and pulls out
    URLs / IPs that could indicate a C2 (command & control) server.
    This is a raw-bytes scan (like `strings` on Linux) — fast, no decompilation needed.
    """
    ascii_re = re.compile(rb"[ -~]{%d,}" % min_len)
    urls, ips, raw_strings = set(), set(), []

    with zipfile.ZipFile(file_path, "r") as z:
        for name in z.namelist():
            if not name.endswith(".dex"):
                continue
            data = z.read(name)[:max_scan_bytes]
            for match in ascii_re.findall(data):
                s = match.decode("ascii", errors="ignore")
                raw_strings.append(s)
                urls.update(URL_RE.findall(s))
                ips.update(IP_RE.findall(s))

    # Filter obvious false-positive IPs (versioning numbers etc. that slipped through)
    ips = {ip for ip in ips if not ip.startswith(("0.", "255."))}

    return {
        "urls_found": sorted(urls)[:50],
        "ips_found": sorted(ips)[:50],
        "num_urls": len(urls),
        "num_ips": len(ips),
    }


def detect_obfuscation(file_path: str) -> dict:
    """
    Heuristic obfuscation/packing detector based on Shannon entropy of DEX files.
    Legit, unobfuscated DEX typically sits ~5.5-6.5 bits/byte.
    Heavily obfuscated / encrypted / packed payloads often exceed ~7.2.
    """
    entropies = []
    with zipfile.ZipFile(file_path, "r") as z:
        for name in z.namelist():
            if name.endswith(".dex"):
                data = z.read(name)
                entropies.append(shannon_entropy(data))

    if not entropies:
        return {"max_entropy": 0.0, "likely_obfuscated": False, "note": "No DEX files found."}

    max_entropy = max(entropies)
    likely_obfuscated = max_entropy > 7.2

    return {
        "max_entropy": round(max_entropy, 3),
        "avg_entropy": round(sum(entropies) / len(entropies), 3),
        "likely_obfuscated": likely_obfuscated,
        "note": (
            "High entropy suggests packed/encrypted/obfuscated code — common in malware "
            "trying to evade static signature scanners."
            if likely_obfuscated else
            "Entropy is within the normal range for standard (non-packed) DEX bytecode."
        ),
    }


def inventory_native_libs(file_path: str) -> dict:
    """Lists native .so libraries bundled in lib/<abi>/ — malware sometimes hides
    payloads in native code to dodge Java/Dex-level static analysis."""
    libs = []
    with zipfile.ZipFile(file_path, "r") as z:
        for name in z.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                info = z.getinfo(name)
                libs.append({"path": name, "size_bytes": info.file_size})

    abis = sorted(set(p["path"].split("/")[1] for p in libs)) if libs else []
    return {
        "native_libs": libs[:100],
        "num_native_libs": len(libs),
        "abis_present": abis,
        "has_native_code": len(libs) > 0,
    }


def check_exported_components(androguard_apk_obj) -> dict:
    """
    Flags exported components without permission protection — a classic
    Android privilege-escalation / component-hijacking risk (not something
    VirusTotal signatures catch, since it's a config issue, not a code hash).
    """
    risky = []
    try:
        for activity in androguard_apk_obj.get_activities():
            if androguard_apk_obj.is_exported_activity(activity) if hasattr(
                androguard_apk_obj, "is_exported_activity"
            ) else False:
                risky.append({"component": activity, "type": "activity"})
    except Exception:
        pass

    # Fallback: parse manifest XML directly for exported="true" without permission
    exported_unprotected = []
    try:
        manifest_xml = androguard_apk_obj.get_android_manifest_xml()
        ns = "{http://schemas.android.com/apk/res/android}"
        for tag in ["activity", "service", "receiver", "provider"]:
            for node in manifest_xml.findall(f".//{tag}"):
                exported = node.get(f"{ns}exported")
                permission = node.get(f"{ns}permission")
                name = node.get(f"{ns}name", "unknown")
                if exported == "true" and not permission:
                    exported_unprotected.append({"component": name, "type": tag})
    except Exception:
        pass

    return {
        "exported_unprotected_components": exported_unprotected[:50],
        "num_exported_unprotected": len(exported_unprotected),
    }


def fingerprint_sdks(androguard_dex_obj) -> list:
    """Detects known third-party SDKs/ad-networks/trackers by class-name prefix."""
    found = set()
    try:
        dex_list = androguard_dex_obj if isinstance(androguard_dex_obj, list) else [androguard_dex_obj]
        for dex in dex_list:
            for cls in dex.get_classes():
                cname = cls.get_name().replace("L", "", 1).replace(";", "").replace(".", "/")
                for prefix, label in KNOWN_SDKS.items():
                    if cname.startswith(prefix):
                        found.add(label)
    except Exception:
        pass
    return sorted(found)


def run_advanced_analysis(file_path: str, androguard_apk_obj=None, androguard_dex_obj=None) -> dict:
    """Convenience wrapper that runs all advanced checks and merges results."""
    result = {}
    result["iocs"] = extract_strings_and_iocs(file_path)
    result["obfuscation"] = detect_obfuscation(file_path)
    result["native_libs"] = inventory_native_libs(file_path)

    if androguard_apk_obj is not None:
        result["exported_components"] = check_exported_components(androguard_apk_obj)
    if androguard_dex_obj is not None:
        result["detected_sdks"] = fingerprint_sdks(androguard_dex_obj)

    return result
