"""
Layer 1 - Signature-based detection.
Computes SHA-256 of the uploaded APK and queries the VirusTotal v3 API.
"""

import hashlib
import time
import requests

VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{}"


def compute_sha256(file_path: str) -> str:
    """Stream the file in chunks so large APKs don't blow up memory."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def query_virustotal(file_hash: str, api_key: str, timeout: int = 15) -> dict:
    """
    Queries VirusTotal for a known hash.

    Returns a dict:
      {"found": bool, "malicious": int, "suspicious": int, "harmless": int,
       "undetected": int, "total_engines": int, "permalink": str, "error": str|None}
    """
    if not api_key:
        return {"found": False, "error": "NO_API_KEY"}

    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(
            VT_FILE_URL.format(file_hash), headers=headers, timeout=timeout
        )
    except requests.exceptions.RequestException as e:
        return {"found": False, "error": f"NETWORK_ERROR: {e}"}

    if resp.status_code == 404:
        # Hash not present in VT's dataset -> unknown / possibly zero-day
        return {"found": False, "error": None}

    if resp.status_code == 401:
        return {"found": False, "error": "INVALID_API_KEY"}

    if resp.status_code == 429:
        return {"found": False, "error": "RATE_LIMITED"}

    if resp.status_code != 200:
        return {"found": False, "error": f"HTTP_{resp.status_code}"}

    data = resp.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": sum(stats.values()) if stats else 0,
        "meaningful_name": attrs.get("meaningful_name"),
        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
        "error": None,
    }
