"""
Community-reported scam number / fraudulent UPI ID lookup.

Uses a small local, extensible JSON-backed database (not a live crowdsourced
service - OneClick doesn't operate a backend to collect reports from other
users). Ships with a handful of illustrative example entries and is designed
to be extended with real reported numbers/VPAs over time, or pointed at an
external feed if one becomes available.

DESIGN NOTE: same flag-only philosophy - a match is a strong warning, not a
guarantee, and a "clean" result means "not found in this local list", not
"verified safe" (the number/VPA may simply not have been reported yet).
"""

import json
import os
import re

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "sample_data", "scam_reports.json")


def _load_db() -> dict:
    if not os.path.exists(DB_PATH):
        return {"phone_numbers": {}, "upi_ids": {}}
    with open(DB_PATH) as f:
        return json.load(f)


def _normalize_phone(number: str) -> str:
    digits = re.sub(r"[^0-9]", "", number)
    # Normalize Indian numbers to a bare 10-digit form for comparison
    # (strip a leading '91' country code or '0' trunk prefix if present).
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    return digits


def check_phone_number(number: str) -> dict:
    """Returns {"is_reported": bool, "category": str|None, "report_count": int, "note": str|None}."""
    db = _load_db()
    normalized = _normalize_phone(number)
    entry = db.get("phone_numbers", {}).get(normalized)
    if entry:
        return {
            "is_reported": True, "category": entry.get("category"),
            "report_count": entry.get("report_count", 1), "note": entry.get("note"),
        }
    return {"is_reported": False, "category": None, "report_count": 0, "note": None}


def check_upi_id(vpa: str) -> dict:
    """Returns {"is_reported": bool, "category": str|None, "report_count": int, "note": str|None}."""
    db = _load_db()
    entry = db.get("upi_ids", {}).get(vpa.strip().lower())
    if entry:
        return {
            "is_reported": True, "category": entry.get("category"),
            "report_count": entry.get("report_count", 1), "note": entry.get("note"),
        }
    return {"is_reported": False, "category": None, "report_count": 0, "note": None}


def add_report(kind: str, value: str, category: str, note: str = "") -> None:
    """
    Lets a user add a local report (e.g. from the UI's 'Report this number/UPI ID'
    button). This only updates OneClick's own local JSON file - it is NOT a
    shared/crowdsourced service, so reports here are only visible to this
    installation unless the file is manually shared/merged.
    """
    db = _load_db()
    key = "phone_numbers" if kind == "phone" else "upi_ids"
    value_key = _normalize_phone(value) if kind == "phone" else value.strip().lower()

    existing = db[key].get(value_key)
    if existing:
        existing["report_count"] = existing.get("report_count", 1) + 1
    else:
        db[key][value_key] = {"category": category, "report_count": 1, "note": note}

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2)
