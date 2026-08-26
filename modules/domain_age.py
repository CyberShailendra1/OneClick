"""
Domain age (WHOIS) check.

Phishing domains are almost always registered very recently - often just
hours or days before a campaign launches, since registrars/blocklists catch
up quickly. A domain's age is a strong, independent signal that doesn't rely
on VirusTotal already having seen the URL.

NOTE: WHOIS lookups depend on an external WHOIS server being reachable from
wherever OneClick is deployed. In network-restricted environments (locked-down
corporate networks, some sandboxes/CI runners) WHOIS (port 43) may be blocked
even when HTTP(S) isn't - if so, this check degrades gracefully and reports
"unknown" rather than failing the whole scan.
"""

from datetime import datetime, timezone

import whois as _whois


def check_domain_age(domain: str) -> dict:
    """
    Returns {"available": bool, "creation_date": str|None, "age_days": int|None,
              "is_newly_registered": bool, "reason": str|None, "error": str|None}
    """
    try:
        w = _whois.whois(domain, timeout=6)
    except Exception as e:
        return {
            "available": False, "creation_date": None, "age_days": None,
            "is_newly_registered": False, "reason": None,
            "error": f"WHOIS lookup failed (server unreachable or domain not found): {e}",
        }

    creation = w.creation_date
    if isinstance(creation, list):
        creation = creation[0] if creation else None

    if creation is None:
        return {
            "available": False, "creation_date": None, "age_days": None,
            "is_newly_registered": False, "reason": None,
            "error": "WHOIS record has no creation date (privacy-protected or unsupported TLD).",
        }

    if creation.tzinfo is None:
        creation = creation.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - creation).days

    is_new = age_days < 30
    reason = None
    if age_days < 7:
        reason = f"Domain was registered only {age_days} day(s) ago - extremely common for throwaway phishing sites."
    elif is_new:
        reason = f"Domain was registered {age_days} days ago - still quite new; treat with extra caution."

    return {
        "available": True, "creation_date": creation.isoformat(), "age_days": age_days,
        "is_newly_registered": is_new, "reason": reason, "error": None,
    }
