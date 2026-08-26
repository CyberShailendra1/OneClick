"""
Data-breach exposure checker (email/password).

NOTE ON API ACCESS: HaveIBeenPwned's email-breach-lookup API now requires a
paid API key (their free tier was discontinued). This module is written
against their documented API contract and handles the auth/response format
correctly, but - like Layer 5 (dynamic analysis) - it could NOT be tested
against the live service in this environment (no API key available, and the
sandbox's network egress doesn't reach haveibeenpwned.com anyway). You'll
need your own HIBP API key (https://haveibeenpwned.com/API/Key) to use the
email-breach check; the password check below uses HIBP's free k-anonymity
endpoint, which doesn't require a key, but was likewise untestable here due
to network restrictions.
"""

import hashlib

import requests

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
HIBP_PASSWORD_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"


def check_email_breaches(email: str, api_key: str) -> dict:
    """
    Checks if an email appears in known data breaches. Requires a paid HIBP
    API key. Returns {"found": bool, "breaches": [...], "error": str|None}.
    """
    if not api_key:
        return {"found": False, "breaches": [], "error": "NO_API_KEY"}

    headers = {"hibp-api-key": api_key, "user-agent": "OneClick-Analyzer"}
    try:
        resp = requests.get(
            HIBP_BREACH_URL.format(email), headers=headers,
            params={"truncateResponse": "false"}, timeout=10,
        )
    except requests.exceptions.RequestException as e:
        return {"found": False, "breaches": [], "error": f"NETWORK_ERROR: {e}"}

    if resp.status_code == 404:
        return {"found": False, "breaches": [], "error": None}
    if resp.status_code == 401:
        return {"found": False, "breaches": [], "error": "INVALID_API_KEY"}
    if resp.status_code == 429:
        return {"found": False, "breaches": [], "error": "RATE_LIMITED"}
    if resp.status_code != 200:
        return {"found": False, "breaches": [], "error": f"HTTP_{resp.status_code}"}

    data = resp.json()
    breaches = [
        {
            "name": b.get("Name"), "domain": b.get("Domain"),
            "breach_date": b.get("BreachDate"),
            "data_classes": b.get("DataClasses", []),
        }
        for b in data
    ]
    return {"found": len(breaches) > 0, "breaches": breaches, "error": None}


def check_password_pwned(password: str) -> dict:
    """
    Checks a password against HIBP's Pwned Passwords database using
    k-anonymity: only the first 5 characters of the SHA-1 hash are sent, so
    the actual password is never transmitted. This endpoint is free and
    doesn't require an API key.
    Returns {"is_pwned": bool, "times_seen": int, "error": str|None}.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(HIBP_PASSWORD_RANGE_URL.format(prefix), timeout=10)
    except requests.exceptions.RequestException as e:
        return {"is_pwned": False, "times_seen": 0, "error": f"NETWORK_ERROR: {e}"}

    if resp.status_code != 200:
        return {"is_pwned": False, "times_seen": 0, "error": f"HTTP_{resp.status_code}"}

    for line in resp.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return {"is_pwned": True, "times_seen": int(count), "error": None}

    return {"is_pwned": False, "times_seen": 0, "error": None}
