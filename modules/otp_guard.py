"""
OTP / verification-code auto-redaction.

DESIGN PRINCIPLE (same philosophy as the phishing scanner): this module only
ever MASKS sensitive codes before they're displayed, stored, or exported -
it never reads your actual phone SMS/email inbox (OneClick is a web tool,
not a native app with SMS/mail permissions). You paste a message in; you get
a redacted version back. The real code is never persisted anywhere - not in
the database, not in logs, not in any report.

Why this matters even for a pasted (not live-intercepted) message: people
often paste SMS/email text into tools (including this one, to check a link
for phishing) without noticing the message also contains a live OTP. If that
raw text then ends up in scan history, a screenshot, or a shared report, the
code is exposed. Auto-redaction closes that gap.
"""

import re

# Phrases that typically precede/follow an OTP or verification code.
# Kept broad (English-first, since Indian bank/service OTP SMS are almost
# always in English regardless of app language) but not exhaustive.
OTP_KEYWORDS = [
    "otp", "one time password", "one-time password", "one time pin", "one-time pin",
    "verification code", "security code", "auth code", "authentication code",
    "login code", "access code", "confirmation code", "passcode", "pin is",
    "code is", "your code", "use code", "use otp", "enter otp", "enter code",
    "verify with", "secret code", "transaction code", "activation code",
    # Common Hinglish phrasing (Hindi-English code-mixed messages)
    "otp hai", "code hai", "password hai", "pin hai", "otp hain",
]

# A numeric code, optionally split with a single space/dash between each
# digit (e.g. "123 456", "123-456"), 4 to 8 digits total. Anchored to digit
# boundaries only, so it can never bleed into surrounding words.
_NUMERIC_CODE = re.compile(r"\b\d(?:[ \-]?\d){3,7}\b")

# An uppercase alphanumeric code (e.g. "A3B9F2") - must contain at least one
# digit and one letter so it doesn't match plain acronyms/words.
_ALNUM_CODE = re.compile(r"\b(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{5,8}\b")

_KEYWORD_PATTERN = re.compile("|".join(re.escape(k) for k in OTP_KEYWORDS), re.IGNORECASE)

CONTEXT_WINDOW = 35  # characters to look before/after a keyword for a code


def _find_code_candidates(window: str):
    """Yields (match, kind) for both numeric and alnum code patterns in a window."""
    for m in _NUMERIC_CODE.finditer(window):
        yield m, "numeric"
    for m in _ALNUM_CODE.finditer(window):
        yield m, "alnum"


def _looks_like_code(token: str, kind: str) -> bool:
    """Numeric codes: 4-8 digits once separators are stripped.
    Alnum codes: already constrained by the regex itself (5-8 chars,
    at least one letter and one digit), so no extra filtering needed."""
    if kind == "alnum":
        return True
    digits = re.sub(r"[^0-9]", "", token)
    return 4 <= len(digits) <= 8


def detect_codes(text: str) -> list:
    """
    Returns a list of {"code": str, "start": int, "end": int, "keyword": str}
    for every code found near an OTP-related keyword. This is the only
    function that ever sees the real code value - callers should use
    redact_message() rather than surfacing this list directly to the UI.
    """
    findings = []
    for kw_match in _KEYWORD_PATTERN.finditer(text):
        window_start = max(0, kw_match.start() - CONTEXT_WINDOW)
        window_end = min(len(text), kw_match.end() + CONTEXT_WINDOW)
        window = text[window_start:window_end]

        for code_match, kind in _find_code_candidates(window):
            token = code_match.group()
            if not _looks_like_code(token, kind):
                continue
            abs_start = window_start + code_match.start()
            abs_end = window_start + code_match.end()
            # avoid re-flagging the keyword text itself if it contains digits
            if abs_start >= kw_match.start() and abs_end <= kw_match.end():
                continue
            findings.append({
                "code": token, "start": abs_start, "end": abs_end,
                "keyword": kw_match.group(),
            })

    # de-duplicate overlapping findings, keep first occurrence
    findings.sort(key=lambda f: f["start"])
    deduped = []
    last_end = -1
    for f in findings:
        if f["start"] >= last_end:
            deduped.append(f)
            last_end = f["end"]
    return deduped


def redact_message(text: str) -> dict:
    """
    Returns {"redacted_text": str, "codes_hidden": int, "keywords_matched": [...]}.
    The actual code values are NEVER included in the return value - only a
    count and the trigger keywords, so callers (UI, database, reports) can
    never accidentally leak them even if they log this result.
    """
    findings = detect_codes(text)
    if not findings:
        return {"redacted_text": text, "codes_hidden": 0, "keywords_matched": []}

    redacted = text
    # replace from the end so earlier offsets stay valid
    for f in reversed(findings):
        mask = "•" * max(len(re.sub(r"[ \-]", "", f["code"])), 4)
        redacted = redacted[:f["start"]] + f"[{mask} HIDDEN]" + redacted[f["end"]:]

    return {
        "redacted_text": redacted,
        "codes_hidden": len(findings),
        "keywords_matched": sorted({f["keyword"].lower() for f in findings}),
    }
