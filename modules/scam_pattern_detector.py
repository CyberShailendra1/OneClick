"""
Scam-script pattern detector.

Detects common social-engineering templates used in scam calls/messages -
"digital arrest", fake courier/customs holds, lottery/prize scams, fake job
offers, tech-support scams, etc. Same keyword-anchored, flag-only philosophy
as the rest of OneClick: this only surfaces a warning with the matched
pattern, never blocks or deletes anything.
"""

import re

# Each entry: (category label, [trigger phrases], explanation shown to the user)
SCAM_PATTERNS = [
    (
        "Digital Arrest / Fake Law Enforcement",
        ["digital arrest", "cyber crime cell", "your aadhaar is linked to", "money laundering case",
         "narcotics case", "arrest warrant", "do not disconnect the call", "stay on video call"],
        "This matches the 'digital arrest' scam pattern - fraudsters impersonate police/CBI/customs "
        "officials on video call and pressure victims into transferring money to avoid a fake arrest. "
        "Real law enforcement never arrests or demands money over a phone/video call.",
    ),
    (
        "Fake Courier / Customs Hold",
        ["parcel is held at customs", "package is stuck at customs", "illegal items found in your parcel",
         "courier is on hold", "pay customs duty", "fedex your parcel", "parcel contains banned"],
        "This matches the fake courier/customs scam - a call or message claims your parcel is held "
        "and asks for a 'customs fee' or personal/bank details to release it.",
    ),
    (
        "Lottery / Prize Scam",
        ["you have won", "lucky winner", "claim your prize", "lottery winner", "kbc lottery",
         "you have been selected for a cash prize", "winning number"],
        "This matches a lottery/prize scam - a message claims you won something you never entered, "
        "and asks for a 'processing fee' or personal details to release the (nonexistent) prize.",
    ),
    (
        "Fake Job Offer",
        ["work from home job", "earn per day guaranteed", "part time job whatsapp", "registration fee for job",
         "no experience needed earn", "daily payment job telegram", "like and subscribe job"],
        "This matches a fake job-offer scam - often asks for an upfront 'registration' or 'training' "
        "fee, or asks you to complete tasks (like YouTube likes) with a fee before any payout.",
    ),
    (
        "Tech Support Scam",
        ["your computer is infected", "call microsoft support", "your device has a virus call",
         "windows security alert call this number", "your bank account is compromised call"],
        "This matches a tech-support scam - a pop-up or call falsely claims your device is infected "
        "and pushes you to call a number or install remote-access software.",
    ),
    (
        "Fake Bank/KYC Update",
        ["your kyc will expire", "update kyc immediately", "account will be blocked within 24",
         "your bank account will be suspended", "kyc verification pending click"],
        "This matches a fake KYC-update scam - urgency-based messages pushing you to 'update KYC' "
        "via a link, which usually leads to a credential-harvesting phishing page.",
    ),
    (
        "Loan / Instant Credit Scam",
        ["pre-approved loan of", "instant loan no documents", "loan approved click to claim",
         "processing fee for loan disbursement"],
        "This matches a loan-scam pattern - offers an implausibly easy loan and then asks for an "
        "upfront 'processing fee' before any money is actually disbursed.",
    ),
    (
        "Romance / Relationship Scam",
        ["i am currently deployed overseas", "i need money for customs to send you the gift",
         "we have never met but i love you", "send gift card to prove"],
        "This matches a romance-scam pattern - an online relationship (often never met in person) "
        "that eventually asks for money, gift cards, or financial help.",
    ),
]


def detect_scam_patterns(text: str) -> list:
    """
    Returns a list of {"category": str, "matched_phrases": [...], "explanation": str}
    for every scam category with at least one matched trigger phrase.
    """
    text_lower = text.lower()
    findings = []
    for category, phrases, explanation in SCAM_PATTERNS:
        matched = [p for p in phrases if p in text_lower]
        if matched:
            findings.append({"category": category, "matched_phrases": matched, "explanation": explanation})
    return findings
