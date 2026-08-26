"""
QR code ("quishing") scanner.

Decodes a QR code image and, if it contains a URL, routes it through the
existing phishing_scanner pipeline (heuristics + optional VirusTotal +
optional landing-page investigation). Same flag-only philosophy as the rest
of OneClick - this only reports, never blocks/deletes anything.
"""

from pyzbar.pyzbar import decode as _zbar_decode
from PIL import Image

from modules.phishing_scanner import scan_url


def decode_qr_image(image_path: str) -> list:
    """Returns a list of decoded payload strings found in the image (a QR
    image can contain multiple codes, though usually just one)."""
    img = Image.open(image_path)
    # Zbar wants RGB; convert defensively (e.g. for RGBA/P-mode PNGs/screenshots).
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    results = _zbar_decode(img)
    return [r.data.decode("utf-8", errors="replace") for r in results]


def scan_qr_image(image_path: str, vt_api_key: str = None) -> dict:
    """
    Decodes a QR image and, for any URL payloads found, runs the full
    phishing-scan pipeline. Non-URL payloads (plain text, UPI deep links,
    vCards, WiFi configs, etc.) are still returned but not URL-scanned.
    """
    payloads = decode_qr_image(image_path)
    if not payloads:
        return {"found": False, "payloads": [], "url_results": [], "error": None}

    url_results = []
    for payload in payloads:
        if payload.lower().startswith(("http://", "https://")):
            url_results.append(scan_url(payload, vt_api_key=vt_api_key))
        elif payload.lower().startswith("upi://"):
            url_results.append(_scan_upi_payload(payload))

    return {"found": True, "payloads": payloads, "url_results": url_results, "error": None}


def _scan_upi_payload(payload: str) -> dict:
    """
    UPI deep links (upi://pay?pa=...&pn=...) aren't web URLs, so they don't
    go through the web phishing heuristics, but we can still surface the
    payee VPA/name for the user to sanity-check before paying, and check the
    VPA against OneClick's local scam-report list.
    """
    from urllib.parse import urlparse, parse_qs
    from modules.scam_lookup import check_upi_id

    parsed = urlparse(payload)
    params = parse_qs(parsed.query)
    payee_vpa = params.get("pa", [None])[0]
    payee_name = params.get("pn", [None])[0]
    amount = params.get("am", [None])[0]

    reasons = [
        f"This is a UPI payment request{f' to {payee_name}' if payee_name else ''}"
        f"{f' ({payee_vpa})' if payee_vpa else ''}"
        f"{f' for ₹{amount}' if amount else ''}.",
        "OneClick cannot verify UPI VPA ownership - double-check the payee name shown "
        "on your UPI app matches who you expect before approving payment.",
    ]

    score = 0
    label = "UPI Payment Request"
    if payee_vpa:
        report = check_upi_id(payee_vpa)
        if report["is_reported"]:
            score = 90
            label = "UPI Payment Request - REPORTED VPA"
            reasons.insert(0,
                f"⚠️ This UPI ID has been reported {report['report_count']} time(s) as "
                f"'{report['category']}'. {report['note'] or ''}".strip()
            )

    return {
        "url": payload, "normalized_url": payload, "score": score, "label": label,
        "reasons": reasons, "heuristic": {}, "virustotal": {"found": False}, "is_upi": True,
        "payee_vpa": payee_vpa, "payee_name": payee_name, "amount": amount,
    }
