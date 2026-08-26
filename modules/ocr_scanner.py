"""
Screenshot OCR scam detector.

Most people forward scam messages as SCREENSHOTS, not copy-pasted text.
This module extracts text from an uploaded screenshot (Tesseract OCR) and
routes it through the existing phishing-URL and OTP-redaction pipelines -
so a screenshotted scam message gets the same protection as pasted text.
"""

import pytesseract
from PIL import Image

from modules.phishing_scanner import extract_urls_from_text, scan_url
from modules.otp_guard import redact_message
from modules.scam_pattern_detector import detect_scam_patterns


def extract_text_from_image(image_path: str) -> str:
    img = Image.open(image_path)
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    return pytesseract.image_to_string(img)


def scan_screenshot(image_path: str, vt_api_key: str = None) -> dict:
    """
    Full pipeline on a screenshot: OCR -> URL extraction/scan -> OTP
    redaction -> scam-script pattern matching. Returns everything the
    dashboard needs to render a single combined report.
    """
    raw_text = extract_text_from_image(image_path)

    if not raw_text.strip():
        return {
            "raw_text": "", "ocr_confidence_note": "No readable text detected in the image.",
            "urls_found": [], "url_results": [], "redaction": {"redacted_text": "", "codes_hidden": 0, "keywords_matched": []},
            "scam_patterns": [],
        }

    urls = extract_urls_from_text(raw_text)
    url_results = [scan_url(u, vt_api_key=vt_api_key) for u in urls]
    redaction = redact_message(raw_text)
    scam_patterns = detect_scam_patterns(raw_text)

    return {
        "raw_text": raw_text,
        "urls_found": urls,
        "url_results": url_results,
        "redaction": redaction,
        "scam_patterns": scam_patterns,
    }
