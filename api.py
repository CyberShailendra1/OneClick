"""
FastAPI backend for OneClick — exposes the same pipeline as REST endpoints
so other tools (CI pipelines, mobile apps, other services, and the React Web UI) can integrate.

Run:
    uvicorn api:app --host 0.0.0.0 --port 8000

Docs (auto-generated) at: http://localhost:8000/docs
"""

import os
import re
import shutil
import tempfile
import uuid

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from modules.pipeline import scan_apk
from modules import database
from modules.report_generator import build_report_dict, export_json, export_pdf
from modules.phishing_scanner import scan_url, extract_urls_from_text, investigate_url
from modules.otp_guard import redact_message
from modules.scam_lookup import check_phone_number, check_upi_id, add_report
from modules.breach_checker import check_password_pwned
from modules.scam_pattern_detector import detect_scam_patterns
from modules.security_tools import (
    check_security_headers,
    inspect_ssl_cert,
    check_email_security,
    scan_port_exposure,
    scan_generic_file,
)

app = FastAPI(
    title="OneClick APK Analyzer API",
    description="Multi-layer Android malware detection: VirusTotal signatures + "
                 "Androguard static analysis + Random Forest risk scoring.",
    version="1.0.0",
)

# Allows the browser extension, local Vite dev server, and web UIs to call this API directly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORTS_DIR = os.path.join(tempfile.gettempdir(), "oneclick_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


# Load .env file automatically if present
def _load_env_file(filepath=".env"):
    env_path = os.path.join(os.path.dirname(__file__), filepath)
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key and key not in os.environ and not val.startswith("YOUR_"):
                        os.environ[key] = val

_load_env_file()


def get_default_vt_key(provided_key: str | None = None) -> str | None:
    if provided_key and provided_key.strip():
        return provided_key.strip()
    key = os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("ONECLICK_VT_API_KEY")
    if key and not key.startswith("YOUR_") and key.strip():
        return key.strip()
    return None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
async def scan(
    file: UploadFile = File(...),
    vt_api_key: str = Query(default=None, description="Optional VirusTotal API key"),
    advanced: bool = Query(default=True, description="Run advanced static analysis"),
):
    """Upload an APK and get back the full OneClick scan result as JSON."""
    active_vt_key = get_default_vt_key(vt_api_key)
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be a .apk")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        # Offload synchronous/heavy scan pipeline to threadpool to avoid blocking event loop
        result = await run_in_threadpool(
            scan_apk, tmp_path, file.filename, vt_api_key=active_vt_key, run_advanced=advanced
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return result


@app.post("/scan/report")
async def scan_and_get_report(
    file: UploadFile = File(...),
    vt_api_key: str = Query(default=None),
    format: str = Query(default="pdf", pattern="^(pdf|json)$"),
):
    """Scan an APK and return a downloadable PDF or JSON report."""
    active_vt_key = get_default_vt_key(vt_api_key)
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be a .apk")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        result = await run_in_threadpool(
            scan_apk, tmp_path, file.filename, vt_api_key=active_vt_key, run_advanced=True
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    report = build_report_dict(
        filename=file.filename,
        sha256=result["sha256"],
        layer1=result.get("vt_result"),
        features=result.get("features") or {},
        ml_result=result.get("ml_result") or {"label": "Known Threat", "risk_score": 100.0, "reasons": []},
        advanced=result.get("advanced"),
    )

    report_id = str(uuid.uuid4())
    out_path = os.path.join(REPORTS_DIR, f"{report_id}.{format}")
    if format == "pdf":
        await run_in_threadpool(export_pdf, report, out_path)
        media_type = "application/pdf"
    else:
        await run_in_threadpool(export_json, report, out_path)
        media_type = "application/json"

    return FileResponse(
        out_path,
        media_type=media_type,
        filename=f"oneclick_report.{format}",
        background=BackgroundTask(os.unlink, out_path)
    )


@app.get("/history")
def history(limit: int = Query(default=50, le=500)):
    """Return recent scan history from the local SQLite database."""
    return database.get_history(limit=limit)


@app.get("/history/{sha256}")
def history_by_hash(sha256: str):
    record = database.get_history_by_hash(sha256)
    if not record:
        raise HTTPException(status_code=404, detail="No scan history for this hash")
    return record


@app.delete("/history")
def clear_history():
    database.clear_history()
    return {"status": "cleared"}


# ---------------------------------------------------------------------------
# Phishing / malicious-URL scanning
# ---------------------------------------------------------------------------

class URLScanRequest(BaseModel):
    url: str
    vt_api_key: str | None = None


class MessageScanRequest(BaseModel):
    text: str
    vt_api_key: str | None = None


@app.post("/scan-url")
def scan_url_endpoint(req: URLScanRequest):
    """Scan a single URL for phishing/malicious indicators."""
    active_vt_key = get_default_vt_key(req.vt_api_key)
    result = scan_url(req.url, vt_api_key=active_vt_key)
    database.save_url_scan(
        url=result["url"], verdict=result["label"],
        risk_score=result["score"], reasons=result["reasons"],
    )
    return result


@app.post("/investigate-url")
def investigate_url_endpoint(req: URLScanRequest):
    """Opt-in deep-dive: statically inspects landing page and redirects."""
    return investigate_url(req.url)


@app.post("/scan-message")
def scan_message_endpoint(req: MessageScanRequest):
    """Extracts URLs from a pasted message and scans each one."""
    active_vt_key = get_default_vt_key(req.vt_api_key)
    urls = extract_urls_from_text(req.text)
    results = []
    for url in urls:
        result = scan_url(url, vt_api_key=active_vt_key)
        database.save_url_scan(
            url=result["url"], verdict=result["label"],
            risk_score=result["score"], reasons=result["reasons"],
        )
        results.append(result)
    return {"urls_found": len(urls), "results": results}


@app.get("/url-history")
def url_history(limit: int = Query(default=50, le=500)):
    return database.get_url_history(limit=limit)


@app.post("/url-history/{row_id}/action")
def set_url_action(row_id: int, action: str = Query(..., pattern="^(dismissed|deleted_by_user|none)$")):
    database.set_url_scan_action(row_id, action)
    return {"status": "updated", "id": row_id, "action": action}


@app.delete("/url-history")
def clear_url_history():
    database.clear_url_history()
    return {"status": "cleared"}


# ---------------------------------------------------------------------------
# OTP Redaction
# ---------------------------------------------------------------------------

class RedactRequest(BaseModel):
    text: str


@app.post("/redact-message")
def redact_message_endpoint(req: RedactRequest):
    """Auto-hides OTP/verification codes in a pasted message."""
    return redact_message(req.text)


# ---------------------------------------------------------------------------
# Optional User Authentication & Dashboard (OTP Login)
# ---------------------------------------------------------------------------

class SendOtpRequest(BaseModel):
    phone: str

class VerifyOtpRequest(BaseModel):
    phone: str
    otp: str

@app.post("/auth/send-otp")
def send_otp_endpoint(req: SendOtpRequest):
    clean_phone = re.sub(r"[^0-9]", "", req.phone)
    if len(clean_phone) < 10:
        raise HTTPException(status_code=400, detail="Invalid phone number format")

    import random
    # Generate 6-digit OTP
    otp_code = str(random.randint(100000, 999999))
    database.save_otp(clean_phone, otp_code, ttl_seconds=300)

    # In local/open demo environment, print to console and return in response for seamless zero-SMS-cost testing
    print(f"\n[ONECLICK AUTH] Generated OTP for {clean_phone}: {otp_code}\n")
    return {
        "status": "success",
        "message": f"OTP sent to +91 {clean_phone[-10:]}",
        "demo_otp": otp_code,  # Provided for easy local testing without external paid SMS gateway
    }

@app.post("/auth/verify-otp")
def verify_otp_endpoint(req: VerifyOtpRequest):
    clean_phone = re.sub(r"[^0-9]", "", req.phone)
    login_result = database.verify_otp_and_login(clean_phone, req.otp.strip())
    if not login_result:
        raise HTTPException(status_code=401, detail="Invalid or expired OTP code")
    return {
        "status": "success",
        "token": login_result["token"],
        "phone": login_result["phone"],
    }

@app.get("/auth/me")
def get_current_user_endpoint(token: str = Query(...)):
    user = database.get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return {"status": "authenticated", "user": user}

@app.post("/auth/logout")
def logout_endpoint(token: str = Query(...)):
    database.delete_session(token)
    return {"status": "logged_out"}



# ---------------------------------------------------------------------------
# Scam Lookup & Password Breach Checker
# ---------------------------------------------------------------------------

class PhoneCheckRequest(BaseModel):
    phone: str


class UpiCheckRequest(BaseModel):
    upi_id: str


class ScamReportRequest(BaseModel):
    type: str  # "phone" or "upi"
    value: str
    category: str
    note: str | None = None


class PasswordBreachRequest(BaseModel):
    password: str


@app.post("/scam-lookup/phone")
def scam_phone_endpoint(req: PhoneCheckRequest):
    return check_phone_number(req.phone)


@app.post("/scam-lookup/upi")
def scam_upi_endpoint(req: UpiCheckRequest):
    return check_upi_id(req.upi_id)


@app.post("/scam-lookup/report")
def scam_report_endpoint(req: ScamReportRequest):
    success = add_report(req.type, req.value, req.category, req.note)
    return {"status": "saved" if success else "failed"}


@app.post("/breach/password")
def breach_password_endpoint(req: PasswordBreachRequest):
    return check_password_pwned(req.password)


# ---------------------------------------------------------------------------
# Extended Security Tools Suite
# ---------------------------------------------------------------------------

class URLToolRequest(BaseModel):
    url: str


class HostToolRequest(BaseModel):
    host: str


class DomainToolRequest(BaseModel):
    domain: str


@app.post("/tools/security-headers")
def security_headers_endpoint(req: URLToolRequest):
    return check_security_headers(req.url)


@app.post("/tools/ssl-cert")
def ssl_cert_endpoint(req: HostToolRequest):
    return inspect_ssl_cert(req.host)


@app.post("/tools/email-security")
def email_security_endpoint(req: DomainToolRequest):
    return check_email_security(req.domain)


@app.post("/tools/port-scan")
def port_scan_endpoint(req: HostToolRequest):
    return scan_port_exposure(req.host)


@app.post("/tools/scan-file")
async def scan_file_endpoint(
    file: UploadFile = File(...),
    vt_api_key: str = Query(default=None),
):
    active_vt_key = get_default_vt_key(vt_api_key)
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        result = await run_in_threadpool(
            scan_generic_file, tmp_path, file.filename or "unknown_file", vt_api_key=active_vt_key
        )
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return result


# ---------------------------------------------------------------------------
# Universal Citizen Smart Analyzer (Zero-Knowledge Security Shield)
# ---------------------------------------------------------------------------

class SmartAnalyzeRequest(BaseModel):
    query: str
    vt_api_key: str | None = None


@app.post("/smart-analyze")
def smart_analyze_endpoint(req: SmartAnalyzeRequest):
    raw_query = req.query.strip()
    active_vt_key = get_default_vt_key(req.vt_api_key)

    if not raw_query:
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    # 1. Check if it's a Phone Number (10 to 13 digits with optional +, spaces, dashes)
    clean_digits = re.sub(r"[^0-9]", "", raw_query)
    is_phone_pattern = bool(re.match(r"^(\+?91|0)?[6-9]\d{9}$", raw_query.replace(" ", "").replace("-", "")))
    if is_phone_pattern or (len(clean_digits) == 10 and not any(c in raw_query for c in ['@', '/', '.'])):
        phone_res = check_phone_number(raw_query)
        if phone_res["is_reported"]:
            return {
                "type": "phone",
                "level": "danger",
                "title": "🚨 Fraudulent / Scam Phone Number Detected",
                "summary": f"This number has been reported {phone_res['report_count']} time(s) for cyber fraud ({phone_res['category'] or 'Scam'}).",
                "actions": [
                    "Do NOT answer or call back this number.",
                    "Do NOT share OTPs, passwords, or bank account details.",
                    "Block this number on your phone and WhatsApp immediately.",
                    "If you sent money, immediately call National Cybercrime Helpline 1930."
                ],
                "details": phone_res,
            }
        else:
            return {
                "type": "phone",
                "level": "safe",
                "title": "🟢 No Fraud Reports Found for this Number",
                "summary": "This phone number is not listed in our database of reported scam callers.",
                "actions": [
                    "Remember: Even unknown callers can try social engineering. Never share your bank OTP or UPI PIN with anyone."
                ],
                "details": phone_res,
            }

    # 2. Check if it's a UPI ID / VPA (e.g. name@bank)
    if re.match(r"^[\w\.\-]+@[a-zA-Z0-9]+$", raw_query):
        upi_res = check_upi_id(raw_query)
        if upi_res["is_reported"]:
            return {
                "type": "upi",
                "level": "danger",
                "title": "🚨 Fraudulent UPI ID / VPA Detected",
                "summary": f"This UPI address has been flagged for financial fraud ({upi_res['category'] or 'Scam'}).",
                "actions": [
                    "Do NOT send any money or scan any QR code linked to this ID.",
                    "Remember: You NEVER need to enter your UPI PIN to RECEIVE money.",
                    "Report this handle in your UPI app (GPay/PhonePe/Paytm) as fraud."
                ],
                "details": upi_res,
            }
        else:
            return {
                "type": "upi",
                "level": "safe",
                "title": "🟢 Clean UPI Handle",
                "summary": "This UPI handle has no active fraud complaints in our database.",
                "actions": [
                    "Safety Rule: Entering your UPI PIN always DEBITS (deducts) money from your account, never credits it."
                ],
                "details": upi_res,
            }

    # 3. Check if it's a URL or contains URLs
    urls_found = extract_urls_from_text(raw_query)
    is_standalone_url = bool(re.match(r"^(https?://|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,})", raw_query)) and " " not in raw_query

    if is_standalone_url or len(urls_found) > 0:
        target_url = raw_query if is_standalone_url else urls_found[0]
        url_res = scan_url(target_url, vt_api_key=active_vt_key)
        
        # Save to database
        database.save_url_scan(
            url=url_res["url"], verdict=url_res["label"],
            risk_score=url_res["score"], reasons=url_res["reasons"]
        )

        level = "safe"
        if url_res["label"] == "Malicious":
            level = "danger"
        elif url_res["label"] == "Suspicious":
            level = "caution"

        return {
            "type": "url",
            "level": level,
            "title": f"{'🚨 Dangerous Malicious Link' if level == 'danger' else '⚠️ Suspicious Link Detected' if level == 'caution' else '🟢 Link Appears Safe'}",
            "summary": f"Risk Score: {url_res['score']}%. " + ("; ".join(url_res["reasons"]) if url_res["reasons"] else "No active phishing patterns detected."),
            "actions": [
                "Do NOT enter your passwords, card numbers, or personal information on this page." if level != "safe" else "Link verified safe by heuristic checks.",
                "If you clicked this link and entered bank credentials, immediately change your online banking password and freeze your card.",
                "Never download or install APK files or unknown software from unverified links."
            ],
            "details": url_res,
        }

    # 4. Text Message / SMS / WhatsApp Message Analysis
    scam_patterns = detect_scam_patterns(raw_query)
    redacted = redact_message(raw_query)

    if scam_patterns:
        top_scam = scam_patterns[0]
        return {
            "type": "message",
            "level": "danger",
            "title": f"🚨 Scam Alert: {top_scam['category']}",
            "summary": top_scam["explanation"],
            "actions": [
                "Do NOT reply, call any number in the message, or click any links.",
                "Real police, CBI, or judges NEVER put anyone under 'Digital Arrest' or demand money via video calls.",
                "Electricity boards or banks NEVER threaten immediate disconnection via random personal numbers.",
                "Report cyber fraud to the government helpline by calling 1930."
            ],
            "details": {
                "matched_patterns": scam_patterns,
                "sanitized_message": redacted["redacted_text"],
                "otps_masked": redacted.get("codes_hidden", 0),
            }
        }

    # If sensitive codes were found
    codes_hidden = redacted.get("codes_hidden", 0)
    if codes_hidden > 0:
        return {
            "type": "message",
            "level": "caution",
            "title": "⚠️ Sensitive OTP / Verification Code Detected in Message",
            "summary": f"Found {codes_hidden} secret code(s) inside this message. We masked them to protect you.",
            "actions": [
                "NEVER share this code with anyone, even someone claiming to be bank manager or support staff.",
                "Banks and official institutions NEVER ask for your OTP over phone, SMS, or WhatsApp."
            ],
            "details": {
                "sanitized_message": redacted["redacted_text"],
                "codes_found": codes_hidden,
            }
        }

    # Default Clean text

    return {
        "type": "general",
        "level": "safe",
        "title": "🟢 No Known Scam Patterns Detected",
        "summary": "This message does not match known cyber fraud scripts (electricity cut-off, digital arrest, fake courier, lottery).",
        "actions": [
            "Always be cautious if an unknown sender creates urgency or asks for money/personal details."
        ],
        "details": {"raw_text": raw_query},
    }


# ---------------------------------------------------------------------------
# Optional User Authentication & Dashboard Endpoints (OTP based)
# ---------------------------------------------------------------------------

class SendOtpRequest(BaseModel):
    phone: str

class VerifyOtpRequest(BaseModel):
    phone: str
    otp: str

@app.post("/auth/send-otp")
def send_otp_endpoint(req: SendOtpRequest):
    import random
    clean_phone = re.sub(r"[^0-9]", "", req.phone)
    if len(clean_phone) < 10:
        raise HTTPException(status_code=400, detail="Invalid mobile number. Please provide a 10-digit number.")
    
    # 6-digit OTP code
    otp_code = str(random.randint(100000, 999999))
    database.save_otp(clean_phone, otp_code, ttl_seconds=300)
    print(f"\n[ONECLICK AUTH] Generated OTP for +91-{clean_phone}: {otp_code}\n")
    
    return {
        "status": "success",
        "message": f"Verification OTP sent to +91 {clean_phone}.",
        "demo_otp": otp_code
    }

@app.post("/auth/verify-otp")
def verify_otp_endpoint(req: VerifyOtpRequest):
    clean_phone = re.sub(r"[^0-9]", "", req.phone)
    res = database.verify_otp_and_login(clean_phone, req.otp.strip())
    if not res:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP code.")
    return {
        "status": "success",
        "token": res["token"],
        "phone": res["phone"]
    }

@app.get("/auth/me")
def get_current_user_endpoint(token: str = Query(...)):
    user = database.get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    return {"status": "success", "user": user}

@app.post("/auth/logout")
def logout_endpoint(token: str = Query(...)):
    database.delete_session(token)
    return {"status": "success"}


# ---------------------------------------------------------------------------
# Serve Built React Frontend with SPA routing support
# ---------------------------------------------------------------------------
FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "frontend", "dist")
if os.path.exists(FRONTEND_DIST):
    # Serve assets folder
    assets_dir = os.path.join(FRONTEND_DIST, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    # Serve index.html for all non-API GET requests (SPA fallback)
    @app.get("/{full_path:path}")
    def serve_spa(full_path: str):
        # If it's a specific static file (like favicon, robots.txt, etc.)
        target_file = os.path.join(FRONTEND_DIST, full_path)
        if full_path and os.path.isfile(target_file):
            return FileResponse(target_file)
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))

