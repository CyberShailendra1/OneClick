"""
FastAPI backend for OneClick — exposes the same pipeline as REST endpoints
so other tools (CI pipelines, mobile apps, other services, and the React Web UI) can integrate.

Run:
    uvicorn api:app --host 0.0.0.0 --port 8000

Docs (auto-generated) at: http://localhost:8000/docs
"""

import os
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
# Serve Built React Frontend (if built into frontend/dist)
# ---------------------------------------------------------------------------
FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "frontend", "dist")
if os.path.exists(FRONTEND_DIST):
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
