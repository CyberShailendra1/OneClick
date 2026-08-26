"""
FastAPI backend for OneClick — exposes the same pipeline as REST endpoints
so other tools (CI pipelines, mobile apps, other services) can integrate.

Run:
    uvicorn api:app --host 0.0.0.0 --port 8000

Docs (auto-generated) at: http://localhost:8000/docs
"""

import os
import tempfile
import uuid

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from modules.pipeline import scan_apk
from modules import database
from modules.report_generator import build_report_dict, export_json, export_pdf
from modules.phishing_scanner import scan_url, extract_urls_from_text, investigate_url
from modules.otp_guard import redact_message
from pydantic import BaseModel

app = FastAPI(
    title="OneClick APK Analyzer API",
    description="Multi-layer Android malware detection: VirusTotal signatures + "
                 "Androguard static analysis + Random Forest risk scoring.",
    version="1.0.0",
)

# Allows the browser extension (chrome-extension:// origin) and local web UIs
# to call this API directly. NOTE: this is permissive (any origin) for local
# development convenience - restrict allow_origins to specific origins before
# any non-local/production deployment, since there's no auth layer yet either
# (see README security notes).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

REPORTS_DIR = os.path.join(tempfile.gettempdir(), "oneclick_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


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
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be a .apk")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = scan_apk(tmp_path, file.filename, vt_api_key=vt_api_key, run_advanced=advanced)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
    finally:
        os.unlink(tmp_path)

    return result


@app.post("/scan/report")
async def scan_and_get_report(
    file: UploadFile = File(...),
    vt_api_key: str = Query(default=None),
    format: str = Query(default="pdf", pattern="^(pdf|json)$"),
):
    """Scan an APK and return a downloadable PDF or JSON report."""
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be a .apk")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = scan_apk(tmp_path, file.filename, vt_api_key=vt_api_key, run_advanced=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")
    finally:
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
        export_pdf(report, out_path)
        media_type = "application/pdf"
    else:
        export_json(report, out_path)
        media_type = "application/json"

    return FileResponse(out_path, media_type=media_type, filename=f"oneclick_report.{format}")


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
#
# DESIGN NOTE: these endpoints only ever return a risk assessment. They never
# delete, block, or modify anything - by design, to avoid false positives
# causing silent data loss. Any deletion action is left to the caller/user.
# ---------------------------------------------------------------------------

class URLScanRequest(BaseModel):
    url: str
    vt_api_key: str | None = None


class MessageScanRequest(BaseModel):
    text: str
    vt_api_key: str | None = None


@app.post("/scan-url")
def scan_url_endpoint(req: URLScanRequest):
    """Scan a single URL for phishing/malicious indicators. Flags only - never deletes anything."""
    result = scan_url(req.url, vt_api_key=req.vt_api_key)
    database.save_url_scan(
        url=result["url"], verdict=result["label"],
        risk_score=result["score"], reasons=result["reasons"],
    )
    return result


@app.post("/investigate-url")
def investigate_url_endpoint(req: URLScanRequest):
    """
    Opt-in deep-dive: follows redirects and statically inspects the landing
    page (forms, meta-refresh, scripts) to describe what it would do to a
    visitor. Read-only - never executes JavaScript or submits anything.
    SSRF-guarded against private/internal IP targets.
    """
    return investigate_url(req.url)


@app.post("/scan-message")
def scan_message_endpoint(req: MessageScanRequest):
    """Extracts URLs from a pasted message (SMS/email/etc.) and scans each one."""
    urls = extract_urls_from_text(req.text)
    results = []
    for url in urls:
        result = scan_url(url, vt_api_key=req.vt_api_key)
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
    """Records what the user decided to do about a flagged URL. Called by the
    user's own action - OneClick itself never sets this automatically."""
    database.set_url_scan_action(row_id, action)
    return {"status": "updated", "id": row_id, "action": action}


@app.delete("/url-history")
def clear_url_history():
    database.clear_url_history()
    return {"status": "cleared"}


class RedactRequest(BaseModel):
    text: str


@app.post("/redact-message")
def redact_message_endpoint(req: RedactRequest):
    """
    Auto-hides OTP/verification codes in a pasted message. The real code
    value is never included in the response - only the redacted text and a
    count. This endpoint does not read any live SMS/email inbox; it only
    processes text sent to it directly.
    """
    return redact_message(req.text)
