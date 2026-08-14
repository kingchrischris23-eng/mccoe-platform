from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from api.auth import verify_api_auth
from api.schemas import LogAnalyzeRequest, LogAnalyzeResponse
from config import settings
from src.logs.analyzer import analyze_logs
from src.logs.detectors import detect_alerts
from src.logs.parser import parse_log_file
from src.storage.repository import create_log_session, save_alerts, save_log_entries

router = APIRouter(prefix="/api/logs", tags=["Logs"])


def _analyze_content(filename: str, content: str) -> LogAnalyzeResponse:
    entries = parse_log_file(content)
    alerts = detect_alerts(entries)
    session_id = create_log_session(filename)
    save_log_entries(session_id, entries)
    save_alerts(session_id, alerts)
    analysis = analyze_logs(entries, alerts)
    analysis["alert_breakdown"] = dict(analysis["alert_breakdown"])
    return LogAnalyzeResponse(
        session_id=session_id,
        filename=filename,
        entries_parsed=len(entries),
        alerts_found=len(alerts),
        alerts=alerts,
        analysis=analysis,
    )


@router.post("/analyze", response_model=LogAnalyzeResponse)
async def analyze_logs_json(
    payload: LogAnalyzeRequest,
    _auth: str = Depends(verify_api_auth),
) -> LogAnalyzeResponse:
    return _analyze_content(payload.filename, payload.content)


@router.post("/analyze/upload", response_model=LogAnalyzeResponse)
async def analyze_logs_upload(
    file: UploadFile = File(...),
    _auth: str = Depends(verify_api_auth),
) -> LogAnalyzeResponse:
    raw = await file.read()
    size_mb = len(raw) / (1024 * 1024)
    if size_mb > settings.max_upload_mb:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_upload_mb} MB limit.")

    content = raw.decode("utf-8", errors="replace")
    filename = file.filename or "uploaded.log"
    return _analyze_content(filename, content)