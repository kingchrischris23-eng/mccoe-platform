from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from api.auth import verify_api_auth
from api.schemas import ReportGenerateRequest, ReportGenerateResponse
from config import REPORTS_DIR
from src.reports.filters import ReportFilters
from src.reports.generator import generate_threat_report, generate_threat_report_markdown, generate_threat_reports

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.post("/generate", response_model=ReportGenerateResponse)
def generate_report(
    payload: ReportGenerateRequest,
    _auth: str = Depends(verify_api_auth),
) -> ReportGenerateResponse:
    files: list[dict] = []

    filters = ReportFilters.from_dict(payload.filters.model_dump() if payload.filters else None)

    if payload.format == "pdf":
        path = generate_threat_report(auto=payload.auto, filters=filters)
        files.append({"format": "pdf", "filename": path.name, "path": str(path)})
        summary = path.name
    elif payload.format == "markdown":
        path = generate_threat_report_markdown(auto=payload.auto, filters=filters)
        files.append({"format": "markdown", "filename": path.name, "path": str(path)})
        summary = path.name
    else:
        paths = generate_threat_reports(auto=payload.auto, filters=filters)
        files = [
            {"format": "pdf", "filename": paths["pdf"].name, "path": str(paths["pdf"])},
            {"format": "markdown", "filename": paths["markdown"].name, "path": str(paths["markdown"])},
        ]
        summary = f"{paths['pdf'].name}, {paths['markdown'].name}"

    return ReportGenerateResponse(format=payload.format, files=files, summary=summary)


@router.get("/download/{filename}")
def download_report(filename: str, _auth: str = Depends(verify_api_auth)) -> FileResponse:
    safe_name = Path(filename).name
    file_path = REPORTS_DIR / safe_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report not found.")

    media = "application/pdf" if safe_name.endswith(".pdf") else "text/markdown"
    return FileResponse(file_path, media_type=media, filename=safe_name)