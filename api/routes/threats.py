from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from api.auth import verify_api_auth
from api.schemas import IOCImportRequest, IOCImportResponse, IOCResponse, ThreatListResponse
from src.data_import.ioc_importer import import_iocs_from_upload, parse_ioc_records
from src.feeds.aggregator import refresh_feeds
from src.storage.repository import count_iocs_filtered, list_iocs_filtered, save_iocs

router = APIRouter(prefix="/api/threats", tags=["Threats"])


@router.get("", response_model=ThreatListResponse)
def list_threats(
    severity: str | None = Query(None, description="Filter by severity (low, medium, high, critical)"),
    ioc_type: str | None = Query(None, description="Filter by IOC type (ip, domain, url, hash, etc.)"),
    source: str | None = Query(None, description="Filter by feed source"),
    search: str | None = Query(None, description="Search IOC value or tags"),
    limit: int | None = Query(None, ge=1, le=50000, description="Max IOCs to return (omit for all)"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    sort: str = Query("newest", description="Sort: newest, risk, oldest"),
    refresh: bool = Query(False, description="Refresh and merge threat feeds before listing"),
    _auth: str = Depends(verify_api_auth),
) -> ThreatListResponse:
    if refresh:
        result = refresh_feeds(force_refresh=True)
        save_iocs(result.iocs)

    effective_limit = limit
    rows = list_iocs_filtered(
        severity=severity,
        ioc_type=ioc_type,
        source=source,
        search=search,
        limit=effective_limit,
        offset=offset,
        sort=sort,
    )
    total = count_iocs_filtered(severity=severity, ioc_type=ioc_type, source=source, search=search)
    return ThreatListResponse(
        count=len(rows),
        iocs=[IOCResponse(**row) for row in rows],
        total=total,
    )


@router.post("/import", response_model=IOCImportResponse)
def import_threats_json(
    payload: IOCImportRequest,
    _auth: str = Depends(verify_api_auth),
) -> IOCImportResponse:
    try:
        iocs = parse_ioc_records(payload.iocs)
        save_iocs(iocs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return IOCImportResponse(imported=len(iocs), message=f"Imported {len(iocs)} IOC(s).")


@router.post("/import/upload", response_model=IOCImportResponse)
async def import_threats_upload(
    file: UploadFile = File(...),
    _auth: str = Depends(verify_api_auth),
) -> IOCImportResponse:
    content = (await file.read()).decode("utf-8", errors="replace")
    try:
        iocs = import_iocs_from_upload(file.filename or "upload.csv", content)
        save_iocs(iocs)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return IOCImportResponse(imported=len(iocs), message=f"Imported {len(iocs)} IOC(s).")