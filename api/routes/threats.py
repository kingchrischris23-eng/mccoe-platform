from fastapi import APIRouter, Depends, Query

from api.auth import verify_api_auth
from api.schemas import IOCResponse, ThreatListResponse
from src.feeds.aggregator import aggregate_feeds
from src.storage.repository import list_iocs_filtered, save_iocs

router = APIRouter(prefix="/api/threats", tags=["Threats"])


@router.get("", response_model=ThreatListResponse)
def list_threats(
    severity: str | None = Query(None, description="Filter by severity (low, medium, high, critical)"),
    ioc_type: str | None = Query(None, description="Filter by IOC type (ip, domain, url, hash, etc.)"),
    source: str | None = Query(None, description="Filter by feed source"),
    search: str | None = Query(None, description="Search IOC value or tags"),
    limit: int = Query(100, ge=1, le=500),
    refresh: bool = Query(False, description="Refresh and merge threat feeds before listing"),
    _auth: str = Depends(verify_api_auth),
) -> ThreatListResponse:
    if refresh:
        iocs = aggregate_feeds()
        save_iocs(iocs)

    rows = list_iocs_filtered(severity=severity, ioc_type=ioc_type, source=source, search=search, limit=limit)
    return ThreatListResponse(
        count=len(rows),
        iocs=[IOCResponse(**row) for row in rows],
    )