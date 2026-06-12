from fastapi import APIRouter, Depends, Query

from api.auth import verify_api_auth
from api.schemas import VulnerabilityListResponse, VulnerabilityScanResponse
from src.storage.repository import list_vuln_scans

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", response_model=VulnerabilityListResponse)
def list_vulnerabilities(
    target: str | None = Query(None, description="Filter by scan target"),
    limit: int = Query(20, ge=1, le=100),
    _auth: str = Depends(verify_api_auth),
) -> VulnerabilityListResponse:
    scans = list_vuln_scans()
    if target:
        scans = [scan for scan in scans if scan["target"].lower() == target.lower()]
    scans = scans[:limit]
    return VulnerabilityListResponse(
        count=len(scans),
        scans=[VulnerabilityScanResponse(**scan) for scan in scans],
    )