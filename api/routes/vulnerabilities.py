from fastapi import APIRouter, Depends, Query

from api.auth import verify_api_auth
from api.schemas import VulnerabilityCreateRequest, VulnerabilityListResponse, VulnerabilityScanResponse
from src.storage.repository import list_vuln_scans, save_vuln_scan

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


@router.post("", response_model=VulnerabilityScanResponse)
def create_vulnerability(
    payload: VulnerabilityCreateRequest,
    _auth: str = Depends(verify_api_auth),
) -> VulnerabilityScanResponse:
    scan_id = save_vuln_scan(payload.model_dump())
    scans = list_vuln_scans()
    created = next(scan for scan in scans if scan["id"] == scan_id)
    return VulnerabilityScanResponse(**created)