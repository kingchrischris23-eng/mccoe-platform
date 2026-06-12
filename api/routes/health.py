from fastapi import APIRouter

from api.schemas import HealthResponse
from config import is_local_only
from src.reports.branding import REPORT_VERSION

router = APIRouter(tags=["Health"])


@router.get("/api/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    return HealthResponse(status="ok", version=REPORT_VERSION, local_only=is_local_only())