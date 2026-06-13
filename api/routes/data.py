from fastapi import APIRouter, Depends

from api.auth import verify_api_auth
from api.schemas import DataClearRequest, DataClearResponse, DemoLoadResponse
from src.data_import.demo_loader import load_demo_data
from src.storage.data_clear import execute_clear

router = APIRouter(prefix="/api", tags=["Data"])


@router.post("/demo/load", response_model=DemoLoadResponse)
def load_demo(
    _auth: str = Depends(verify_api_auth),
) -> DemoLoadResponse:
    summary = load_demo_data()
    return DemoLoadResponse(loaded=summary, message="Demo data loaded.")


def _selections_from_request(payload: DataClearRequest | None) -> list[str]:
    if payload is None:
        return ["all_user_data"]
    mapping = {
        "feed_cache": payload.feed_cache,
        "logs": payload.logs,
        "manual_iocs": payload.manual_iocs,
        "scans": payload.scans,
        "reports": payload.reports,
        "all_user_data": payload.all_user_data,
    }
    selected = [key for key, enabled in mapping.items() if enabled]
    return selected or ["all_user_data"]


@router.delete("/data", response_model=DataClearResponse)
def clear_data(
    payload: DataClearRequest | None = None,
    _auth: str = Depends(verify_api_auth),
) -> DataClearResponse:
    result = execute_clear(_selections_from_request(payload))
    return DataClearResponse(
        message="Dashboard data cleared.",
        cleared={
            "categories": result.categories,
            "summary": result.summary_lines(),
            "total_items": result.total_items,
        },
    )