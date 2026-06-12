from fastapi import APIRouter, Depends

from api.auth import verify_api_auth
from api.schemas import DataClearResponse, DemoLoadResponse
from src.data_import.demo_loader import load_demo_data
from src.storage.repository import clear_all_data

router = APIRouter(prefix="/api", tags=["Data"])


@router.post("/demo/load", response_model=DemoLoadResponse)
def load_demo(
    _auth: str = Depends(verify_api_auth),
) -> DemoLoadResponse:
    summary = load_demo_data()
    return DemoLoadResponse(loaded=summary, message="Demo data loaded.")


@router.delete("/data", response_model=DataClearResponse)
def clear_data(
    _auth: str = Depends(verify_api_auth),
) -> DataClearResponse:
    clear_all_data()
    return DataClearResponse(message="All dashboard data cleared.")