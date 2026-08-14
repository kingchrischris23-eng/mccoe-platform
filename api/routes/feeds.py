from fastapi import APIRouter, Depends

from api.auth import verify_api_auth
from api.schemas import FeedRefreshResponse, FeedSourceStatus, FeedStatusResponse
from src.feeds.aggregator import get_feed_status, refresh_feeds
from src.storage.repository import save_iocs

router = APIRouter(prefix="/api/feeds", tags=["Feeds"])


@router.get("/status", response_model=FeedStatusResponse)
def feed_status(
    _auth: str = Depends(verify_api_auth),
) -> FeedStatusResponse:
    sources = get_feed_status()
    return FeedStatusResponse(
        sources=[
            FeedSourceStatus(
                name=source.name,
                count=source.count,
                cached_at=source.cached_at.isoformat() if source.cached_at else None,
                stale=source.stale,
                live=source.live,
                error=source.error,
                rate_limited=source.rate_limited,
            )
            for source in sources
        ]
    )


@router.post("/refresh", response_model=FeedRefreshResponse)
def refresh_live_feeds(
    _auth: str = Depends(verify_api_auth),
) -> FeedRefreshResponse:
    result = refresh_feeds(force_refresh=True)
    save_iocs(result.iocs)
    return FeedRefreshResponse(
        total=result.total,
        sources=[
            FeedSourceStatus(
                name=source.name,
                count=source.count,
                cached_at=source.cached_at.isoformat() if source.cached_at else None,
                stale=source.stale,
                live=source.live,
                error=source.error,
                rate_limited=source.rate_limited,
            )
            for source in result.sources
        ],
        message=f"Refreshed {result.total} IOC(s).",
    )