from datetime import datetime, timezone

import httpx

from config import settings
from src.feeds.cache import read_cache, write_cache
from src.feeds.common import ioc_from_dict, ioc_to_dict, score_severity
from src.feeds.models import FeedSourceResult, IOC


def can_fetch_live() -> bool:
    return not settings.local_only and settings.enable_live_feeds


def fetch_urlhaus(*, force_refresh: bool = False) -> FeedSourceResult:
    if not settings.enable_urlhaus:
        return FeedSourceResult(name="urlhaus", error="disabled")

    if not force_refresh or not can_fetch_live():
        cached, meta = read_cache("urlhaus", allow_stale=True)
        if cached is not None:
            iocs = [ioc_from_dict(item) for item in cached]
            return FeedSourceResult(
                name="urlhaus",
                iocs=iocs,
                count=len(iocs),
                cached_at=meta.cached_at,
                stale=meta.stale,
                live=False,
            )
        if not can_fetch_live():
            return FeedSourceResult(
                name="urlhaus",
                error="local_only" if settings.local_only else "live_feeds_disabled",
            )

    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/"
    try:
        response = httpx.get(url, timeout=15.0)
        response.raise_for_status()
        rows = response.json().get("urls", [])
    except httpx.HTTPError as exc:
        return _cache_fallback("urlhaus", str(exc))

    iocs: list[IOC] = []
    serialized: list[dict] = []
    for row in rows:
        tags = [row.get("threat", "malware"), row.get("tags", "")]
        description = f"URLhaus entry: {row.get('url_status', 'unknown')}"
        ioc = IOC(
            ioc_type="url",
            value=row.get("url", ""),
            severity=score_severity(tags, description),
            source="URLhaus",
            first_seen=datetime.now(timezone.utc),
            tags=[tag for tag in tags if tag],
            description=description,
        )
        iocs.append(ioc)
        serialized.append(ioc_to_dict(ioc))

    if serialized:
        write_cache("urlhaus", serialized, source="URLhaus")
    return FeedSourceResult(
        name="urlhaus",
        iocs=iocs,
        count=len(iocs),
        cached_at=datetime.now(timezone.utc),
        stale=False,
        live=True,
    )


def fetch_otx(*, force_refresh: bool = False) -> FeedSourceResult:
    if not settings.enable_otx:
        return FeedSourceResult(name="otx", error="disabled")

    if not settings.otx_api_key:
        cached, meta = read_cache("otx", allow_stale=True)
        if cached is not None:
            iocs = [ioc_from_dict(item) for item in cached]
            return FeedSourceResult(
                name="otx",
                iocs=iocs,
                count=len(iocs),
                cached_at=meta.cached_at,
                stale=meta.stale,
                live=False,
                error="missing_api_key",
            )
        return FeedSourceResult(name="otx", error="missing_api_key")

    if not force_refresh or not can_fetch_live():
        cached, meta = read_cache("otx", allow_stale=True)
        if cached is not None:
            iocs = [ioc_from_dict(item) for item in cached]
            return FeedSourceResult(
                name="otx",
                iocs=iocs,
                count=len(iocs),
                cached_at=meta.cached_at,
                stale=meta.stale,
                live=False,
            )
        if not can_fetch_live():
            return FeedSourceResult(
                name="otx",
                error="local_only" if settings.local_only else "live_feeds_disabled",
            )

    headers = {"X-OTX-API-KEY": settings.otx_api_key}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    try:
        response = httpx.get(url, headers=headers, timeout=20.0)
        response.raise_for_status()
        pulses = response.json().get("results", [])[:10]
    except httpx.HTTPError as exc:
        return _cache_fallback("otx", str(exc))

    iocs: list[IOC] = []
    serialized: list[dict] = []
    for pulse in pulses:
        tags = pulse.get("tags", [])
        description = pulse.get("description", "") or pulse.get("name", "OTX pulse")
        for indicator in pulse.get("indicators", [])[:20]:
            ioc_type = indicator.get("type", "unknown")
            value = indicator.get("indicator", "")
            if not value:
                continue
            ioc = IOC(
                ioc_type=ioc_type,
                value=value,
                severity=score_severity(tags, description),
                source="AlienVault OTX",
                first_seen=datetime.now(timezone.utc),
                tags=tags,
                description=description[:300],
            )
            iocs.append(ioc)
            serialized.append(ioc_to_dict(ioc))

    if serialized:
        write_cache("otx", serialized, source="AlienVault OTX")
    return FeedSourceResult(
        name="otx",
        iocs=iocs,
        count=len(iocs),
        cached_at=datetime.now(timezone.utc),
        stale=False,
        live=True,
    )


def _cache_fallback(name: str, error: str) -> FeedSourceResult:
    cached, meta = read_cache(name, allow_stale=True)
    if cached is None:
        return FeedSourceResult(name=name, error=error)
    iocs = [ioc_from_dict(item) for item in cached]
    return FeedSourceResult(
        name=name,
        iocs=iocs,
        count=len(iocs),
        cached_at=meta.cached_at,
        stale=True,
        live=False,
        error=error,
    )