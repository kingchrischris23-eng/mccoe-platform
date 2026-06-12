from datetime import datetime, timezone

import httpx

from config import settings
from src.feeds.cache import read_cache, write_cache
from src.feeds.common import ioc_from_dict, ioc_to_dict
from src.feeds.models import FeedSourceResult, IOC

CACHE_NAME = "cisa_kev"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def can_fetch_live() -> bool:
    return not settings.local_only and settings.enable_live_feeds and settings.enable_cisa_kev


def fetch_cisa_kev(*, force_refresh: bool = False) -> FeedSourceResult:
    if not settings.enable_cisa_kev:
        return FeedSourceResult(name="cisa_kev", error="disabled")

    if not force_refresh or not can_fetch_live():
        cached, meta = read_cache(CACHE_NAME, allow_stale=True)
        if cached is not None:
            iocs = [ioc_from_dict(item) for item in cached]
            return FeedSourceResult(
                name="cisa_kev",
                iocs=iocs,
                count=len(iocs),
                cached_at=meta.cached_at,
                stale=meta.stale,
                live=False,
            )
        if not can_fetch_live():
            return FeedSourceResult(
                name="cisa_kev",
                error="local_only" if settings.local_only else "live_feeds_disabled",
            )

    try:
        response = httpx.get(KEV_URL, timeout=30.0)
        response.raise_for_status()
        rows = response.json().get("vulnerabilities", [])
        iocs = [_kev_to_ioc(row) for row in rows]
        serialized = [ioc_to_dict(ioc) for ioc in iocs]
        if serialized:
            write_cache(CACHE_NAME, serialized, source="CISA KEV")
        return FeedSourceResult(
            name="cisa_kev",
            iocs=iocs,
            count=len(iocs),
            cached_at=datetime.now(timezone.utc),
            stale=False,
            live=True,
        )
    except httpx.HTTPError as exc:
        cached, meta = read_cache(CACHE_NAME, allow_stale=True)
        if cached is None:
            return FeedSourceResult(name="cisa_kev", error=str(exc))
        iocs = [ioc_from_dict(item) for item in cached]
        return FeedSourceResult(
            name="cisa_kev",
            iocs=iocs,
            count=len(iocs),
            cached_at=meta.cached_at,
            stale=True,
            live=False,
            error=str(exc),
        )


def _kev_to_ioc(row: dict) -> IOC:
    cve_id = row.get("cveID", "UNKNOWN")
    vendor = row.get("vendorProject", "")
    product = row.get("product", "")
    due_date = row.get("dueDate", "")
    ransomware = row.get("knownRansomwareCampaignUse", "Unknown")
    description = row.get("shortDescription", row.get("vulnerabilityName", "CISA KEV entry"))
    tags = [tag for tag in [vendor, product, f"due:{due_date}", f"ransomware:{ransomware}"] if tag]
    return IOC(
        ioc_type="cve",
        value=cve_id,
        severity="critical",
        source="CISA KEV",
        first_seen=datetime.now(timezone.utc),
        tags=tags,
        description=f"{description[:200]} | Due: {due_date}",
    )