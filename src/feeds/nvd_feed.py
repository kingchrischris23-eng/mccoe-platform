from datetime import datetime, timedelta, timezone

import httpx

from config import settings
from src.feeds.cache import read_cache, write_cache
from src.feeds.common import cvss_to_severity, ioc_from_dict, ioc_to_dict, score_severity
from src.feeds.models import FeedSourceResult, IOC
from src.feeds.rate_limit import nvd_interval_seconds, request_with_backoff, seconds_until_retry

CACHE_NAME = "nist_nvd"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def can_fetch_live() -> bool:
    return not settings.local_only and settings.enable_live_feeds and settings.enable_nvd_feed


def fetch_nvd_feed(*, force_refresh: bool = False) -> FeedSourceResult:
    if not settings.enable_nvd_feed:
        return FeedSourceResult(name="nist_nvd", error="disabled")

    if not force_refresh or not can_fetch_live():
        cached, meta = read_cache(CACHE_NAME, allow_stale=True)
        if cached is not None:
            iocs = [_parse_cached_item(item) for item in cached]
            return FeedSourceResult(
                name="nist_nvd",
                iocs=iocs,
                count=len(iocs),
                cached_at=meta.cached_at,
                stale=meta.stale,
                live=False,
                rate_limited=meta.rate_limited,
            )
        if not can_fetch_live():
            return FeedSourceResult(
                name="nist_nvd",
                error="local_only" if settings.local_only else "live_feeds_disabled",
            )

    try:
        rows = _fetch_recent_cves()
        iocs = [_cve_to_ioc(row) for row in rows]
        serialized = [ioc_to_dict(ioc) for ioc in iocs]
        if serialized:
            write_cache(CACHE_NAME, serialized, source="NIST NVD")
        return FeedSourceResult(
            name="nist_nvd",
            iocs=iocs,
            count=len(iocs),
            cached_at=datetime.now(timezone.utc),
            stale=False,
            live=True,
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (403, 429):
            return _fallback_from_cache(rate_limited=True, error=f"rate_limited:{seconds_until_retry('nvd')}")
        return _fallback_from_cache(error=str(exc))
    except httpx.HTTPError as exc:
        return _fallback_from_cache(error=str(exc))


def _fallback_from_cache(*, rate_limited: bool = False, error: str | None = None) -> FeedSourceResult:
    cached, meta = read_cache(CACHE_NAME, allow_stale=True)
    if cached is None:
        return FeedSourceResult(name="nist_nvd", error=error, rate_limited=rate_limited)
    iocs = [_parse_cached_item(item) for item in cached]
    return FeedSourceResult(
        name="nist_nvd",
        iocs=iocs,
        count=len(iocs),
        cached_at=meta.cached_at,
        stale=True,
        live=False,
        error=error,
        rate_limited=rate_limited or meta.rate_limited,
    )


def _fetch_recent_cves() -> list[dict]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 50,
    }
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    def _do_request():
        return httpx.get(NVD_URL, params=params, headers=headers, timeout=25.0)

    response = request_with_backoff("nvd", nvd_interval_seconds(), _do_request)
    return response.json().get("vulnerabilities", [])


def _cve_to_ioc(item: dict) -> IOC:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
    score = metrics[0]["cvssData"]["baseScore"] if metrics else 0.0
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "No description available.",
    )
    severity = cvss_to_severity(score) if score else score_severity([], description)
    return IOC(
        ioc_type="cve",
        value=cve_id,
        severity=severity,
        source="NIST NVD",
        first_seen=datetime.now(timezone.utc),
        tags=["nvd", "cve"],
        description=f"CVSS {score}: {description[:220]}",
    )


def _parse_cached_item(item: dict) -> IOC:
    return ioc_from_dict(item)