from datetime import datetime, timezone

import httpx

from config import get_abusech_auth_key, get_otx_api_key, has_abusech_auth_key, settings
from src.feeds.abusech_client import (
    can_fetch_abusech_live,
    rate_limit_error,
    threatfox_post,
    urlhaus_get_recent,
)
from src.feeds.cache import read_cache, write_cache
from src.feeds.common import ioc_from_dict, ioc_to_dict, score_severity
from src.feeds.feed_log import log_feed_result
from src.feeds.models import FeedSourceResult, IOC
from src.feeds.rate_limit import request_with_backoff

URLHAUS_SOURCE = "URLhaus"
OTX_SOURCE = "AlienVault OTX"
THREATFOX_SOURCE = "ThreatFox"
OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OTX_INTERVAL_SECONDS = 2.0


def can_fetch_live() -> bool:
    return not settings.local_only and settings.enable_live_feeds


def fetch_urlhaus(*, force_refresh: bool = False) -> FeedSourceResult:
    if not settings.enable_urlhaus:
        return FeedSourceResult(name="urlhaus", error="disabled", status_message="URLhaus feed disabled.")

    cached_result = _read_cached_source("urlhaus")
    if not force_refresh:
        return cached_result or FeedSourceResult(
            name="urlhaus",
            error="no_cache",
            status_message="No URLhaus cache yet. Refresh live feeds when online.",
        )

    if not can_fetch_abusech_live():
        if cached_result and cached_result.count:
            cached_result.error = _abusech_block_reason()
            cached_result.status_message = f"Serving {cached_result.count} cached URLhaus IOCs ({_abusech_block_reason()})."
            return cached_result
        return FeedSourceResult(
            name="urlhaus",
            error=_abusech_block_reason(),
            status_message=_abusech_status_hint("URLhaus"),
        )

    try:
        response = urlhaus_get_recent(source="urlhaus")
        payload = response.json()
        status = payload.get("query_status", "unknown")
        if status == "no_results":
            return FeedSourceResult(
                name="urlhaus",
                count=0,
                live=True,
                status_message="URLhaus API returned no recent URLs.",
            )
        if status != "ok":
            return _cache_fallback(
                "urlhaus",
                status,
                status_message=f"URLhaus API error: {status}",
            )
        rows = payload.get("urls", [])
    except ValueError:
        return FeedSourceResult(
            name="urlhaus",
            error="missing_auth_key",
            status_message="URLhaus requires ABUSECH_AUTH_KEY in Settings.",
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (403, 429):
            return _cache_fallback(
                "urlhaus",
                rate_limit_error("urlhaus"),
                rate_limited=True,
                status_message="URLhaus rate limited — serving cache.",
            )
        return _cache_fallback("urlhaus", str(exc), status_message=f"URLhaus HTTP error: {exc}")
    except httpx.HTTPError as exc:
        return _cache_fallback("urlhaus", str(exc), status_message=f"URLhaus connection error: {exc}")

    iocs, serialized = _parse_urlhaus_rows(rows)
    if serialized:
        write_cache("urlhaus", serialized, source=URLHAUS_SOURCE)
    message = f"Successfully pulled {len(iocs)} IOCs from URLhaus (live)."
    log_feed_result("urlhaus", message)
    return FeedSourceResult(
        name="urlhaus",
        iocs=iocs,
        count=len(iocs),
        cached_at=datetime.now(timezone.utc),
        stale=False,
        live=True,
        status_message=message,
    )


def fetch_otx(*, force_refresh: bool = False) -> FeedSourceResult:
    if not settings.enable_otx:
        return FeedSourceResult(name="otx", error="disabled")

    api_key = get_otx_api_key()
    if not api_key:
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
                rate_limited=meta.rate_limited,
            )
        if not can_fetch_live():
            return FeedSourceResult(
                name="otx",
                error="local_only" if settings.local_only else "live_feeds_disabled",
            )

    headers = {"X-OTX-API-KEY": api_key}
    try:

        def _request():
            return httpx.get(OTX_PULSES_URL, headers=headers, timeout=25.0)

        response = request_with_backoff("otx", OTX_INTERVAL_SECONDS, _request)
        pulses = response.json().get("results", [])[:15]
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (403, 429):
            return _cache_fallback("otx", rate_limit_error("otx"), rate_limited=True)
        return _cache_fallback("otx", str(exc))
    except httpx.HTTPError as exc:
        return _cache_fallback("otx", str(exc))

    iocs, serialized = _parse_otx_pulses(pulses)
    if serialized:
        write_cache("otx", serialized, source=OTX_SOURCE)
    return FeedSourceResult(
        name="otx",
        iocs=iocs,
        count=len(iocs),
        cached_at=datetime.now(timezone.utc),
        stale=False,
        live=True,
    )


def fetch_threatfox(*, force_refresh: bool = False) -> FeedSourceResult:
    if not settings.enable_threatfox:
        return FeedSourceResult(name="threatfox", error="disabled", status_message="ThreatFox feed disabled.")

    cached_result = _read_cached_source("threatfox")
    if not force_refresh:
        return cached_result or FeedSourceResult(
            name="threatfox",
            error="no_cache",
            status_message="No ThreatFox cache yet. Refresh live feeds when online.",
        )

    if not can_fetch_abusech_live():
        if cached_result and cached_result.count:
            cached_result.error = _abusech_block_reason()
            cached_result.status_message = (
                f"Serving {cached_result.count} cached ThreatFox IOCs ({_abusech_block_reason()})."
            )
            return cached_result
        return FeedSourceResult(
            name="threatfox",
            error=_abusech_block_reason(),
            status_message=_abusech_status_hint("ThreatFox"),
        )

    try:
        response = threatfox_post({"query": "get_iocs", "days": 7}, source="threatfox")
        payload = response.json()
        status = payload.get("query_status", "unknown_error")
        if status != "ok":
            return _cache_fallback(
                "threatfox",
                status,
                status_message=f"ThreatFox API returned: {status}",
            )
        rows = payload.get("data", [])
    except ValueError:
        return FeedSourceResult(
            name="threatfox",
            error="missing_auth_key",
            status_message="ThreatFox requires ABUSECH_AUTH_KEY in Settings.",
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (403, 429):
            return _cache_fallback(
                "threatfox",
                rate_limit_error("threatfox"),
                rate_limited=True,
                status_message="ThreatFox rate limited — serving cache.",
            )
        return _cache_fallback("threatfox", str(exc), status_message=f"ThreatFox HTTP error: {exc}")
    except httpx.HTTPError as exc:
        return _cache_fallback("threatfox", str(exc), status_message=f"ThreatFox connection error: {exc}")

    iocs, serialized = _parse_threatfox_rows(rows)
    if serialized:
        write_cache(
            "threatfox",
            serialized,
            source=THREATFOX_SOURCE,
            meta={"rate_limited": False},
        )
    message = f"Successfully pulled {len(iocs)} IOCs from ThreatFox (live, last 7 days)."
    log_feed_result("threatfox", message)
    return FeedSourceResult(
        name="threatfox",
        iocs=iocs,
        count=len(iocs),
        cached_at=datetime.now(timezone.utc),
        stale=False,
        live=True,
        status_message=message,
    )


def _normalize_tags(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(tag).strip() for tag in raw if str(tag).strip()]
    text = str(raw).strip()
    return [text] if text else []


def _read_cached_source(name: str) -> FeedSourceResult | None:
    cached, meta = read_cache(name, allow_stale=True)
    if cached is None:
        return None
    iocs = [ioc_from_dict(item) for item in cached]
    mode = "cached (stale)" if meta.stale else "cached"
    return FeedSourceResult(
        name=name,
        iocs=iocs,
        count=len(iocs),
        cached_at=meta.cached_at,
        stale=meta.stale,
        live=False,
        rate_limited=meta.rate_limited,
        status_message=f"Serving {len(iocs)} {name} IOCs from {mode} cache.",
    )


def _abusech_block_reason() -> str:
    if settings.local_only:
        return "local_only"
    if not has_abusech_auth_key():
        return "missing_auth_key"
    return "live_feeds_disabled"


def _abusech_status_hint(feed_name: str) -> str:
    if settings.local_only:
        return f"{feed_name}: LOCAL_ONLY=true — set LOCAL_ONLY=false in .env."
    if not has_abusech_auth_key():
        return f"{feed_name}: add ABUSECH_AUTH_KEY in Settings (free key from auth.abuse.ch)."
    return f"{feed_name}: live pull blocked — check .env and feed settings."


def _parse_urlhaus_rows(rows: list[dict]) -> tuple[list[IOC], list[dict]]:
    iocs: list[IOC] = []
    serialized: list[dict] = []
    for row in rows:
        tags = _normalize_tags(row.get("threat", "malware")) + _normalize_tags(row.get("tags"))
        description = f"URLhaus ({row.get('url_status', 'unknown')})"
        first_seen = _parse_timestamp(row.get("date_added")) or datetime.now(timezone.utc)
        ioc = IOC(
            ioc_type="url",
            value=row.get("url", ""),
            severity=score_severity(tags, description),
            source=URLHAUS_SOURCE,
            first_seen=first_seen,
            tags=tags,
            description=description,
        )
        if not ioc.value:
            continue
        iocs.append(ioc)
        serialized.append(ioc_to_dict(ioc))
    return iocs, serialized


def _parse_otx_pulses(pulses: list[dict]) -> tuple[list[IOC], list[dict]]:
    iocs: list[IOC] = []
    serialized: list[dict] = []
    for pulse in pulses:
        tags = pulse.get("tags", [])
        description = pulse.get("description", "") or pulse.get("name", "OTX pulse")
        modified = _parse_timestamp(pulse.get("modified")) or datetime.now(timezone.utc)
        for indicator in pulse.get("indicators", [])[:25]:
            ioc_type = indicator.get("type", "unknown")
            value = indicator.get("indicator", "")
            if not value:
                continue
            ioc = IOC(
                ioc_type=ioc_type,
                value=value,
                severity=score_severity(tags, description),
                source=OTX_SOURCE,
                first_seen=modified,
                tags=tags,
                description=description[:300],
            )
            iocs.append(ioc)
            serialized.append(ioc_to_dict(ioc))
    return iocs, serialized


def _parse_threatfox_rows(rows: list[dict]) -> tuple[list[IOC], list[dict]]:
    iocs: list[IOC] = []
    serialized: list[dict] = []
    for row in rows:
        value = row.get("ioc", "")
        if not value:
            continue
        ioc_type = _normalize_threatfox_type(row.get("ioc_type", "unknown"))
        tags = list(row.get("tags") or [])
        malware = row.get("malware_printable") or row.get("malware")
        threat_type = row.get("threat_type_desc") or row.get("threat_type")
        if malware:
            tags.append(str(malware))
        if threat_type:
            tags.append(str(threat_type))
        description = threat_type or f"ThreatFox IOC ({row.get('ioc_type_desc', ioc_type)})"
        severity = _threatfox_severity(row, tags, description)
        first_seen = _parse_timestamp(row.get("first_seen")) or datetime.now(timezone.utc)
        ioc = IOC(
            ioc_type=ioc_type,
            value=value,
            severity=severity,
            source=THREATFOX_SOURCE,
            first_seen=first_seen,
            tags=tags,
            description=description[:300],
        )
        iocs.append(ioc)
        serialized.append(ioc_to_dict(ioc))
    return iocs, serialized


def _normalize_threatfox_type(raw: str) -> str:
    mapping = {
        "ip:port": "ip",
        "url": "url",
        "domain": "domain",
        "md5_hash": "hash",
        "sha1_hash": "hash",
        "sha256_hash": "hash",
    }
    return mapping.get(raw, raw)


def _threatfox_severity(row: dict, tags: list[str], description: str) -> str:
    confidence = int(row.get("confidence_level") or 0)
    if confidence >= 90:
        return "critical"
    if confidence >= 75:
        return "high"
    scored = score_severity(tags, description)
    if confidence >= 50 and scored == "low":
        return "medium"
    return scored


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith(" UTC"):
        text = text[:-4] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _cache_fallback(
    name: str,
    error: str,
    *,
    rate_limited: bool = False,
    status_message: str | None = None,
) -> FeedSourceResult:
    cached, meta = read_cache(name, allow_stale=True)
    if cached is None:
        return FeedSourceResult(
            name=name,
            error=error,
            rate_limited=rate_limited,
            status_message=status_message or f"{name}: {error}",
        )
    iocs = [ioc_from_dict(item) for item in cached]
    fallback_msg = status_message or f"Serving {len(iocs)} cached {name} IOCs after error: {error}"
    log_feed_result(name, fallback_msg)
    return FeedSourceResult(
        name=name,
        iocs=iocs,
        count=len(iocs),
        cached_at=meta.cached_at,
        stale=True,
        live=False,
        error=error,
        rate_limited=rate_limited or meta.rate_limited,
        status_message=fallback_msg,
    )