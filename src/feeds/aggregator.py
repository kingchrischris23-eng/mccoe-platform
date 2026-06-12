from config import settings
from src.feeds.cisa_kev import fetch_cisa_kev
from src.feeds.models import FeedResult, FeedSourceResult, IOC
from src.feeds.nvd_feed import fetch_nvd_feed
from src.feeds.sources import fetch_otx, fetch_urlhaus


def can_refresh_live() -> bool:
    return not settings.local_only and settings.enable_live_feeds


def refresh_feeds(*, force_refresh: bool = False) -> FeedResult:
    source_results = [
        fetch_urlhaus(force_refresh=force_refresh),
        fetch_otx(force_refresh=force_refresh),
        fetch_nvd_feed(force_refresh=force_refresh),
        fetch_cisa_kev(force_refresh=force_refresh),
    ]
    merged = _merge_iocs([result.iocs for result in source_results])
    return FeedResult(iocs=merged, sources=source_results)


def aggregate_feeds(*, force_refresh: bool = False) -> list[IOC]:
    return refresh_feeds(force_refresh=force_refresh).iocs


def get_feed_status() -> list[FeedSourceResult]:
    return refresh_feeds(force_refresh=False).sources


def _merge_iocs(groups: list[list[IOC]]) -> list[IOC]:
    merged: dict[tuple[str, str], IOC] = {}
    for iocs in groups:
        for ioc in iocs:
            key = ioc.key
            if key not in merged:
                merged[key] = ioc
                continue
            existing = merged[key]
            existing.tags = sorted(set(existing.tags + ioc.tags))
            if _severity_rank(ioc.severity) > _severity_rank(existing.severity):
                existing.severity = ioc.severity
            if ioc.description and ioc.description not in existing.description:
                existing.description = f"{existing.description} | {ioc.description}".strip(" |")
            if ioc.source not in existing.source:
                existing.source = f"{existing.source}, {ioc.source}"

    return sorted(merged.values(), key=lambda item: (-_severity_rank(item.severity), item.value))


def _severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 0)