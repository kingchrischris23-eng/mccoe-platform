from config import is_local_only
from src.feeds.models import IOC
from src.feeds.sources import fetch_otx, fetch_urlhaus, load_sample_iocs


def aggregate_feeds() -> list[IOC]:
    if is_local_only():
        collected = load_sample_iocs()
    else:
        collected = fetch_urlhaus() + fetch_otx()
        if not collected:
            collected = load_sample_iocs()

    merged: dict[tuple[str, str], IOC] = {}
    for ioc in collected:
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

    return sorted(merged.values(), key=lambda item: (-_severity_rank(item.severity), item.value))


def _severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 0)