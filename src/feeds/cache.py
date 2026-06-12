import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from config import CACHE_DIR, settings


@dataclass
class CacheMeta:
    name: str
    cached_at: datetime | None
    count: int
    stale: bool
    source: str = ""
    error: str | None = None
    rate_limited: bool = False


def cache_path(name: str) -> Path:
    return CACHE_DIR / f"{name}.json"


def read_cache(
    name: str,
    ttl_minutes: int | None = None,
    *,
    allow_stale: bool | None = None,
) -> tuple[list[dict] | None, CacheMeta]:
    ttl = ttl_minutes if ttl_minutes is not None else settings.feed_cache_ttl_minutes
    stale_ok = allow_stale if allow_stale is not None else settings.feed_stale_fallback
    path = cache_path(name)
    if not path.exists():
        return None, CacheMeta(name=name, cached_at=None, count=0, stale=True, source=name)

    payload = json.loads(path.read_text(encoding="utf-8"))
    items = payload.get("items", [])
    cached_at = datetime.fromisoformat(payload["cached_at"])
    age_minutes = (datetime.now(timezone.utc) - cached_at).total_seconds() / 60
    is_stale = age_minutes > ttl
    meta = CacheMeta(
        name=name,
        cached_at=cached_at,
        count=len(items),
        stale=is_stale,
        source=payload.get("source", name),
        rate_limited=payload.get("meta", {}).get("rate_limited", False),
    )

    if not is_stale or stale_ok:
        return items, meta
    return None, meta


def write_cache(
    name: str,
    items: list[dict],
    *,
    source: str | None = None,
    meta: dict | None = None,
) -> None:
    payload = {
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "source": source or name,
        "items": items,
        "meta": meta or {},
    }
    cache_path(name).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def get_cache_status(name: str) -> CacheMeta:
    _, meta = read_cache(name, allow_stale=True)
    return meta