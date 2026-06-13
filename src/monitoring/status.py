from dataclasses import dataclass
from datetime import datetime, timezone

from config import get_auto_feed_refresh_hours, is_auto_feed_refresh_enabled, settings
from src.feeds.aggregator import can_refresh_live
from src.feeds.cache import get_cache_status
from src.monitoring.state import get_state_timestamp, read_monitoring_state
from src.storage.repository import list_network_scans


def format_relative_time(value: datetime | str | None) -> str:
    if value is None:
        return "never"
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return "unknown"
    else:
        dt = value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    seconds = int((datetime.now(timezone.utc) - dt).total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        minutes = seconds // 60
        suffix = "s" if minutes != 1 else ""
        return f"{minutes} minute{suffix} ago"
    if seconds < 86400:
        hours = seconds // 3600
        suffix = "s" if hours != 1 else ""
        return f"{hours} hour{suffix} ago"
    days = seconds // 86400
    suffix = "s" if days != 1 else ""
    return f"{days} day{suffix} ago"


def format_time_until(value: datetime | str | None) -> str:
    if value is None:
        return "not scheduled"
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return "unknown"
    else:
        dt = value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    seconds = int((dt - datetime.now(timezone.utc)).total_seconds())
    if seconds <= 0:
        return "due now"
    if seconds < 3600:
        minutes = seconds // 60
        suffix = "s" if minutes != 1 else ""
        return f"in {minutes} minute{suffix}"
    if seconds < 86400:
        hours = seconds // 3600
        suffix = "s" if hours != 1 else ""
        return f"in {hours} hour{suffix}"
    days = seconds // 86400
    suffix = "s" if days != 1 else ""
    return f"in {days} day{suffix}"


def enabled_feed_names() -> list[str]:
    names: list[str] = []
    if settings.enable_otx:
        names.append("otx")
    if settings.enable_urlhaus:
        names.append("urlhaus")
    if settings.enable_threatfox:
        names.append("threatfox")
    if settings.enable_nvd_feed:
        names.append("nist_nvd")
    if settings.enable_cisa_kev:
        names.append("cisa_kev")
    return names


def compute_feed_health() -> tuple[str, str]:
    if not can_refresh_live():
        return "Disabled", "Online mode and live feeds required"

    enabled = enabled_feed_names()
    if not enabled:
        return "Disabled", "No feed sources enabled"

    metas = [get_cache_status(name) for name in enabled]
    with_data = [meta for meta in metas if meta.count > 0]
    fresh = [meta for meta in metas if meta.count > 0 and not meta.stale]

    if not with_data:
        return "Offline", "No cached feed data"
    if len(fresh) == len(enabled):
        return "Healthy", f"{len(fresh)}/{len(enabled)} sources fresh"
    if fresh:
        return "Degraded", f"{len(fresh)}/{len(enabled)} sources fresh"
    return "Degraded", "Serving stale cache"


def _latest_scan_time() -> datetime | None:
    state_time = get_state_timestamp("last_network_scan")
    scans = list_network_scans(limit=1)
    if not scans:
        return state_time
    try:
        scan_time = datetime.fromisoformat(scans[0]["scanned_at"])
        if scan_time.tzinfo is None:
            scan_time = scan_time.replace(tzinfo=timezone.utc)
    except (KeyError, ValueError):
        return state_time
    if state_time is None:
        return scan_time
    return max(state_time, scan_time)


@dataclass
class DashboardStatus:
    feed_health: str
    feed_detail: str
    last_feed_refresh: str
    last_network_scan: str
    last_quick_refresh: str
    auto_refresh_enabled: bool
    auto_refresh_hours: int
    next_auto_refresh: str | None = None


def get_dashboard_status() -> DashboardStatus:
    state = read_monitoring_state()
    feed_label, feed_detail = compute_feed_health()
    last_feed = state.get("last_feed_refresh")
    last_scan_dt = _latest_scan_time()
    last_quick = state.get("last_quick_refresh")

    next_auto: str | None = None
    auto_enabled = is_auto_feed_refresh_enabled()
    auto_hours = get_auto_feed_refresh_hours()
    if auto_enabled and last_feed:
        try:
            last_dt = datetime.fromisoformat(str(last_feed))
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
            due_at = datetime.fromtimestamp(
                last_dt.timestamp() + auto_hours * 3600,
                tz=timezone.utc,
            )
            next_auto = format_time_until(due_at)
        except ValueError:
            next_auto = None
    elif auto_enabled:
        next_auto = "on next check"

    return DashboardStatus(
        feed_health=feed_label,
        feed_detail=feed_detail,
        last_feed_refresh=format_relative_time(last_feed),
        last_network_scan=format_relative_time(last_scan_dt),
        last_quick_refresh=format_relative_time(last_quick),
        auto_refresh_enabled=auto_enabled,
        auto_refresh_hours=auto_hours,
        next_auto_refresh=next_auto,
    )