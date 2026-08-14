import logging
import threading
from datetime import datetime, timezone

from config import get_auto_feed_refresh_hours, is_auto_feed_refresh_enabled
from src.feeds.aggregator import can_refresh_live, refresh_feeds
from src.monitoring.state import get_state_timestamp, update_monitoring_state
from src.storage.repository import save_iocs

_logger = logging.getLogger(__name__)
_refresh_lock = threading.Lock()
_refresh_thread: threading.Thread | None = None


def _hours_since(dt: datetime) -> float:
    now = datetime.now(timezone.utc)
    return (now - dt).total_seconds() / 3600


def _is_auto_refresh_due() -> bool:
    last = get_state_timestamp("last_feed_refresh")
    if last is None:
        return True
    return _hours_since(last) >= get_auto_feed_refresh_hours()


def _run_feed_refresh() -> None:
    started = datetime.now(timezone.utc)
    try:
        result = refresh_feeds(force_refresh=True)
        save_iocs(result.iocs)
        update_monitoring_state(
            last_feed_refresh=started.isoformat(),
            last_auto_feed_refresh=started.isoformat(),
        )
        _logger.info("Scheduled feed refresh completed (%s IOCs)", result.total)
    except Exception:
        _logger.exception("Scheduled feed refresh failed")
    finally:
        _refresh_lock.release()


def maybe_run_scheduled_feed_refresh() -> bool:
    """Start a one-shot background feed refresh when the 24h interval has elapsed."""
    global _refresh_thread

    if not is_auto_feed_refresh_enabled() or not can_refresh_live():
        return False
    if not _is_auto_refresh_due():
        return False
    if _refresh_thread is not None and _refresh_thread.is_alive():
        return False
    if not _refresh_lock.acquire(blocking=False):
        return False

    _refresh_thread = threading.Thread(target=_run_feed_refresh, name="feed-auto-refresh", daemon=True)
    _refresh_thread.start()
    return True