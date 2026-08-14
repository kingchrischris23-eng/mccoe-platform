from datetime import datetime, timezone
from typing import Any

from src.feeds.aggregator import can_refresh_live, refresh_feeds
from src.monitoring.state import update_monitoring_state
from src.network.scanner import run_network_scan
from src.storage.repository import save_iocs
from src.vuln.checker import allowed_targets


def _default_scan_target() -> str:
    targets = allowed_targets()
    for preferred in ("127.0.0.1", "localhost"):
        if preferred in targets:
            return preferred
    return targets[0] if targets else "127.0.0.1"


def quick_refresh_all() -> dict[str, Any]:
    """Refresh live feeds (when enabled) and run a quick localhost scan."""
    started = datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "started_at": started.isoformat(),
        "feeds": None,
        "scan": None,
        "errors": [],
    }

    if can_refresh_live():
        try:
            feed_result = refresh_feeds(force_refresh=True)
            save_iocs(feed_result.iocs)
            result["feeds"] = {
                "count": feed_result.total,
                "sources": len(feed_result.sources),
            }
            update_monitoring_state(last_feed_refresh=started.isoformat())
        except Exception as exc:  # noqa: BLE001 — surface to UI
            result["errors"].append(f"Feeds: {exc}")
    else:
        result["feeds"] = {"skipped": True, "reason": "Live feeds disabled"}

    target = _default_scan_target()
    try:
        scan = run_network_scan(target, port_range="1-1000", scan_type="Quick")
        result["scan"] = {
            "target": scan["target"],
            "summary": scan["summary"],
            "scanned_at": scan["scanned_at"],
        }
        update_monitoring_state(last_network_scan=scan["scanned_at"])
    except Exception as exc:  # noqa: BLE001 — nmap may be missing
        result["errors"].append(f"Scan: {exc}")

    update_monitoring_state(last_quick_refresh=started.isoformat())
    return result