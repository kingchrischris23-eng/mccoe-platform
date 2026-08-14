"""Debug logging for threat feed HTTP calls."""

import json
import logging
from typing import Any

logger = logging.getLogger("cyber_dashboard.feeds")

# Enable via FEED_DEBUG=true in .env or logging config.
logging.getLogger("cyber_dashboard.feeds").setLevel(logging.DEBUG)


def log_request(source: str, method: str, url: str, *, has_auth: bool, body: dict | None = None) -> None:
    payload = {"method": method, "url": url, "auth_key_present": has_auth}
    if body is not None:
        payload["body"] = body
    logger.debug("[%s] request %s", source, json.dumps(payload, default=str))


def log_response(source: str, status_code: int, payload: Any, *, row_count: int | None = None) -> None:
    summary: dict[str, Any] = {"status_code": status_code}
    if isinstance(payload, dict):
        summary["query_status"] = payload.get("query_status")
        if row_count is None:
            if "data" in payload:
                row_count = len(payload.get("data") or [])
            elif "urls" in payload:
                row_count = len(payload.get("urls") or [])
        if row_count is not None:
            summary["rows"] = row_count
    elif row_count is not None:
        summary["rows"] = row_count
    logger.debug("[%s] response %s", source, json.dumps(summary, default=str))


def log_feed_result(source: str, message: str) -> None:
    logger.info("[%s] %s", source, message)