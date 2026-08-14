"""Shared HTTP helpers for abuse.ch community APIs."""

import httpx

from config import get_abusech_auth_key, has_abusech_auth_key
from src.feeds.feed_log import log_request, log_response
from src.feeds.rate_limit import request_with_backoff, seconds_until_retry

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"
URLHAUS_USER_AGENT = "MCCoE-CyberDashboard/1.0 (+https://github.com/mccoe/cyber-dashboard)"
ABUSECH_INTERVAL_SECONDS = 2.0


def can_fetch_abusech_live() -> bool:
    """abuse.ch feeds can pull when online and an Auth-Key is configured."""
    from config import settings

    return not settings.local_only and has_abusech_auth_key()


def abusech_headers(*, require_auth: bool = True) -> dict[str, str]:
    headers = {
        "User-Agent": URLHAUS_USER_AGENT,
        "Accept": "application/json",
    }
    key = get_abusech_auth_key()
    if key:
        headers["Auth-Key"] = key
    elif require_auth:
        raise ValueError("missing_auth_key")
    return headers


def urlhaus_get_recent(*, source: str = "urlhaus", timeout: float = 25.0) -> httpx.Response:
    headers = abusech_headers(require_auth=True)

    def _request():
        log_request(source, "GET", URLHAUS_RECENT_URL, has_auth=True)
        return httpx.get(URLHAUS_RECENT_URL, headers=headers, timeout=timeout)

    response = request_with_backoff(source, ABUSECH_INTERVAL_SECONDS, _request)
    try:
        log_response(source, response.status_code, response.json())
    except Exception:
        log_response(source, response.status_code, None)
    return response


def threatfox_post(payload: dict, *, source: str = "threatfox", timeout: float = 30.0) -> httpx.Response:
    headers = abusech_headers(require_auth=True)
    headers["Content-Type"] = "application/json"

    def _request():
        log_request(source, "POST", THREATFOX_API_URL, has_auth=True, body=payload)
        return httpx.post(
            THREATFOX_API_URL,
            headers=headers,
            json=payload,
            timeout=timeout,
        )

    response = request_with_backoff(source, ABUSECH_INTERVAL_SECONDS, _request)
    try:
        log_response(source, response.status_code, response.json())
    except Exception:
        log_response(source, response.status_code, None)
    return response


def rate_limit_error(source: str) -> str:
    return f"rate_limited:{seconds_until_retry(source)}"