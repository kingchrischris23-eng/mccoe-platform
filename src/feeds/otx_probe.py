import httpx

from config import get_otx_api_key, has_otx_api_key
from src.feeds.rate_limit import request_with_backoff

OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OTX_INTERVAL_SECONDS = 2.0


def probe_otx_api_connection() -> dict:
    """Probe AlienVault OTX with the configured API key."""
    key = get_otx_api_key()
    key_len = len(key)

    if not key:
        return {
            "success": False,
            "message": "No OTX API key configured. Add one in Settings.",
            "has_key": False,
            "key_length": 0,
            "status_code": None,
        }

    try:

        def _request():
            return httpx.get(
                OTX_PULSES_URL,
                headers={"X-OTX-API-KEY": key},
                params={"limit": 1},
                timeout=20.0,
            )

        response = request_with_backoff("otx", OTX_INTERVAL_SECONDS, _request)
        payload = response.json()
        count = payload.get("count", len(payload.get("results", [])))
        return {
            "success": True,
            "message": f"OTX API reachable. Subscribed pulses: {count}.",
            "has_key": True,
            "key_length": key_len,
            "status_code": response.status_code,
        }
    except httpx.HTTPStatusError as exc:
        body = exc.response.text[:200] if exc.response is not None else ""
        return {
            "success": False,
            "message": f"HTTP {exc.response.status_code}: {body or exc}",
            "has_key": has_otx_api_key(),
            "key_length": key_len,
            "status_code": exc.response.status_code if exc.response is not None else None,
        }
    except httpx.HTTPError as exc:
        return {
            "success": False,
            "message": str(exc),
            "has_key": has_otx_api_key(),
            "key_length": key_len,
            "status_code": None,
        }