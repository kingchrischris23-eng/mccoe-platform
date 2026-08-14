import httpx

from config import get_nvd_api_key, has_nvd_api_key
from src.feeds.nvd_auth import nvd_request_headers
from src.feeds.rate_limit import nvd_interval_seconds, request_with_backoff

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def probe_nvd_api_connection() -> dict:
    """Probe the NVD API with the currently configured key (or no-key mode)."""
    rate_mode = "with_key" if has_nvd_api_key() else "no_key"
    key_len = len(get_nvd_api_key())

    try:

        def _request():
            return httpx.get(
                NVD_URL,
                params={"resultsPerPage": 1},
                headers=nvd_request_headers(),
                timeout=20.0,
            )

        response = request_with_backoff("nvd", nvd_interval_seconds(), _request)
        payload = response.json()
        total = payload.get("totalResults", "unknown")
        return {
            "success": True,
            "message": f"NVD API reachable. Catalog reports {total} CVE(s).",
            "has_key": has_nvd_api_key(),
            "rate_mode": rate_mode,
            "key_length": key_len,
            "status_code": response.status_code,
        }
    except httpx.HTTPStatusError as exc:
        body = exc.response.text[:200] if exc.response is not None else ""
        return {
            "success": False,
            "message": f"HTTP {exc.response.status_code}: {body or exc}",
            "has_key": has_nvd_api_key(),
            "rate_mode": rate_mode,
            "key_length": key_len,
            "status_code": exc.response.status_code if exc.response is not None else None,
        }
    except httpx.HTTPError as exc:
        return {
            "success": False,
            "message": str(exc),
            "has_key": has_nvd_api_key(),
            "rate_mode": rate_mode,
            "key_length": key_len,
            "status_code": None,
        }