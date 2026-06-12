from config import settings


def nvd_request_headers() -> dict[str, str]:
    """Build NVD API headers. Key is optional — omit for no-key public rate limits."""
    headers: dict[str, str] = {}
    key = settings.nvd_api_key.strip()
    if key:
        headers["apiKey"] = key
    return headers