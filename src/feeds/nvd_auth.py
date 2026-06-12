from config import get_nvd_api_key


def nvd_request_headers() -> dict[str, str]:
    """Build NVD API headers. Key is optional — omit for no-key public rate limits."""
    headers: dict[str, str] = {}
    key = get_nvd_api_key()
    if key:
        headers["apiKey"] = key
    return headers