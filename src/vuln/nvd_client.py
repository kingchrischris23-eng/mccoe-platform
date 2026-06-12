import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

from config import CACHE_DIR, settings
from src.feeds.nvd_auth import nvd_request_headers
from src.feeds.rate_limit import nvd_interval_seconds, request_with_backoff

CACHE_FILE = CACHE_DIR / "nvd_lookup.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cves(keyword: str, limit: int = 5) -> list[dict]:
    cache = _load_lookup_cache()
    cache_key = keyword.lower()
    if cache_key in cache:
        return cache[cache_key][:limit]

    if settings.local_only:
        return []

    params = {"keywordSearch": keyword, "resultsPerPage": limit}
    try:
        response = request_with_backoff(
            "nvd",
            nvd_interval_seconds(),
            lambda: httpx.get(NVD_URL, params=params, headers=nvd_request_headers(), timeout=20.0),
        )
        vulnerabilities = response.json().get("vulnerabilities", [])
    except httpx.HTTPError:
        if cache_key in cache:
            return cache[cache_key][:limit]
        return []

    findings: list[dict] = []
    for item in vulnerabilities[:limit]:
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
        score = metrics[0]["cvssData"]["baseScore"] if metrics else 0.0
        vector = metrics[0]["cvssData"]["vectorString"] if metrics else "N/A"
        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "No description available.",
        )
        findings.append(
            {
                "cve_id": cve.get("id", "UNKNOWN"),
                "score": score,
                "vector": vector,
                "description": description[:250],
            }
        )

    cache[cache_key] = findings
    _save_lookup_cache(cache)
    return findings


def _load_lookup_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    payload = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    return payload.get("items", {})


def _save_lookup_cache(cache: dict) -> None:
    payload = {"cached_at": datetime.now(timezone.utc).isoformat(), "items": cache}
    CACHE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")