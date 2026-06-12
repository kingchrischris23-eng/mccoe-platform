import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

from config import CACHE_DIR, settings

CACHE_FILE = CACHE_DIR / "nvd_cache.json"


def lookup_cves(keyword: str, limit: int = 5) -> list[dict]:
    if settings.local_only:
        return _sample_cves(keyword)[:limit]

    cache = _load_cache()
    cache_key = keyword.lower()
    if cache_key in cache:
        return cache[cache_key][:limit]

    params = {"keywordSearch": keyword, "resultsPerPage": limit}
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    try:
        response = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            headers=headers,
            timeout=20.0,
        )
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
    except httpx.HTTPError:
        return _sample_cves(keyword)

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
    _save_cache(cache)
    return findings


def _sample_cves(keyword: str) -> list[dict]:
    return [
        {
            "cve_id": "CVE-2024-0001",
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "description": f"Sample CVE related to {keyword} for offline training mode.",
        }
    ]


def _load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    payload = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    return payload.get("items", payload)


def _save_cache(cache: dict) -> None:
    payload = {"cached_at": datetime.now(timezone.utc).isoformat(), "items": cache}
    CACHE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")