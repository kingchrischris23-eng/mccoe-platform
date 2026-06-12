import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

from config import CACHE_DIR, SAMPLES_DIR, settings
from src.feeds.models import IOC

SEVERITY_KEYWORDS = {
    "critical": ("ransomware", "c2", "botnet", "exploit"),
    "high": ("malware", "phishing", "trojan"),
    "medium": ("suspicious", "scanner"),
}


def _score_severity(tags: list[str], description: str) -> str:
    text = " ".join(tags + [description]).lower()
    for severity, keywords in SEVERITY_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            return severity
    return "low"


def _cache_path(name: str) -> Path:
    return CACHE_DIR / f"{name}.json"


def _read_cache(name: str, ttl_minutes: int) -> list[dict] | None:
    path = _cache_path(name)
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    cached_at = datetime.fromisoformat(payload["cached_at"])
    age_minutes = (datetime.now(timezone.utc) - cached_at).total_seconds() / 60
    if age_minutes > ttl_minutes:
        return None
    return payload["items"]


def _write_cache(name: str, items: list[dict]) -> None:
    payload = {"cached_at": datetime.now(timezone.utc).isoformat(), "items": items}
    _cache_path(name).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def fetch_urlhaus() -> list[IOC]:
    if settings.local_only:
        return []

    cached = _read_cache("urlhaus", settings.feed_cache_ttl_minutes)
    if cached is not None:
        return [_ioc_from_dict(item) for item in cached]

    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/"
    try:
        response = httpx.get(url, timeout=15.0)
        response.raise_for_status()
        rows = response.json().get("urls", [])
    except httpx.HTTPError:
        return load_sample_iocs()

    iocs: list[IOC] = []
    serialized: list[dict] = []
    for row in rows:
        tags = [row.get("threat", "malware"), row.get("tags", "")]
        description = f"URLhaus entry: {row.get('url_status', 'unknown')}"
        ioc = IOC(
            ioc_type="url",
            value=row.get("url", ""),
            severity=_score_severity(tags, description),
            source="URLhaus",
            first_seen=datetime.now(timezone.utc),
            tags=[tag for tag in tags if tag],
            description=description,
        )
        iocs.append(ioc)
        serialized.append(_ioc_to_dict(ioc))

    if serialized:
        _write_cache("urlhaus", serialized)
    return iocs


def fetch_otx() -> list[IOC]:
    if settings.local_only or not settings.otx_api_key:
        return []

    cached = _read_cache("otx", settings.feed_cache_ttl_minutes)
    if cached is not None:
        return [_ioc_from_dict(item) for item in cached]

    headers = {"X-OTX-API-KEY": settings.otx_api_key}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    try:
        response = httpx.get(url, headers=headers, timeout=20.0)
        response.raise_for_status()
        pulses = response.json().get("results", [])[:10]
    except httpx.HTTPError:
        return []

    iocs: list[IOC] = []
    serialized: list[dict] = []
    for pulse in pulses:
        tags = pulse.get("tags", [])
        description = pulse.get("description", "") or pulse.get("name", "OTX pulse")
        for indicator in pulse.get("indicators", [])[:20]:
            ioc_type = indicator.get("type", "unknown")
            value = indicator.get("indicator", "")
            if not value:
                continue
            ioc = IOC(
                ioc_type=ioc_type,
                value=value,
                severity=_score_severity(tags, description),
                source="AlienVault OTX",
                first_seen=datetime.now(timezone.utc),
                tags=tags,
                description=description[:300],
            )
            iocs.append(ioc)
            serialized.append(_ioc_to_dict(ioc))

    if serialized:
        _write_cache("otx", serialized)
    return iocs


def load_sample_iocs() -> list[IOC]:
    sample_path = SAMPLES_DIR / "sample_iocs.csv"
    if not sample_path.exists():
        return _default_sample_iocs()

    iocs: list[IOC] = []
    with sample_path.open(encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            tags = [tag.strip() for tag in row.get("tags", "").split(";") if tag.strip()]
            iocs.append(
                IOC(
                    ioc_type=row["ioc_type"],
                    value=row["value"],
                    severity=row.get("severity", "medium"),
                    source=row.get("source", "Sample"),
                    first_seen=datetime.now(timezone.utc),
                    tags=tags,
                    description=row.get("description", ""),
                )
            )
    return iocs


def _default_sample_iocs() -> list[IOC]:
    now = datetime.now(timezone.utc)
    return [
        IOC("ip", "198.51.100.42", "high", "Sample", now, ["bruteforce"], "Known brute-force source"),
        IOC("domain", "evil-training.example", "critical", "Sample", now, ["phishing"], "Phishing domain"),
        IOC("url", "http://malware-lab.example/payload.exe", "high", "Sample", now, ["malware"], "Malware URL"),
        IOC("hash", "d41d8cd98f00b204e9800998ecf8427e", "medium", "Sample", now, ["sample"], "Example MD5 hash"),
    ]


def _ioc_to_dict(ioc: IOC) -> dict:
    return {
        "ioc_type": ioc.ioc_type,
        "value": ioc.value,
        "severity": ioc.severity,
        "source": ioc.source,
        "first_seen": ioc.first_seen.isoformat(),
        "tags": ioc.tags,
        "description": ioc.description,
    }


def _ioc_from_dict(data: dict) -> IOC:
    return IOC(
        ioc_type=data["ioc_type"],
        value=data["value"],
        severity=data["severity"],
        source=data["source"],
        first_seen=datetime.fromisoformat(data["first_seen"]),
        tags=data.get("tags", []),
        description=data.get("description", ""),
    )