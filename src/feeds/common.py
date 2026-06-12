from datetime import datetime, timezone

from src.feeds.models import IOC

SEVERITY_KEYWORDS = {
    "critical": ("ransomware", "c2", "botnet", "exploit", "kev", "actively exploited"),
    "high": ("malware", "phishing", "trojan"),
    "medium": ("suspicious", "scanner"),
}


def score_severity(tags: list[str], description: str) -> str:
    text = " ".join(tags + [description]).lower()
    for severity, keywords in SEVERITY_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            return severity
    return "low"


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def ioc_to_dict(ioc: IOC) -> dict:
    return {
        "ioc_type": ioc.ioc_type,
        "value": ioc.value,
        "severity": ioc.severity,
        "source": ioc.source,
        "first_seen": ioc.first_seen.isoformat(),
        "tags": ioc.tags,
        "description": ioc.description,
    }


def ioc_from_dict(data: dict) -> IOC:
    return IOC(
        ioc_type=data["ioc_type"],
        value=data["value"],
        severity=data["severity"],
        source=data["source"],
        first_seen=datetime.fromisoformat(data["first_seen"]),
        tags=data.get("tags", []),
        description=data.get("description", ""),
    )