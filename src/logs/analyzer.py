import json
from collections import Counter, defaultdict

from src.storage.repository import list_ioc_values


SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 15, "low": 5}


def analyze_logs(entries: list[dict], alerts: list[dict]) -> dict:
    status_counts = Counter(entry.get("status_code") for entry in entries if entry.get("status_code"))
    ip_counts = Counter(entry.get("source_ip") for entry in entries if entry.get("source_ip"))
    ua_counts = Counter(entry.get("user_agent") for entry in entries if entry.get("user_agent"))
    timeline = _build_timeline(entries)
    risk_scores = _compute_risk_scores(entries, alerts)
    correlations = _correlate_with_iocs(alerts)

    return {
        "total_entries": len(entries),
        "unique_ips": len(ip_counts),
        "status_counts": dict(status_counts),
        "top_ips": ip_counts.most_common(10),
        "top_user_agents": ua_counts.most_common(5),
        "timeline": timeline,
        "risk_scores": risk_scores,
        "correlations": correlations,
        "alert_breakdown": Counter(alert["rule_id"] for alert in alerts),
    }


def _build_timeline(entries: list[dict]) -> list[dict]:
    buckets: Counter[str] = Counter()
    for entry in entries:
        timestamp = entry.get("timestamp", "")
        if not timestamp:
            continue
        hour_key = timestamp.split(":")[0]
        buckets[hour_key] += 1
    return [{"hour": hour, "count": count} for hour, count in sorted(buckets.items())]


def _compute_risk_scores(entries: list[dict], alerts: list[dict]) -> list[dict]:
    ip_alert_counts: Counter[str] = Counter()
    ip_severity: dict[str, int] = defaultdict(int)

    for alert in alerts:
        source_ip = alert.get("source_ip")
        if not source_ip:
            continue
        ip_alert_counts[source_ip] += 1
        ip_severity[source_ip] += SEVERITY_WEIGHTS.get(alert.get("severity", "low"), 5)

    request_counts = Counter(entry.get("source_ip") for entry in entries if entry.get("source_ip"))
    scores: list[dict] = []
    for source_ip, requests in request_counts.items():
        alert_count = ip_alert_counts.get(source_ip, 0)
        score = min(100, alert_count * 20 + ip_severity.get(source_ip, 0) + min(requests, 20))
        scores.append(
            {
                "source_ip": source_ip,
                "requests": requests,
                "alerts": alert_count,
                "risk_score": score,
                "risk_level": _risk_level(score),
            }
        )
    return sorted(scores, key=lambda item: item["risk_score"], reverse=True)


def _risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _correlate_with_iocs(alerts: list[dict]) -> list[dict]:
    ioc_values = list_ioc_values()
    correlations: list[dict] = []
    for alert in alerts:
        source_ip = (alert.get("source_ip") or "").lower()
        if source_ip and source_ip in ioc_values:
            correlations.append(
                {
                    "source_ip": source_ip,
                    "rule_id": alert["rule_id"],
                    "message": f"{source_ip} matches a known threat feed IOC",
                }
            )
    return correlations


def export_analysis_json(analysis: dict) -> str:
    serializable = {
        **analysis,
        "alert_breakdown": dict(analysis["alert_breakdown"]),
    }
    return json.dumps(serializable, indent=2)