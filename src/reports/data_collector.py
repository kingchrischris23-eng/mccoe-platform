from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.feeds.aggregator import get_feed_status
from src.logs.analyzer import analyze_logs
from src.storage.repository import (
    get_alerts,
    get_log_entries,
    get_latest_session_id,
    list_iocs,
    list_network_scans,
    list_vuln_scans,
)


@dataclass
class ReportData:
    timestamp: datetime
    auto: bool
    iocs: list[dict]
    alerts: list[dict]
    vuln_scans: list[dict]
    analysis: dict | None
    alert_breakdown: dict[str, int]
    correlations: list[dict]
    feed_summary: list[dict] = field(default_factory=list)
    kev_highlights: list[dict] = field(default_factory=list)
    nvd_highlights: list[dict] = field(default_factory=list)
    network_scans: list[dict] = field(default_factory=list)

    @property
    def mode_label(self) -> str:
        return "Automated" if self.auto else "Manual"


def collect_report_data(auto: bool = False) -> ReportData:
    iocs = list_iocs()
    alerts = get_alerts()
    vuln_scans = list_vuln_scans()
    network_scans = list_network_scans(limit=5)
    session_id = get_latest_session_id()
    entries = get_log_entries(session_id) if session_id else []
    analysis = analyze_logs(entries, alerts) if entries else None

    breakdown: dict[str, int] = {}
    for alert in alerts:
        breakdown[alert["rule_name"]] = breakdown.get(alert["rule_name"], 0) + 1

    correlations = analysis["correlations"] if analysis else []
    feed_summary = _build_feed_summary()
    kev_highlights = [ioc for ioc in iocs if "CISA KEV" in ioc.get("source", "")]
    nvd_highlights = [ioc for ioc in iocs if "NIST NVD" in ioc.get("source", "")]

    return ReportData(
        timestamp=datetime.now(timezone.utc),
        auto=auto,
        iocs=iocs,
        alerts=alerts,
        vuln_scans=vuln_scans,
        analysis=analysis,
        alert_breakdown=breakdown,
        correlations=correlations,
        feed_summary=feed_summary,
        kev_highlights=kev_highlights[:10],
        nvd_highlights=nvd_highlights[:10],
        network_scans=network_scans,
    )


def _build_feed_summary() -> list[dict]:
    summary = []
    for source in get_feed_status():
        if source.error == "disabled":
            continue
        summary.append(
            {
                "name": source.name,
                "count": source.count,
                "cached_at": source.cached_at.isoformat() if source.cached_at else None,
                "stale": source.stale,
                "live": source.live,
            }
        )
    return summary


def recommendations(data: ReportData) -> list[str]:
    items = [
        "Review high-severity IOCs and validate whether they appear in your environment.",
        "Prioritize investigation of source IPs with the highest risk scores.",
        "Patch or harden services with known CVE matches and missing security headers.",
    ]
    if data.alerts:
        items.append("Enable MFA and account lockout if brute-force alerts were detected.")
    if data.correlations:
        items.append("Immediately investigate IPs that matched both log alerts and threat feeds.")
    if data.kev_highlights:
        items.append("Prioritize CISA KEV entries — these CVEs are known to be actively exploited.")
    if data.network_scans:
        items.append("Review network scan results and close or firewall unnecessary exposed services.")
    if not data.vuln_scans:
        items.append("Run a vulnerability scan or add a manual finding to include exposure data.")
    if not data.iocs:
        items.append("Import IOCs via CSV/JSON or refresh live feeds to populate threat intelligence.")
    return items