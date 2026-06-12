from dataclasses import dataclass
from datetime import datetime, timezone

from src.logs.analyzer import analyze_logs
from src.storage.repository import get_alerts, get_log_entries, get_latest_session_id, list_iocs, list_vuln_scans


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

    @property
    def mode_label(self) -> str:
        return "Automated" if self.auto else "Manual"


def collect_report_data(auto: bool = False) -> ReportData:
    iocs = list_iocs()
    alerts = get_alerts()
    vuln_scans = list_vuln_scans()
    session_id = get_latest_session_id()
    entries = get_log_entries(session_id) if session_id else []
    analysis = analyze_logs(entries, alerts) if entries else None

    breakdown: dict[str, int] = {}
    for alert in alerts:
        breakdown[alert["rule_name"]] = breakdown.get(alert["rule_name"], 0) + 1

    correlations = analysis["correlations"] if analysis else []

    return ReportData(
        timestamp=datetime.now(timezone.utc),
        auto=auto,
        iocs=iocs,
        alerts=alerts,
        vuln_scans=vuln_scans,
        analysis=analysis,
        alert_breakdown=breakdown,
        correlations=correlations,
    )


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
    if not data.vuln_scans:
        items.append("Run a vulnerability check to include exposure data in future reports.")
    if not data.iocs:
        items.append("Refresh threat feeds or load sample IOC data before the next reporting cycle.")
    return items