from dataclasses import dataclass, field
from datetime import datetime, timezone

from config import get_ioc_recent_days
from src.feeds.aggregator import get_feed_status
from src.reports.filters import ReportFilters
from src.logs.analyzer import analyze_logs
from src.storage.repository import (
    count_iocs_filtered,
    get_alerts,
    get_log_entries,
    get_latest_session_id,
    list_iocs_filtered,
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
    ioc_total_count: int = 0
    ioc_filtered_count: int = 0
    ioc_nist_count: int = 0
    ioc_cisa_count: int = 0
    ioc_otx_count: int = 0
    ioc_urlhaus_count: int = 0
    ioc_threatfox_count: int = 0
    ioc_recent_count: int = 0
    ioc_report_limit: int = 0
    filters: ReportFilters = field(default_factory=ReportFilters.defaults)
    filter_summary: list[str] = field(default_factory=list)
    recently_added: list[dict] = field(default_factory=list)
    feed_summary: list[dict] = field(default_factory=list)
    kev_highlights: list[dict] = field(default_factory=list)
    nvd_highlights: list[dict] = field(default_factory=list)
    network_scans: list[dict] = field(default_factory=list)

    @property
    def mode_label(self) -> str:
        return "Automated" if self.auto else "Manual"


def collect_report_data(
    auto: bool = False,
    filters: ReportFilters | None = None,
) -> ReportData:
    filters = filters or ReportFilters.defaults()
    query = filters.query_kwargs()
    report_limit = filters.effective_limit()
    recent_days = get_ioc_recent_days()

    ioc_total = count_iocs_filtered()
    ioc_filtered = count_iocs_filtered(**query)
    ioc_nist = count_iocs_filtered(source="NIST NVD")
    ioc_cisa = count_iocs_filtered(source="CISA KEV")
    ioc_otx = count_iocs_filtered(source="AlienVault OTX")
    ioc_urlhaus = count_iocs_filtered(source="URLhaus")
    ioc_threatfox = count_iocs_filtered(source="ThreatFox")
    ioc_recent = count_iocs_filtered(recent_days=recent_days)

    iocs = list_iocs_filtered(limit=report_limit, sort="newest", **query)
    included = len(iocs)

    fresh_query = {**query, "recency_tier": "fresh"}
    if "recent_days" in fresh_query:
        del fresh_query["recent_days"]
    recently_added = list_iocs_filtered(limit=20, sort="newest", **fresh_query)

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

    filter_summary = filters.summary_lines(
        matching=ioc_filtered,
        included=included,
        dashboard_total=ioc_total,
    )

    return ReportData(
        timestamp=datetime.now(timezone.utc),
        auto=auto,
        iocs=iocs,
        ioc_total_count=ioc_total,
        ioc_filtered_count=ioc_filtered,
        ioc_nist_count=ioc_nist,
        ioc_cisa_count=ioc_cisa,
        ioc_otx_count=ioc_otx,
        ioc_urlhaus_count=ioc_urlhaus,
        ioc_threatfox_count=ioc_threatfox,
        ioc_recent_count=ioc_recent,
        ioc_report_limit=report_limit,
        filters=filters,
        filter_summary=filter_summary,
        recently_added=recently_added,
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
    if data.filters.source == "cisa_kev":
        items.append("This report is scoped to CISA KEV — treat all listed CVEs as actively exploited priorities.")
    if data.filters.source == "nist_nvd":
        items.append("This report is scoped to NIST NVD — validate patch levels against the listed CVEs.")
    if data.filters.source == "otx":
        items.append("This report is scoped to AlienVault OTX pulses — verify indicators against your telemetry.")
    if data.filters.source == "urlhaus":
        items.append("This report is scoped to URLhaus — block or investigate listed malicious URLs.")
    if data.filters.source == "threatfox":
        items.append("This report is scoped to ThreatFox — prioritize C2 and payload-delivery indicators.")
    if data.ioc_filtered_count > len(data.iocs):
        items.append(
            "Additional IOCs matched your filters but were omitted due to the report item limit — "
            "adjust filters or raise max items in Threat Reporter."
        )
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